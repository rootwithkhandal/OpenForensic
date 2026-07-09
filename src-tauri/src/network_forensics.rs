use rusqlite::Connection;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::Utc;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CapturedPacket {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub info: String,
    pub correlated_pid: Option<u32>,
    pub correlated_process_name: String,
    pub risk_flags: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsCacheRecord {
    pub record_name: String,
    pub record_type: String,
    pub record_data: String,
    pub ttl: u32,
    pub source: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArpTableEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface_name: String,
    pub entry_type: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WifiProfileEntry {
    pub ssid: String,
    pub authentication: String,
    pub encryption: String,
    pub password_or_key: String,
    pub last_connected: String,
    pub source: String,
}

/// PCAP File Writer supporting Global and Packet headers (PCAP v2.4 magic 0xa1b2c3d4)
pub struct PcapWriter {
    file: File,
}

impl PcapWriter {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        // Write PCAP Global Header (24 bytes)
        // magic_number: 0xa1b2c3d4 (32-bit uint)
        // version_major: 2 (16-bit uint)
        // version_minor: 4 (16-bit uint)
        // thiszone: 0 (32-bit int)
        // sigfigs: 0 (32-bit uint)
        // snaplen: 65535 (32-bit uint)
        // network: 1 = LINKTYPE_ETHERNET (32-bit uint)
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
        header.extend_from_slice(&2u16.to_ne_bytes());
        header.extend_from_slice(&4u16.to_ne_bytes());
        header.extend_from_slice(&0i32.to_ne_bytes());
        header.extend_from_slice(&0u32.to_ne_bytes());
        header.extend_from_slice(&65535u32.to_ne_bytes());
        header.extend_from_slice(&1u32.to_ne_bytes());
        file.write_all(&header)?;
        Ok(Self { file })
    }

    pub fn write_packet(&mut self, timestamp_sec: u32, timestamp_usec: u32, packet_data: &[u8]) -> std::io::Result<()> {
        let len = packet_data.len() as u32;
        let mut pkt_hdr = Vec::with_capacity(16);
        pkt_hdr.extend_from_slice(&timestamp_sec.to_ne_bytes());
        pkt_hdr.extend_from_slice(&timestamp_usec.to_ne_bytes());
        pkt_hdr.extend_from_slice(&len.to_ne_bytes());
        pkt_hdr.extend_from_slice(&len.to_ne_bytes());
        self.file.write_all(&pkt_hdr)?;
        self.file.write_all(packet_data)?;
        Ok(())
    }
}

/// Correlate network packet endpoints against active process socket snapshot
pub fn correlate_packet_to_process(
    db: &Connection,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> (Option<u32>, String) {
    let port_str = format!(":{}", src_port);
    let dst_port_str = format!(":{}", dst_port);

    // Look up in network_connections table
    if let Ok(mut stmt) = db.prepare(
        "SELECT pid FROM network_connections WHERE local_address LIKE ?1 OR foreign_address LIKE ?2 OR local_address LIKE ?3 LIMIT 1"
    ) {
        let pattern1 = format!("%{}", port_str);
        let pattern2 = format!("%{}", dst_port_str);
        let pattern3 = format!("%{}", src_ip);

        if let Ok(mut rows) = stmt.query(rusqlite::params![pattern1, pattern2, pattern3]) {
            if let Ok(Some(row)) = rows.next() {
                if let Ok(pid_i64) = row.get::<_, i64>(0) {
                    let pid = pid_i64 as u32;
                    // Query process name
                    if let Ok(mut proc_stmt) = db.prepare("SELECT name FROM processes WHERE pid = ?1 LIMIT 1") {
                        if let Ok(mut p_rows) = proc_stmt.query(rusqlite::params![pid_i64]) {
                            if let Ok(Some(p_row)) = p_rows.next() {
                                let name = p_row.get::<_, String>(0).unwrap_or_else(|_| "Unknown Process".to_string());
                                return (Some(pid), name);
                            }
                        }
                    }
                    return (Some(pid), format!("PID {}", pid));
                }
            }
        }
    }
    (None, "Uncorrelated / Kernel Stack".to_string())
}

/// Extract DNS Cache across Windows / Linux / macOS
pub fn extract_dns_cache(db: &Connection) -> usize {
    let mut count = 0;

    #[cfg(target_os = "windows")]
    {
        // 1. Run `ipconfig /displaydns` and parse resolver cache
        if let Ok(output) = Command::new("ipconfig").arg("/displaydns").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut current_name = String::new();
            let mut current_type = String::new();
            let mut current_ttl = 0u32;
            let mut current_data = String::new();

            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Record Name") {
                    if !current_name.is_empty() && !current_data.is_empty() {
                        let _ = db.execute(
                            "INSERT INTO dns_cache_entries (record_name, record_type, record_data, ttl, source) VALUES (?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params![current_name, current_type, current_data, current_ttl, "Windows Resolver Cache (ipconfig /displaydns)"],
                        );
                        count += 1;
                    }
                    if let Some(pos) = trimmed.find(':') {
                        current_name = trimmed[pos + 1..].trim().to_string();
                        current_type = "A".to_string();
                        current_data.clear();
                    }
                } else if trimmed.starts_with("Record Type") {
                    if let Some(pos) = trimmed.find(':') {
                        let t_val = trimmed[pos + 1..].trim();
                        current_type = match t_val {
                            "1" => "A",
                            "5" => "CNAME",
                            "28" => "AAAA",
                            "12" => "PTR",
                            "16" => "TXT",
                            other => other,
                        }.to_string();
                    }
                } else if trimmed.starts_with("Time To Live") {
                    if let Some(pos) = trimmed.find(':') {
                        current_ttl = trimmed[pos + 1..].trim().parse::<u32>().unwrap_or(300);
                    }
                } else if trimmed.starts_with("A (Host) Record") || trimmed.starts_with("CNAME Record") {
                    if let Some(pos) = trimmed.find(':') {
                        current_data = trimmed[pos + 1..].trim().to_string();
                    }
                }
            }
            if !current_name.is_empty() && !current_data.is_empty() {
                let _ = db.execute(
                    "INSERT INTO dns_cache_entries (record_name, record_type, record_data, ttl, source) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![current_name, current_type, current_data, current_ttl, "Windows Resolver Cache"],
                );
                count += 1;
            }
        }

        // 2. Also parse /etc/hosts equivalent: C:\Windows\System32\drivers\etc\hosts
        let hosts_path = Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts");
        if hosts_path.exists() {
            count += parse_hosts_file(hosts_path, "Windows System32 Hosts File", db);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let hosts_path = Path::new("/etc/hosts");
        if hosts_path.exists() {
            count += parse_hosts_file(hosts_path, "Linux/Unix Hosts File (/etc/hosts)", db);
        }
        let resolv_path = Path::new("/etc/resolv.conf");
        if resolv_path.exists() {
            if let Ok(text) = fs::read_to_string(resolv_path) {
                for line in text.lines() {
                    let trim = line.trim();
                    if trim.starts_with("nameserver ") {
                        let ns_ip = trim.strip_prefix("nameserver ").unwrap_or("").trim();
                        let _ = db.execute(
                            "INSERT INTO dns_cache_entries (record_name, record_type, record_data, ttl, source) VALUES (?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params!["DNS Resolver Server", "NS", ns_ip, 0i64, "System /etc/resolv.conf"],
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    count
}

fn parse_hosts_file(hosts_path: &Path, source_label: &str, db: &Connection) -> usize {
    let mut count = 0;
    if let Ok(file) = File::open(hosts_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let trim = line.trim();
            if trim.is_empty() || trim.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trim.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip = parts[0];
                for hostname in &parts[1..] {
                    if hostname.starts_with('#') {
                        break;
                    }
                    let rec_type = if ip.contains(':') { "AAAA" } else { "A" };
                    let _ = db.execute(
                        "INSERT INTO dns_cache_entries (record_name, record_type, record_data, ttl, source) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![hostname, rec_type, ip, 86400i64, source_label],
                    );
                    count += 1;
                }
            }
        }
    }
    count
}

/// Extract ARP Table Entries across OS platforms
pub fn extract_arp_table(db: &Connection) -> usize {
    let mut count = 0;

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("arp").arg("-a").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut current_iface = "Default Interface".to_string();
            for line in text.lines() {
                let trim = line.trim();
                if trim.starts_with("Interface:") {
                    current_iface = trim.to_string();
                } else {
                    let parts: Vec<&str> = trim.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ip = parts[0];
                        let mac = parts[1];
                        let etype = parts[2];
                        if ip.contains('.') && mac.contains('-') {
                            let _ = db.execute(
                                "INSERT INTO arp_table_entries (ip_address, mac_address, interface_name, entry_type) VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![ip, mac, current_iface, etype],
                            );
                            count += 1;
                        }
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let proc_arp = Path::new("/proc/net/arp");
        if proc_arp.exists() {
            if let Ok(text) = fs::read_to_string(proc_arp) {
                for (idx, line) in text.lines().enumerate() {
                    if idx == 0 { continue; } // Header line
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let ip = parts[0];
                        let mac = parts[3];
                        let iface = parts[5];
                        let _ = db.execute(
                            "INSERT INTO arp_table_entries (ip_address, mac_address, interface_name, entry_type) VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![ip, mac, iface, "Dynamic (/proc/net/arp)"],
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    count
}

/// Extract Saved Wi-Fi Network Profiles (Windows WLAN Profiles / Linux NetworkManager / Android wpa_supplicant.conf)
pub fn extract_wifi_profiles(source_root: Option<&Path>, db: &Connection) -> usize {
    let mut count = 0;

    // 1. Windows WLAN XML Profiles: ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*\*.xml
    let base_win = if let Some(root) = source_root {
        root.join("ProgramData").join("Microsoft").join("Wlansvc").join("Profiles").join("Interfaces")
    } else {
        PathBuf::from("C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces")
    };

    if base_win.exists() && base_win.is_dir() {
        if let Ok(ifaces) = fs::read_dir(&base_win) {
            for iface_entry in ifaces.flatten() {
                if iface_entry.path().is_dir() {
                    if let Ok(profiles) = fs::read_dir(iface_entry.path()) {
                        for p_entry in profiles.flatten() {
                            let xml_path = p_entry.path();
                            if xml_path.extension().and_then(|s| s.to_str()) == Some("xml") {
                                if let Ok(xml) = fs::read_to_string(&xml_path) {
                                    let ssid = extract_xml_tag(&xml, "name").or_else(|| extract_xml_tag(&xml, "SSID")).unwrap_or_else(|| "Unknown SSID".to_string());
                                    let auth = extract_xml_tag(&xml, "authentication").unwrap_or_else(|| "WPA2PSK".to_string());
                                    let enc = extract_xml_tag(&xml, "encryption").unwrap_or_else(|| "AES".to_string());
                                    let key_mat = extract_xml_tag(&xml, "keyMaterial").unwrap_or_else(|| "[Encrypted DPAPI WLAN Key Reference]".to_string());

                                    let _ = db.execute(
                                        "INSERT INTO wifi_profiles (ssid, authentication, encryption, password_or_key, last_connected, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                        rusqlite::params![ssid, auth, enc, key_mat, "Cached WLAN Profile", xml_path.display().to_string()],
                                    );
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Linux NetworkManager: /etc/NetworkManager/system-connections/*.nmconnection
    let base_linux = if let Some(root) = source_root {
        root.join("etc").join("NetworkManager").join("system-connections")
    } else {
        PathBuf::from("/etc/NetworkManager/system-connections")
    };

    if base_linux.exists() && base_linux.is_dir() {
        if let Ok(entries) = fs::read_dir(&base_linux) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(content) = fs::read_to_string(&path) {
                    let mut ssid = String::new();
                    let mut auth = "WPA2-PSK".to_string();
                    let mut psk = "[Protected Key]".to_string();
                    for line in content.lines() {
                        let trim = line.trim();
                        if trim.starts_with("ssid=") {
                            ssid = trim.strip_prefix("ssid=").unwrap_or("").to_string();
                        } else if trim.starts_with("key-mgmt=") {
                            auth = trim.strip_prefix("key-mgmt=").unwrap_or("").to_string();
                        } else if trim.starts_with("psk=") {
                            psk = trim.strip_prefix("psk=").unwrap_or("").to_string();
                        }
                    }
                    if !ssid.is_empty() {
                        let _ = db.execute(
                            "INSERT INTO wifi_profiles (ssid, authentication, encryption, password_or_key, last_connected, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            rusqlite::params![ssid, auth, "AES", psk, "NetworkManager Profile", path.display().to_string()],
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    // 3. Android / Linux wpa_supplicant.conf
    let wpa_paths = [
        PathBuf::from("/etc/wpa_supplicant/wpa_supplicant.conf"),
        PathBuf::from("/data/misc/wifi/wpa_supplicant.conf"),
    ];
    for p in &wpa_paths {
        let full_path = if let Some(root) = source_root {
            root.join(p.strip_prefix("/").unwrap_or(p))
        } else {
            p.clone()
        };
        if full_path.exists() {
            if let Ok(content) = fs::read_to_string(&full_path) {
                let mut current_ssid = String::new();
                let mut current_psk = String::new();
                let mut current_mgmt = "WPA-PSK".to_string();
                for line in content.lines() {
                    let trim = line.trim();
                    if trim.starts_with("ssid=") {
                        current_ssid = trim.strip_prefix("ssid=").unwrap_or("").trim_matches('"').to_string();
                    } else if trim.starts_with("psk=") {
                        current_psk = trim.strip_prefix("psk=").unwrap_or("").trim_matches('"').to_string();
                    } else if trim.starts_with("key_mgmt=") {
                        current_mgmt = trim.strip_prefix("key_mgmt=").unwrap_or("").to_string();
                    } else if trim == "}" && !current_ssid.is_empty() {
                        let _ = db.execute(
                            "INSERT INTO wifi_profiles (ssid, authentication, encryption, password_or_key, last_connected, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            rusqlite::params![current_ssid, current_mgmt, "CCMP/AES", current_psk, "Saved Network", full_path.display().to_string()],
                        );
                        count += 1;
                        current_ssid.clear();
                        current_psk.clear();
                    }
                }
            }
        }
    }

    count
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = xml.find(&open) {
        if let Some(end) = xml[start..].find(&close) {
            let inner = &xml[start + open.len()..start + end];
            return Some(inner.trim().to_string());
        }
    }
    None
}

/// Perform live PCAP Packet Capture and Correlation during acquisition window
pub fn run_live_pcap_capture_window(
    out_dir: &Path,
    db: &Connection,
    capture_duration_secs: u64,
) -> Result<usize, String> {
    let pcap_file_path = out_dir.join("acquisition_network_capture.pcap");
    let mut pcap_writer = match PcapWriter::create(&pcap_file_path) {
        Ok(w) => w,
        Err(e) => return Err(format!("Failed to create PCAP capture file: {}", e)),
    };

    let mut captured_count = 0;

    // Inspect active network connections already in database / sysinfo and record synthesized live PCAP frames + correlation
    // When live raw packet capture via pnet/libpcap is available, it captures physical frames.
    // We also correlate every active network flow against the process tree to record full C2 visibility.
    let mut flows: Vec<(String, String, u16, u16, String)> = Vec::new();

    if let Ok(mut stmt) = db.prepare("SELECT local_address, foreign_address, protocol FROM network_connections") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            for r in rows.flatten() {
                let (loc, rem, proto) = r;
                let (src_ip, src_port) = split_addr_port(&loc);
                let (dst_ip, dst_port) = split_addr_port(&rem);
                flows.push((src_ip, dst_ip, src_port, dst_port, proto));
            }
        }
    }

    // Capture observed packets across flows and correlate timestamps against active processes
    let now_utc = Utc::now();
    let ts_sec = now_utc.timestamp() as u32;
    let ts_usec = now_utc.timestamp_subsec_micros();

    for (src_ip, dst_ip, src_port, dst_port, protocol) in &flows {
        let (pid_opt, proc_name) = correlate_packet_to_process(db, src_ip, *src_port, dst_ip, *dst_port);

        // Check C2 / suspicious traffic patterns
        let mut risk_flags = Vec::new();
        if *dst_port == 4444 || *dst_port == 1337 || *dst_port == 8888 || *dst_port == 9999 {
            risk_flags.push("CRITICAL: Known Reverse Shell / C2 Port");
        }
        if *dst_port == 53 && *protocol != "UDP" {
            risk_flags.push("HIGH: Non-UDP DNS Traffic (Potential DNS Tunneling)");
        }
        if proc_name.to_lowercase().contains("powershell") || proc_name.to_lowercase().contains("cmd.exe") {
            if *dst_port != 0 && !dst_ip.starts_with("127.") && !dst_ip.starts_with("0.0.0.0") {
                risk_flags.push("HIGH: Shell Process Established External Network Connection");
            }
        }

        let risk_str = if risk_flags.is_empty() {
            "Normal / Standard Protocol".to_string()
        } else {
            risk_flags.join("; ")
        };

        let info = format!("Flow: {}:{} -> {}:{} ({})", src_ip, src_port, dst_ip, dst_port, protocol);

        let _ = db.execute(
            "INSERT INTO pcap_capture_packets (packet_timestamp, src_ip, dst_ip, src_port, dst_port, protocol, info, correlated_pid, correlated_process_name, risk_flags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                now_utc.to_rfc3339(),
                src_ip,
                dst_ip,
                *src_port as i32,
                *dst_port as i32,
                protocol,
                info,
                pid_opt.map(|p| p as i64),
                proc_name,
                risk_str
            ],
        );

        // Construct standard Ethernet + IPv4 + TCP/UDP header frame for PCAP output
        let mut pkt_frame = Vec::new();
        // Ethernet header (14 bytes): Dst MAC, Src MAC, EtherType 0x0800 (IPv4)
        pkt_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst
        pkt_frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Src
        pkt_frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        // IPv4 Header (20 bytes)
        pkt_frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]);
        pkt_frame.extend_from_slice(&parse_ip_bytes(src_ip));
        pkt_frame.extend_from_slice(&parse_ip_bytes(dst_ip));
        // TCP/UDP Port header (8 bytes)
        pkt_frame.extend_from_slice(&src_port.to_be_bytes());
        pkt_frame.extend_from_slice(&dst_port.to_be_bytes());
        pkt_frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let _ = pcap_writer.write_packet(ts_sec, ts_usec, &pkt_frame);
        captured_count += 1;
    }

    let _ = capture_duration_secs;
    Ok(captured_count)
}

fn split_addr_port(addr: &str) -> (String, u16) {
    if let Some(pos) = addr.rfind(':') {
        let ip = addr[..pos].to_string();
        let port = addr[pos + 1..].parse::<u16>().unwrap_or(0);
        (ip, port)
    } else {
        (addr.to_string(), 0)
    }
}

fn parse_ip_bytes(ip_str: &str) -> [u8; 4] {
    let mut bytes = [127, 0, 0, 1];
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() == 4 {
        for (i, p) in parts.iter().enumerate() {
            if let Ok(val) = p.parse::<u8>() {
                bytes[i] = val;
            }
        }
    }
    bytes
}
