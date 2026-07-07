//! Network connection scanner plugin — scans memory for socket/connection structures.
//!
//! Implements:
//!   - `windows.netstat.NetStat` / `netstat` / `connscan`
//!
//! Scans for TCP endpoint and UDP endpoint pool tags in Windows memory dumps
//! and extracts connection metadata including local/remote addresses and ports.

use crate::error::Result;
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

/// Windows TCP Endpoint pool tag: "TcpE"
const TCP_ENDPOINT_TAG: &[u8; 4] = b"TcpE";

/// Windows TCP Listener pool tag: "TcpL"
const TCP_LISTENER_TAG: &[u8; 4] = b"TcpL";

/// Windows UDP Endpoint pool tag: "UdpA"
const UDP_ENDPOINT_TAG: &[u8; 4] = b"UdpA";

/// Convert a u32 state value to a TCP state string.
fn tcp_state_string(state: u32) -> &'static str {
    match state {
        0 => "CLOSED",
        1 => "LISTENING",
        2 => "SYN_SENT",
        3 => "SYN_RCVD",
        4 => "ESTABLISHED",
        5 => "FIN_WAIT1",
        6 => "FIN_WAIT2",
        7 => "CLOSE_WAIT",
        8 => "CLOSING",
        9 => "LAST_ACK",
        10 => "TIME_WAIT",
        11 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Format a 4-byte array as a dotted IPv4 address.
fn format_ipv4(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Run the network connection scanner.
pub async fn run(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running windows.netstat.NetStat — scanning for network connection structures...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // Scan for all three pool tag types
    let tcp_endpoints = reader.scan_pool_tag(TCP_ENDPOINT_TAG)?;
    let tcp_listeners = reader.scan_pool_tag(TCP_LISTENER_TAG)?;
    let udp_endpoints = reader.scan_pool_tag(UDP_ENDPOINT_TAG)?;

    tx.send(format!(
        "[VOLATILITY] Pool tag scan results: {} TcpE, {} TcpL, {} UdpA",
        tcp_endpoints.len(),
        tcp_listeners.len(),
        udp_endpoints.len()
    )).await?;

    // Table header
    tx.send(format!(
        "{:<8} {:<22} {:<22} {:<14} {:<8} {}",
        "Proto", "Local Address", "Remote Address", "State", "PID", "Process"
    )).await?;
    tx.send("-".repeat(90)).await?;

    let mut conn_count = 0u32;

    // Process TCP endpoints (established connections)
    for &tag_offset in &tcp_endpoints {
        let base = tag_offset + 4; // After pool tag

        // Try known struct offsets for Windows 10 x64 _TCP_ENDPOINT
        // Local port is typically at base+0x72, remote port at base+0x74
        // Local IP at base+0x58, Remote IP at base+0x78
        // PID typically at base+0x238 or similar via owning process pointer

        // Read local port (2 bytes, big-endian in network byte order)
        let mut port_buf = [0u8; 2];
        if reader.read_at(base + 0x72, &mut port_buf).unwrap_or(0) < 2 {
            continue;
        }
        let local_port = u16::from_be_bytes(port_buf);

        if reader.read_at(base + 0x74, &mut port_buf).unwrap_or(0) < 2 {
            continue;
        }
        let remote_port = u16::from_be_bytes(port_buf);

        // Read local IP (4 bytes)
        let mut ip_buf = [0u8; 4];
        if reader.read_at(base + 0x58, &mut ip_buf).unwrap_or(0) < 4 {
            continue;
        }
        let local_ip = format_ipv4(&ip_buf);

        if reader.read_at(base + 0x78, &mut ip_buf).unwrap_or(0) < 4 {
            continue;
        }
        let remote_ip = format_ipv4(&ip_buf);

        // Read state
        let state = reader.read_u32_le(base + 0x6C).unwrap_or(0);

        // Read PID from the owning process
        let pid = reader.read_u32_le(base + 0x238).unwrap_or(0);

        // Sanity checks
        if state > 11 || (local_port == 0 && remote_port == 0) {
            continue;
        }
        if pid > 100_000 || (pid != 0 && pid % 4 != 0) {
            continue;
        }

        let local_addr = format!("{}:{}", local_ip, local_port);
        let remote_addr = format!("{}:{}", remote_ip, remote_port);

        tx.send(format!(
            "{:<8} {:<22} {:<22} {:<14} {:<8} {}",
            "TCP",
            local_addr,
            remote_addr,
            tcp_state_string(state),
            pid,
            "-"
        )).await?;

        conn_count += 1;
    }

    // Process TCP listeners
    for &tag_offset in &tcp_listeners {
        let base = tag_offset + 4;

        let mut port_buf = [0u8; 2];
        if reader.read_at(base + 0x6A, &mut port_buf).unwrap_or(0) < 2 {
            continue;
        }
        let local_port = u16::from_be_bytes(port_buf);

        if local_port == 0 {
            continue;
        }

        let mut ip_buf = [0u8; 4];
        if reader.read_at(base + 0x58, &mut ip_buf).unwrap_or(0) < 4 {
            continue;
        }
        let local_ip = format_ipv4(&ip_buf);

        let pid = reader.read_u32_le(base + 0x22C).unwrap_or(0);
        if pid > 100_000 || (pid != 0 && pid % 4 != 0) {
            continue;
        }

        tx.send(format!(
            "{:<8} {:<22} {:<22} {:<14} {:<8} {}",
            "TCP",
            format!("{}:{}", local_ip, local_port),
            "0.0.0.0:0",
            "LISTENING",
            pid,
            "-"
        )).await?;

        conn_count += 1;
    }

    // Process UDP endpoints
    for &tag_offset in &udp_endpoints {
        let base = tag_offset + 4;

        let mut port_buf = [0u8; 2];
        if reader.read_at(base + 0x80, &mut port_buf).unwrap_or(0) < 2 {
            continue;
        }
        let local_port = u16::from_be_bytes(port_buf);

        if local_port == 0 {
            continue;
        }

        let mut ip_buf = [0u8; 4];
        if reader.read_at(base + 0x58, &mut ip_buf).unwrap_or(0) < 4 {
            continue;
        }
        let local_ip = format_ipv4(&ip_buf);

        let pid = reader.read_u32_le(base + 0x20).unwrap_or(0);
        if pid > 100_000 || (pid != 0 && pid % 4 != 0) {
            continue;
        }

        tx.send(format!(
            "{:<8} {:<22} {:<22} {:<14} {:<8} {}",
            "UDP",
            format!("{}:{}", local_ip, local_port),
            "*:*",
            "-",
            pid,
            "-"
        )).await?;

        conn_count += 1;
    }

    tx.send(format!(
        "\n[VOLATILITY] netstat complete — {} network connections/listeners identified",
        conn_count
    )).await?;

    Ok(())
}
