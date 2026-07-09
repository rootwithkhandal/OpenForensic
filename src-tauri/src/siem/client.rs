use std::path::Path;
use std::io::Write;
use tokio::sync::mpsc::Sender;
use tokio::io::AsyncWriteExt;
use crate::acquisition::ProgressEvent;
use crate::siem::types::{SiemConfig, SiemDestinationType, SiemEvent, SiemExportSummary};

pub struct SiemClient {
    config: SiemConfig,
}

impl SiemClient {
    pub fn new(config: SiemConfig) -> Self {
        Self { config }
    }

    pub async fn test_connection(&self) -> Result<String, String> {
        if self.config.endpoint.trim().is_empty() {
            return Err("SIEM Endpoint URL or socket address is not configured".to_string());
        }

        match self.config.destination_type {
            SiemDestinationType::SplunkHec => {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

                let host_name = sysinfo::System::host_name().unwrap_or_else(|| "openforensic-host".to_string());
                let test_payload = serde_json::json!({
                    "time": chrono::Utc::now().timestamp(),
                    "host": host_name,
                    "source": "openforensic:triage:test",
                    "sourcetype": "_json",
                    "index": self.config.index,
                    "event": {
                        "message": "OpenForensic SIEM/SOC connection verification test",
                        "status": "connected"
                    }
                });

                let resp = client
                    .post(&self.config.endpoint)
                    .header("Authorization", format!("Splunk {}", self.config.auth_token))
                    .json(&test_payload)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP connection error to Splunk HEC ({}): {}", self.config.endpoint, e))?;

                if resp.status().is_success() {
                    Ok(format!("Splunk HEC connection successful! (HTTP Status: {})", resp.status()))
                } else {
                    let status = resp.status();
                    let err_text = resp.text().await.unwrap_or_default();
                    Err(format!("Splunk HEC returned error status: {} - {}", status, err_text))
                }
            }
            SiemDestinationType::WazuhSocket => {
                let addr = self.config.endpoint.trim_start_matches("tcp://").trim_start_matches("udp://");
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(mut stream) => {
                        let _ = stream.write_all(b"{\"openforensic\":\"connection_test\"}\n").await;
                        Ok(format!("Successfully connected to Wazuh TCP socket at {}", addr))
                    }
                    Err(tcp_err) => {
                        // Attempt UDP bind and send test if TCP fails
                        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                            Ok(socket) => {
                                if socket.send_to(b"{\"openforensic\":\"connection_test\"}", addr).await.is_ok() {
                                    Ok(format!("Successfully verified Wazuh UDP socket reachability at {}", addr))
                                } else {
                                    Err(format!("Failed to connect to Wazuh socket via TCP ({}) or UDP: {}", tcp_err, addr))
                                }
                            }
                            Err(_) => Err(format!("Failed to connect to Wazuh socket at {}: {}", addr, tcp_err)),
                        }
                    }
                }
            }
            SiemDestinationType::WazuhLocalLog => {
                let path = Path::new(&self.config.endpoint);
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create Wazuh log directory {}: {}", parent.display(), e))?;
                    }
                }
                match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    Ok(_) => Ok(format!("Wazuh local log file {} is ready and writable for OS agent ingestion", path.display())),
                    Err(e) => Err(format!("Cannot write to Wazuh local log file {}: {}", path.display(), e)),
                }
            }
        }
    }

    pub async fn send_triage_db(
        &self,
        db_path: &Path,
        case_number: &str,
        progress_tx: Option<Sender<ProgressEvent>>,
    ) -> Result<SiemExportSummary, String> {
        let start_time = std::time::Instant::now();
        if !db_path.exists() {
            return Err(format!("Triage database not found at {}", db_path.display()));
        }

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!(
                "[SIEM] Starting live event streaming from {} to destination: {:?}",
                db_path.display(),
                self.config.destination_type
            ))).await;
        }

        let host_name = sysinfo::System::host_name().unwrap_or_else(|| "openforensic-host".to_string());
        let mut all_events: Vec<SiemEvent> = Vec::new();

        {
            let conn = rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| format!("Failed to open triage database for SIEM export: {}", e))?;

            let tables = [
                "processes", "connections", "anti_forensics_alerts", "pcap_capture_packets", "dns_cache_entries",
                "arp_table_entries", "wifi_profiles", "browser_history", "browser_cookies",
                "browser_logins", "browser_downloads", "browser_extensions", "event_logs",
                "im_apps", "memory_triage", "network_triage", "cloud_remote_triage",
                "iot_embedded_triage", "triage_audit_log"
            ];

            for table in &tables {
                let mut stmt = match conn.prepare(&format!("SELECT * FROM {}", table)) {
                    Ok(s) => s,
                    Err(_) => continue, // Table might not exist or be empty
                };

                let col_count = stmt.column_count();
                let col_names: Vec<String> = (0..col_count).map(|i| stmt.column_name(i).unwrap_or("unknown").to_string()).collect();

                let mut rows = match stmt.query([]) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                while let Ok(Some(row)) = rows.next() {
                    let mut map = serde_json::Map::new();
                    for (i, name) in col_names.iter().enumerate() {
                        let val: rusqlite::types::Value = row.get(i).unwrap_or(rusqlite::types::Value::Null);
                        let json_val = match val {
                            rusqlite::types::Value::Null => serde_json::Value::Null,
                            rusqlite::types::Value::Integer(n) => serde_json::Value::Number(n.into()),
                            rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
                            rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
                            rusqlite::types::Value::Blob(b) => serde_json::Value::String(hex::encode(b)),
                        };
                        map.insert(name.clone(), json_val);
                    }
                    map.insert("case_number".to_string(), serde_json::Value::String(case_number.to_string()));

                    all_events.push(SiemEvent {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        host: host_name.clone(),
                        source: format!("openforensic:triage:{}", table),
                        sourcetype: "_json".to_string(),
                        event_type: table.to_string(),
                        data: serde_json::Value::Object(map),
                    });
                }
            }
        }

        let http_client = if self.config.destination_type == SiemDestinationType::SplunkHec {
            Some(reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?)
        } else {
            None
        };

        let total_events = all_events.len();
        let mut successful_events = 0;
        let mut failed_events = 0;

        for siem_event in all_events {
            match self.config.destination_type {
                SiemDestinationType::SplunkHec => {
                    if let Some(ref client) = http_client {
                        let splunk_payload = serde_json::json!({
                            "time": chrono::Utc::now().timestamp(),
                            "host": siem_event.host,
                            "source": siem_event.source,
                            "sourcetype": siem_event.sourcetype,
                            "index": self.config.index,
                            "event": siem_event.data
                        });

                        let res = client
                            .post(&self.config.endpoint)
                            .header("Authorization", format!("Splunk {}", self.config.auth_token))
                            .json(&splunk_payload)
                            .send()
                            .await;

                        match res {
                            Ok(r) if r.status().is_success() => successful_events += 1,
                            _ => failed_events += 1,
                        }
                    }
                }
                SiemDestinationType::WazuhSocket => {
                    let addr = self.config.endpoint.trim_start_matches("tcp://").trim_start_matches("udp://");
                    let json_line = format!("{}\n", serde_json::to_string(&siem_event).unwrap_or_default());
                    if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                        if stream.write_all(json_line.as_bytes()).await.is_ok() {
                            successful_events += 1;
                            continue;
                        }
                    }
                    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        if socket.send_to(json_line.as_bytes(), addr).await.is_ok() {
                            successful_events += 1;
                            continue;
                        }
                    }
                    failed_events += 1;
                }
                SiemDestinationType::WazuhLocalLog => {
                    let path = Path::new(&self.config.endpoint);
                    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                        if writeln!(file, "{}", serde_json::to_string(&siem_event).unwrap_or_default()).is_ok() {
                            successful_events += 1;
                            continue;
                        }
                    }
                    failed_events += 1;
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis();
        let message = format!(
            "SIEM Export complete: {} total events processed ({} successful, {} failed) in {} ms.",
            total_events, successful_events, failed_events, duration_ms
        );

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!("[SIEM] {}", message))).await;
        }

        Ok(SiemExportSummary {
            total_events,
            successful_events,
            failed_events,
            duration_ms,
            message,
        })
    }
}
