use std::path::Path;
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::io::AsyncWriteExt;
use crate::acquisition::ProgressEvent;
use crate::siem::types::{SiemConfig, SiemDestinationType, SiemEvent, SiemExportSummary};

pub struct SiemClient {
    config: SiemConfig,
    http_client: reqwest::Client,
}

impl SiemClient {
    pub fn new(config: SiemConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http_client,
        }
    }

    pub async fn test_connection(&self) -> Result<String, String> {
        let host = sysinfo::System::host_name().unwrap_or_else(|| "openforensic-host".to_string());
        let event = SiemEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            host: host.clone(),
            source: "openforensic:heartbeat".to_string(),
            sourcetype: self.config.index.clone(),
            event_type: "heartbeat".to_string(),
            data: serde_json::json!({
                "status": "online",
                "message": "OpenForensic SIEM Integration Test Heartbeat",
                "version": "2.0.2",
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            }),
        };

        self.send_event(&event).await?;
        Ok(format!("Successfully sent heartbeat test event to {} ({:?})", self.config.endpoint, self.config.destination_type))
    }

    pub async fn send_event(&self, event: &SiemEvent) -> Result<(), String> {
        match self.config.destination_type {
            SiemDestinationType::SplunkHec => {
                let mut endpoint = self.config.endpoint.trim().trim_end_matches('/').to_string();
                if !endpoint.ends_with("/services/collector/event") && !endpoint.ends_with("/services/collector") {
                    endpoint.push_str("/services/collector/event");
                }

                let splunk_payload = serde_json::json!({
                    "time": chrono::Utc::now().timestamp(),
                    "host": event.host,
                    "source": event.source,
                    "sourcetype": event.sourcetype,
                    "index": if self.config.index.is_empty() { "main" } else { &self.config.index },
                    "event": {
                        "event_type": event.event_type,
                        "timestamp": event.timestamp,
                        "data": event.data
                    }
                });

                let auth_header = if self.config.auth_token.starts_with("Splunk ") {
                    self.config.auth_token.clone()
                } else {
                    format!("Splunk {}", self.config.auth_token)
                };

                let resp = self.http_client
                    .post(&endpoint)
                    .header("Authorization", auth_header)
                    .json(&splunk_payload)
                    .send()
                    .await
                    .map_err(|e| format!("Splunk HEC request failed: {}", e))?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(format!("Splunk HEC error ({}): {}", status, text));
                }
                Ok(())
            }
            SiemDestinationType::WazuhSocket => {
                let json_line = serde_json::to_string(event).map_err(|e| e.to_string())? + "\n";
                
                // Try TCP first
                if let Ok(mut stream) = tokio::net::TcpStream::connect(&self.config.endpoint).await {
                    stream.write_all(json_line.as_bytes()).await.map_err(|e| format!("TCP socket write error: {}", e))?;
                    stream.flush().await.map_err(|e| format!("TCP socket flush error: {}", e))?;
                    return Ok(());
                }

                // Fallback to UDP socket
                if let Ok(udp) = tokio::net::UdpSocket::bind("0.0.0.0:0").await
                    && udp.send_to(json_line.as_bytes(), &self.config.endpoint).await.is_ok()
                {
                    return Ok(());
                }

                Err(format!("Failed to connect to Wazuh socket at {}", self.config.endpoint))
            }
            SiemDestinationType::WazuhLocalLog => {
                let json_line = serde_json::to_string(event).map_err(|e| e.to_string())? + "\n";
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.config.endpoint)
                    .await
                    .map_err(|e| format!("Failed to open Wazuh log file {}: {}", self.config.endpoint, e))?;

                file.write_all(json_line.as_bytes()).await.map_err(|e| e.to_string())?;
                file.flush().await.map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    pub async fn send_triage_db(
        &self,
        db_path: &Path,
        case_number: &str,
        progress_tx: Option<Sender<ProgressEvent>>,
    ) -> Result<SiemExportSummary, String> {
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!("[SIEM] Starting export of triage database {} for case {}...", db_path.display(), case_number))).await;
        }
        let host = sysinfo::System::host_name().unwrap_or_else(|| "openforensic-host".to_string());
        let summary_event = SiemEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            host,
            source: "openforensic:triage".to_string(),
            sourcetype: self.config.index.clone(),
            event_type: "triage_summary".to_string(),
            data: serde_json::json!({
                "case_number": case_number,
                "db_path": db_path.to_string_lossy(),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "status": "completed",
            }),
        };
        let _ = self.send_event(&summary_event).await;
        self.export_from_triage_db(db_path, progress_tx).await
    }

    /// Read forensic records from a SQLite Triage database and export them sequentially to SIEM.
    pub async fn export_from_triage_db(
        &self,
        db_path: &Path,
        progress_tx: Option<Sender<ProgressEvent>>,
    ) -> Result<SiemExportSummary, String> {
        let start_time = Instant::now();
        if !db_path.exists() {
            return Err(format!("Triage database not found: {}", db_path.display()));
        }

        let db = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ).map_err(|e| format!("Failed to open Triage DB {}: {}", db_path.display(), e))?;

        let host = sysinfo::System::host_name().unwrap_or_else(|| "unknown-host".to_string());
        let mut events: Vec<SiemEvent> = Vec::new();

        // 1. System Info
        if let Ok(mut stmt) = db.prepare("SELECT hostname, os_name, os_version, cpu_arch, total_ram, boot_time FROM system_info LIMIT 1")
            && let Ok(mut rows) = stmt.query([])
            && let Ok(Some(row)) = rows.next()
        {
            events.push(SiemEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                host: host.clone(),
                source: "openforensic:triage".to_string(),
                sourcetype: self.config.index.clone(),
                event_type: "system_info".to_string(),
                data: serde_json::json!({
                    "hostname": row.get::<_, String>(0).unwrap_or_default(),
                    "os_name": row.get::<_, String>(1).unwrap_or_default(),
                    "os_version": row.get::<_, String>(2).unwrap_or_default(),
                    "cpu_arch": row.get::<_, String>(3).unwrap_or_default(),
                    "total_ram": row.get::<_, u64>(4).unwrap_or_default(),
                    "boot_time": row.get::<_, i64>(5).unwrap_or_default(),
                }),
            });
        }

        // 2. Processes
        if let Ok(mut stmt) = db.prepare("SELECT pid, name, executable_path, command_line, memory_usage FROM processes")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "pid": row.get::<_, u32>(0).unwrap_or_default(),
                    "name": row.get::<_, String>(1).unwrap_or_default(),
                    "executable_path": row.get::<_, String>(2).unwrap_or_default(),
                    "command_line": row.get::<_, String>(3).unwrap_or_default(),
                    "memory_usage": row.get::<_, i64>(4).unwrap_or_default(),
                }))
            })
        {
            for r in rows.flatten() {
                events.push(SiemEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    host: host.clone(),
                    source: "openforensic:triage".to_string(),
                    sourcetype: self.config.index.clone(),
                    event_type: "process".to_string(),
                    data: r,
                });
            }
        }

        // 3. Network Connections
        if let Ok(mut stmt) = db.prepare("SELECT protocol, local_address, foreign_address, state, pid FROM network_connections")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "protocol": row.get::<_, String>(0).unwrap_or_default(),
                    "local_address": row.get::<_, String>(1).unwrap_or_default(),
                    "foreign_address": row.get::<_, String>(2).unwrap_or_default(),
                    "state": row.get::<_, String>(3).unwrap_or_default(),
                    "pid": row.get::<_, u32>(4).unwrap_or_default(),
                }))
            })
        {
            for r in rows.flatten() {
                events.push(SiemEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    host: host.clone(),
                    source: "openforensic:triage".to_string(),
                    sourcetype: self.config.index.clone(),
                    event_type: "network_connection".to_string(),
                    data: r,
                });
            }
        }

        // 4. Browser History
        if let Ok(mut stmt) = db.prepare("SELECT browser_name, url, title, visit_time, visit_count FROM browser_history")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "browser_name": row.get::<_, String>(0).unwrap_or_default(),
                    "url": row.get::<_, String>(1).unwrap_or_default(),
                    "title": row.get::<_, String>(2).unwrap_or_default(),
                    "visit_time": row.get::<_, String>(3).unwrap_or_default(),
                    "visit_count": row.get::<_, i32>(4).unwrap_or_default(),
                }))
            })
        {
            for r in rows.flatten() {
                events.push(SiemEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    host: host.clone(),
                    source: "openforensic:triage".to_string(),
                    sourcetype: self.config.index.clone(),
                    event_type: "browser_history".to_string(),
                    data: r,
                });
            }
        }

        // 5. Event Logs
        if let Ok(mut stmt) = db.prepare("SELECT log_name, event_id, source, time_created, message FROM event_logs")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "log_name": row.get::<_, String>(0).unwrap_or_default(),
                    "event_id": row.get::<_, i64>(1).unwrap_or_default(),
                    "source": row.get::<_, String>(2).unwrap_or_default(),
                    "time_created": row.get::<_, String>(3).unwrap_or_default(),
                    "message": row.get::<_, String>(4).unwrap_or_default(),
                }))
            })
        {
            for r in rows.flatten() {
                events.push(SiemEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    host: host.clone(),
                    source: "openforensic:triage".to_string(),
                    sourcetype: self.config.index.clone(),
                    event_type: "event_log".to_string(),
                    data: r,
                });
            }
        }

        let total_events = events.len();
        let mut successful = 0;
        let mut failed = 0;

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!("[SIEM] Prepared {} forensic records for SIEM export.", total_events))).await;
        }

        for (idx, event) in events.iter().enumerate() {
            match self.send_event(event).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    failed += 1;
                    if failed <= 3
                        && let Some(ref tx) = progress_tx
                    {
                        let _ = tx.send(ProgressEvent::Log(format!("[SIEM ERROR] Failed to send event #{}: {}", idx + 1, e))).await;
                    }
                }
            }

            if (idx + 1) % 50 == 0
                && let Some(ref tx) = progress_tx
            {
                let _ = tx.send(ProgressEvent::Log(format!("[SIEM] Exported {} / {} records...", idx + 1, total_events))).await;
            }
        }

        let duration_ms = start_time.elapsed().as_millis();
        let msg = format!("SIEM export complete: {} successful, {} failed out of {} total events (in {} ms).", successful, failed, total_events, duration_ms);

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!("[SIEM] {}", msg))).await;
        }

        Ok(SiemExportSummary {
            total_events,
            successful_events: successful,
            failed_events: failed,
            duration_ms,
            message: msg,
        })
    }
}
