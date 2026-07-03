use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemDestinationType {
    SplunkHec,
    WazuhSocket,
    WazuhLocalLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub destination_type: SiemDestinationType,
    pub endpoint: String,      // e.g., "https://splunk.example.com:8088" or "127.0.0.1:1514" or "/var/ossec/logs/openforensic.json"
    pub auth_token: String,    // Splunk HEC Token or Wazuh API/Socket Key
    pub index: String,         // Index / Source / Tag e.g. "openforensic_triage"
    pub enabled: bool,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            destination_type: SiemDestinationType::SplunkHec,
            endpoint: String::new(),
            auth_token: String::new(),
            index: "openforensic_triage".to_string(),
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub timestamp: String,
    pub host: String,
    pub source: String,
    pub sourcetype: String,
    pub event_type: String, // e.g., "process", "network_connection", "browser_history", "event_log", "ioc_alert"
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemExportSummary {
    pub total_events: usize,
    pub successful_events: usize,
    pub failed_events: usize,
    pub duration_ms: u128,
    pub message: String,
}
