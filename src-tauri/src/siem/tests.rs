#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use std::fs;
    use crate::siem::types::{SiemConfig, SiemDestinationType, SiemEvent};
    use crate::siem::client::SiemClient;

    #[test]
    fn test_siem_config_default() {
        let cfg = SiemConfig::default();
        assert_eq!(cfg.destination_type, SiemDestinationType::SplunkHec);
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_siem_event_serialization() {
        let ev = SiemEvent {
            timestamp: "2026-07-01T12:00:00Z".to_string(),
            host: "test-host".to_string(),
            source: "openforensic:test".to_string(),
            sourcetype: "_json".to_string(),
            event_type: "process".to_string(),
            data: serde_json::json!({"pid": 1234, "name": "cmd.exe"}),
        };

        let json_str = serde_json::to_string(&ev).unwrap();
        assert!(json_str.contains("cmd.exe"));
        assert!(json_str.contains("openforensic:test"));
    }

    #[tokio::test]
    async fn test_wazuh_local_log_export() {
        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join("test_wazuh_openforensic.json");
        let _ = fs::remove_file(&log_file);

        let config = SiemConfig {
            destination_type: SiemDestinationType::WazuhLocalLog,
            endpoint: log_file.to_string_lossy().to_string(),
            auth_token: String::new(),
            index: "openforensic".to_string(),
            enabled: true,
        };

        let client = SiemClient::new(config);
        let ev = SiemEvent {
            timestamp: "2026-07-01T12:00:00Z".to_string(),
            host: "test-host".to_string(),
            source: "openforensic:triage".to_string(),
            sourcetype: "_json".to_string(),
            event_type: "test".to_string(),
            data: serde_json::json!({"test": true}),
        };

        let res = client.send_event(&ev).await;
        assert!(res.is_ok(), "Failed to write local log event: {:?}", res.err());

        let content = fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("\"test\":true"));
        let _ = fs::remove_file(&log_file);
    }
}
