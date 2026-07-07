#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
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
    async fn test_siem_client_stub() {
        let config = SiemConfig::default();
        let client = SiemClient::new(config);
        let res = client.test_connection().await;
        assert!(res.is_ok());
        assert!(res.unwrap().contains("pruned"));
    }
}
