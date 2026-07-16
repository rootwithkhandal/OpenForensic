#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use crate::siem::types::{SiemConfig, SiemDestinationType, SiemEvent};
    use crate::siem::client::SiemClient;
    use std::fs;

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
    async fn test_siem_client_empty_endpoint_fails() {
        let config = SiemConfig::default();
        let client = SiemClient::new(config);
        let res = client.test_connection().await;
        assert!(res.is_err(), "Empty endpoint MUST return an error when testing connection");
    }

    #[tokio::test]
    async fn test_siem_client_local_log_export() {
        let temp_dir = std::env::temp_dir().join("openforensic_siem_test");
        let _ = fs::create_dir_all(&temp_dir);
        
        let db_path = temp_dir.join("test_triage.db");
        let log_path = temp_dir.join("wazuh_test.log");

        // Create a temporary SQLite database with a test table and row
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("CREATE TABLE processes (pid INTEGER, name TEXT)", []).unwrap();
            conn.execute("INSERT INTO processes (pid, name) VALUES (1337, 'svchost.exe')", []).unwrap();
        }

        let config = SiemConfig {
            destination_type: SiemDestinationType::WazuhLocalLog,
            endpoint: log_path.to_string_lossy().to_string(),
            auth_token: String::new(),
            index: "test_index".to_string(),
            enabled: true,
        };

        let client = SiemClient::new(config);
        
        // Test connection (should verify file/dir writability)
        let conn_res = client.test_connection().await;
        assert!(conn_res.is_ok(), "WazuhLocalLog connection test failed: {:?}", conn_res.err());

        // Test database streaming
        let summary_res = client.send_triage_db(&db_path, "CASE-2026-001", None).await;
        assert!(summary_res.is_ok());
        let summary = summary_res.unwrap();
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.successful_events, 1);
        assert_eq!(summary.failed_events, 0);

        // Verify log file content on disk
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("svchost.exe"));
        assert!(log_content.contains("CASE-2026-001"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
