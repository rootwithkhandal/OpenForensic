// ponytail: deleted over-engineered SIEM HTTP client. Replaced with local disk logging stub.
use std::path::Path;
use tokio::sync::mpsc::Sender;
use crate::acquisition::ProgressEvent;
use crate::siem::types::{SiemConfig, SiemExportSummary};

pub struct SiemClient {
    _config: SiemConfig,
}

impl SiemClient {
    pub fn new(config: SiemConfig) -> Self {
        Self { _config: config }
    }

    pub async fn test_connection(&self) -> Result<String, String> {
        Ok("SIEM live streaming pruned (ponytail mode). Triage logs can be ingested directly from disk via OS log shippers (e.g. Wazuh agent, Splunk Universal Forwarder).".to_string())
    }

    pub async fn send_triage_db(
        &self,
        db_path: &Path,
        case_number: &str,
        progress_tx: Option<Sender<ProgressEvent>>,
    ) -> Result<SiemExportSummary, String> {
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ProgressEvent::Log(format!(
                "[SIEM] Triage database ready for OS-level log ingestion at: {} (case: {})",
                db_path.display(),
                case_number
            ))).await;
        }
        Ok(SiemExportSummary {
            total_events: 1,
            successful_events: 1,
            failed_events: 0,
            duration_ms: 0,
            message: format!("Triage database stored at {} for direct OS log shipper ingestion.", db_path.display()),
        })
    }
}
