use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize, Debug)]
pub struct Case {
    pub id: i64,
    pub case_number: String,
    pub examiner_name: String,
    pub notes: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceItem {
    pub id: i64,
    pub case_id: i64,
    pub evidence_tag: String,
    pub source_path: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcquisitionLog {
    pub id: i64,
    pub evidence_id: i64,
    pub dest_path: String,
    pub format: String,
    pub hash_log: String,
    pub status: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CaseDetail {
    pub case: Case,
    pub evidence: Vec<EvidenceDetail>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceDetail {
    pub item: EvidenceItem,
    pub logs: Vec<AcquisitionLog>,
}

fn get_db_path(app: &AppHandle) -> std::result::Result<PathBuf, String> {
    let mut path = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    path.push("cases.db");
    Ok(path)
}

pub fn init_db(app: &AppHandle) -> Result<(), String> {
    let db_path = get_db_path(app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE NOT NULL,
            examiner_name TEXT NOT NULL,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS evidence_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_tag TEXT NOT NULL,
            source_path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )",
        [],
    ).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS acquisition_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            dest_path TEXT NOT NULL,
            format TEXT NOT NULL,
            hash_log TEXT NOT NULL,
            status TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence_items(id)
        )",
        [],
    ).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            investigator TEXT NOT NULL,
            case_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        )",
        [],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn log_audit_event(
    app: &AppHandle,
    investigator: &str,
    case_id: &str,
    event_type: &str,
    details: &str,
) -> Result<(), String> {
    let db_path = get_db_path(app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO audit_logs (investigator, case_id, event_type, details) VALUES (?1, ?2, ?3, ?4)",
        params![investigator, case_id, event_type, details],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn log_acquisition_to_db(
    app: &AppHandle,
    case_number: &str,
    examiner_name: &str,
    notes: &str,
    evidence_tag: &str,
    source_path: &str,
    dest_path: &str,
    format: &str,
    hash_log: &str,
    status: &str,
) -> Result<(), String> {
    let db_path = get_db_path(app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    // Create or get case
    let case_id: i64 = match conn.query_row(
        "SELECT id FROM cases WHERE case_number = ?1",
        params![case_number],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => {
            conn.execute(
                "INSERT INTO cases (case_number, examiner_name, notes) VALUES (?1, ?2, ?3)",
                params![case_number, examiner_name, notes],
            ).map_err(|e| e.to_string())?;
            conn.last_insert_rowid()
        }
    };

    // Create or get evidence item
    let evidence_id: i64 = match conn.query_row(
        "SELECT id FROM evidence_items WHERE case_id = ?1 AND evidence_tag = ?2",
        params![case_id, evidence_tag],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => {
            conn.execute(
                "INSERT INTO evidence_items (case_id, evidence_tag, source_path) VALUES (?1, ?2, ?3)",
                params![case_id, evidence_tag, source_path],
            ).map_err(|e| e.to_string())?;
            conn.last_insert_rowid()
        }
    };

    // Log acquisition
    conn.execute(
        "INSERT INTO acquisition_logs (evidence_id, dest_path, format, hash_log, status) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![evidence_id, dest_path, format, hash_log, status],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub fn get_cases(app: AppHandle) -> Result<Vec<Case>, String> {
    let db_path = get_db_path(&app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let mut stmt = conn.prepare("SELECT id, case_number, examiner_name, notes, created_at FROM cases ORDER BY created_at DESC").map_err(|e| e.to_string())?;
    let cases = stmt.query_map([], |row| {
        Ok(Case {
            id: row.get(0)?,
            case_number: row.get(1)?,
            examiner_name: row.get(2)?,
            notes: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            created_at: row.get(4)?,
        })
    }).map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;

    Ok(cases)
}

#[tauri::command]
pub fn get_case_details(app: AppHandle, case_id: i64) -> Result<CaseDetail, String> {
    let db_path = get_db_path(&app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let case: Case = conn.query_row(
        "SELECT id, case_number, examiner_name, notes, created_at FROM cases WHERE id = ?1",
        params![case_id],
        |row| {
            Ok(Case {
                id: row.get(0)?,
                case_number: row.get(1)?,
                examiner_name: row.get(2)?,
                notes: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                created_at: row.get(4)?,
            })
        },
    ).map_err(|e| e.to_string())?;

    let mut evidence_stmt = conn.prepare("SELECT id, case_id, evidence_tag, source_path, created_at FROM evidence_items WHERE case_id = ?1").map_err(|e| e.to_string())?;
    let evidence_items: Vec<EvidenceItem> = evidence_stmt.query_map(params![case_id], |row| {
        Ok(EvidenceItem {
            id: row.get(0)?,
            case_id: row.get(1)?,
            evidence_tag: row.get(2)?,
            source_path: row.get(3)?,
            created_at: row.get(4)?,
        })
    }).map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;

    let mut details = Vec::new();
    let mut log_stmt = conn.prepare("SELECT id, evidence_id, dest_path, format, hash_log, status, timestamp FROM acquisition_logs WHERE evidence_id = ?1").map_err(|e| e.to_string())?;
    
    for item in evidence_items {
        let logs = log_stmt.query_map(params![item.id], |row| {
            Ok(AcquisitionLog {
                id: row.get(0)?,
                evidence_id: row.get(1)?,
                dest_path: row.get(2)?,
                format: row.get(3)?,
                hash_log: row.get(4)?,
                status: row.get(5)?,
                timestamp: row.get(6)?,
            })
        }).map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        
        details.push(EvidenceDetail { item, logs });
    }

    Ok(CaseDetail { case, evidence: details })
}

#[tauri::command]
pub fn export_case_report(app: AppHandle, case_id: i64, export_path: String) -> Result<(), String> {
    let details = get_case_details(app.clone(), case_id)?;
    
    let mut report = String::new();
    report.push_str("<!DOCTYPE html><html><head><title>Forensic Case Report</title>");
    report.push_str("<style>body{font-family:sans-serif;margin:40px;line-height:1.6;}h1,h2,h3{color:#333;}table{border-collapse:collapse;width:100%;margin-bottom:20px;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}th{background:#eee;}</style>");
    report.push_str("</head><body>");
    
    report.push_str(&format!("<h1>Forensic Acquisition Report: {}</h1>", details.case.case_number));
    report.push_str("<h2>Case Details</h2>");
    report.push_str("<table>");
    report.push_str(&format!("<tr><th>Case Number</th><td>{}</td></tr>", details.case.case_number));
    report.push_str(&format!("<tr><th>Examiner Name</th><td>{}</td></tr>", details.case.examiner_name));
    report.push_str(&format!("<tr><th>Notes</th><td>{}</td></tr>", details.case.notes));
    report.push_str(&format!("<tr><th>Created At</th><td>{}</td></tr>", details.case.created_at));
    report.push_str("</table>");

    report.push_str("<h2>Evidence Items & Chain of Custody</h2>");
    for (i, ev) in details.evidence.iter().enumerate() {
        report.push_str(&format!("<h3>Evidence #{}: {}</h3>", i + 1, ev.item.evidence_tag));
        report.push_str("<table>");
        report.push_str(&format!("<tr><th>Source Path</th><td>{}</td></tr>", ev.item.source_path));
        report.push_str(&format!("<tr><th>Tagged At</th><td>{}</td></tr>", ev.item.created_at));
        report.push_str("</table>");

        report.push_str("<h4>Acquisition Logs</h4>");
        if ev.logs.is_empty() {
            report.push_str("<p>No acquisitions logged for this item yet.</p>");
        } else {
            for log in &ev.logs {
                report.push_str("<table>");
                report.push_str(&format!("<tr><th>Status</th><td>{}</td></tr>", log.status));
                report.push_str(&format!("<tr><th>Timestamp</th><td>{}</td></tr>", log.timestamp));
                report.push_str(&format!("<tr><th>Destination</th><td>{}</td></tr>", log.dest_path));
                report.push_str(&format!("<tr><th>Format</th><td>{}</td></tr>", log.format));
                report.push_str(&format!("<tr><th>Hashes</th><td><pre>{}</pre></td></tr>", log.hash_log));
                report.push_str("</table>");
            }
        }
    }
    
    report.push_str("</body></html>");

    std::fs::write(&export_path, report).map_err(|e| format!("Failed to write report: {}", e))?;
    
    Ok(())
}
