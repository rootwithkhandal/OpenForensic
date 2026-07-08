use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};
use sha2::Digest;

#[derive(Serialize, Deserialize, Debug)]
pub struct Case {
    pub id: i64,
    pub case_number: String,
    pub examiner_name: String,
    pub notes: String,
    #[serde(default)]
    pub case_root: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FolderInfo {
    pub name: String,
    pub path: String,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CaseFolderTree {
    pub case_root: String,
    pub manifest_path: String,
    pub db_path: String,
    pub folders: Vec<FolderInfo>,
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
            case_root TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).map_err(|e| e.to_string())?;

    let _ = conn.execute("ALTER TABLE cases ADD COLUMN case_root TEXT DEFAULT ''", []);

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
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            entry_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
        )",
        [],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AuditChainVerificationReport {
    pub is_valid: bool,
    pub total_records: usize,
    pub broken_record_id: Option<i64>,
    pub message: String,
}

pub fn verify_audit_log_chain(app: &AppHandle) -> Result<AuditChainVerificationReport, String> {
    let db_path = get_db_path(app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let _ = conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'", []);
    let _ = conn.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'", []);

    let mut stmt = conn.prepare("SELECT id, investigator, case_id, event_type, details, prev_hash, entry_hash FROM audit_logs ORDER BY id ASC").map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;

    let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut total_records = 0;

    while let Ok(Some(row)) = rows.next() {
        total_records += 1;
        let id: i64 = row.get(0).unwrap_or(0);
        let investigator: String = row.get(1).unwrap_or_default();
        let case_id: String = row.get(2).unwrap_or_default();
        let event_type: String = row.get(3).unwrap_or_default();
        let details: String = row.get(4).unwrap_or_default();
        let prev_hash: String = row.get(5).unwrap_or_default();
        let entry_hash: String = row.get(6).unwrap_or_default();

        if prev_hash != expected_prev {
            return Ok(AuditChainVerificationReport {
                is_valid: false,
                total_records,
                broken_record_id: Some(id),
                message: format!("CHAIN-OF-CUSTODY VIOLATION: Record ID {} has an invalid prev_hash! Expected: {}, Found: {}", id, expected_prev, prev_hash),
            });
        }

        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, prev_hash.as_bytes());
        sha2::Digest::update(&mut hasher, investigator.as_bytes());
        sha2::Digest::update(&mut hasher, case_id.as_bytes());
        sha2::Digest::update(&mut hasher, event_type.as_bytes());
        sha2::Digest::update(&mut hasher, details.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());

        if entry_hash != computed_hash {
            return Ok(AuditChainVerificationReport {
                is_valid: false,
                total_records,
                broken_record_id: Some(id),
                message: format!("TAMPER VIOLATION: Record ID {} entry_hash mismatch! Data was modified after insertion (Expected: {}, Found: {})", id, computed_hash, entry_hash),
            });
        }

        expected_prev = entry_hash;
    }

    Ok(AuditChainVerificationReport {
        is_valid: true,
        total_records,
        broken_record_id: None,
        message: format!("CHAIN-OF-CUSTODY INTACT: All {} audit records cryptographically verified via SHA-256 hash chaining.", total_records),
    })
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

    let _ = conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'", []);
    let _ = conn.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'", []);

    let prev_hash: String = conn.query_row(
        "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, prev_hash.as_bytes());
    sha2::Digest::update(&mut hasher, investigator.as_bytes());
    sha2::Digest::update(&mut hasher, case_id.as_bytes());
    sha2::Digest::update(&mut hasher, event_type.as_bytes());
    sha2::Digest::update(&mut hasher, details.as_bytes());
    let entry_hash = hex::encode(hasher.finalize());

    conn.execute(
        "INSERT INTO audit_logs (investigator, case_id, event_type, details, prev_hash, entry_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![investigator, case_id, event_type, details, prev_hash, entry_hash],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn create_case_folder_structure(
    case_root: &std::path::Path,
    case_number: &str,
    case_name: &str,
    examiner: &str,
    notes: &str,
) -> std::result::Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(case_root).map_err(|e| format!("Failed to create case root directory: {}", e))?;

    let folders = ["Cache", "Export", "Log", "ModuleOutput", "Reports"];
    for folder in &folders {
        let mut p = case_root.to_path_buf();
        p.push(folder);
        std::fs::create_dir_all(&p).map_err(|e| format!("Failed to create folder {}: {}", folder, e))?;
    }

    // Generate manifest (.ofc file)
    let manifest = serde_json::json!({
        "case_number": case_number,
        "case_name": case_name,
        "examiner": examiner,
        "notes": notes,
        "created_at": chrono::Local::now().to_rfc3339(),
        "version": "2.1.0",
        "schema": "1.0",
        "directories": folders
    });
    let mut manifest_path = case_root.to_path_buf();
    manifest_path.push(format!("{}.ofc", case_number.replace(' ', "_")));
    if let Ok(content) = serde_json::to_string_pretty(&manifest) {
        let _ = std::fs::write(&manifest_path, content);
    }

    // Initialize per-case portable SQLite database
    let mut db_path = case_root.to_path_buf();
    db_path.push("openforensic.db");
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open per-case SQLite database: {}", e))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS evidence_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_tag TEXT NOT NULL,
            source_path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            entry_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
        )",
        [],
    ).map_err(|e| e.to_string())?;

    Ok((manifest_path, db_path))
}

pub fn get_case_subfolder_path(app: &AppHandle, case_id: i64, subfolder: &str) -> std::result::Result<PathBuf, String> {
    let details = get_case_details(app.clone(), case_id)?;
    if details.case.case_root.is_empty() {
        return Err("Case has no unified folder structure assigned.".to_string());
    }
    let p = std::path::Path::new(&details.case.case_root).join(subfolder);
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(p)
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
    let (case_id, case_root): (i64, String) = match conn.query_row(
        "SELECT id, case_root FROM cases WHERE case_number = ?1",
        params![case_number],
        |row| Ok((row.get(0)?, row.get::<_, Option<String>>(1)?.unwrap_or_default())),
    ) {
        Ok(res) => res,
        Err(_) => {
            conn.execute(
                "INSERT INTO cases (case_number, examiner_name, notes, case_root) VALUES (?1, ?2, ?3, '')",
                params![case_number, examiner_name, notes],
            ).map_err(|e| e.to_string())?;
            (conn.last_insert_rowid(), "".to_string())
        }
    };

    // Create or get evidence item in global db
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

    // Log acquisition in global db
    conn.execute(
        "INSERT INTO acquisition_logs (evidence_id, dest_path, format, hash_log, status) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![evidence_id, dest_path, format, hash_log, status],
    ).map_err(|e| e.to_string())?;

    // Also sync to per-case portable DB if case_root is set
    if !case_root.is_empty() {
        let p = std::path::Path::new(&case_root).join("openforensic.db");
        if let Ok(pconn) = Connection::open(&p) {
            let _ = pconn.execute(
                "CREATE TABLE IF NOT EXISTS evidence_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    evidence_tag TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            );
            let _ = pconn.execute(
                "CREATE TABLE IF NOT EXISTS acquisition_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL,
                    dest_path TEXT NOT NULL,
                    format TEXT NOT NULL,
                    hash_log TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            );
            let p_evidence_id: i64 = match pconn.query_row(
                "SELECT id FROM evidence_items WHERE case_id = ?1 AND evidence_tag = ?2",
                params![case_id, evidence_tag],
                |row| row.get(0),
            ) {
                Ok(id) => id,
                Err(_) => {
                    let _ = pconn.execute(
                        "INSERT INTO evidence_items (case_id, evidence_tag, source_path) VALUES (?1, ?2, ?3)",
                        params![case_id, evidence_tag, source_path],
                    );
                    pconn.last_insert_rowid()
                }
            };
            let _ = pconn.execute(
                "INSERT INTO acquisition_logs (evidence_id, dest_path, format, hash_log, status) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![p_evidence_id, dest_path, format, hash_log, status],
            );
        }
    }

    Ok(())
}

#[tauri::command]
pub fn get_cases(app: AppHandle) -> Result<Vec<Case>, String> {
    let db_path = get_db_path(&app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let mut stmt = conn.prepare("SELECT id, case_number, examiner_name, notes, case_root, created_at FROM cases ORDER BY created_at DESC").map_err(|e| e.to_string())?;
    let cases = stmt.query_map([], |row| {
        Ok(Case {
            id: row.get(0)?,
            case_number: row.get(1)?,
            examiner_name: row.get(2)?,
            notes: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            case_root: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            created_at: row.get(5)?,
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
        "SELECT id, case_number, examiner_name, notes, case_root, created_at FROM cases WHERE id = ?1",
        params![case_id],
        |row| {
            Ok(Case {
                id: row.get(0)?,
                case_number: row.get(1)?,
                examiner_name: row.get(2)?,
                notes: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                case_root: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                created_at: row.get(5)?,
            })
        },
    ).map_err(|e| e.to_string())?;

    // Check if we have a portable DB inside case_root
    let portable_conn = if !case.case_root.is_empty() {
        let p = std::path::Path::new(&case.case_root).join("openforensic.db");
        if p.exists() {
            Connection::open(&p).ok()
        } else {
            None
        }
    } else {
        None
    };
    let query_conn = portable_conn.as_ref().unwrap_or(&conn);

    let mut evidence_stmt = query_conn.prepare("SELECT id, case_id, evidence_tag, source_path, created_at FROM evidence_items WHERE case_id = ?1").map_err(|e| e.to_string())?;
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
    let mut log_stmt = query_conn.prepare("SELECT id, evidence_id, dest_path, format, hash_log, status, timestamp FROM acquisition_logs WHERE evidence_id = ?1").map_err(|e| e.to_string())?;
    
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
    if !details.case.case_root.is_empty() {
        report.push_str(&format!("<tr><th>Unified Case Folder</th><td>{}</td></tr>", details.case.case_root));
    }
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

    if !export_path.is_empty() {
        std::fs::write(&export_path, &report).map_err(|e| format!("Failed to write report: {}", e))?;
    }

    // Always save a copy to the unified case Reports/ folder if available!
    if !details.case.case_root.is_empty() {
        let reports_dir = std::path::Path::new(&details.case.case_root).join("Reports");
        let _ = std::fs::create_dir_all(&reports_dir);
        let auto_path = reports_dir.join(format!("{}_report.html", details.case.case_number.replace(' ', "_")));
        let _ = std::fs::write(&auto_path, &report);
    }
    
    Ok(())
}

fn calculate_dir_metrics(path: &std::path::Path) -> (usize, u64) {
    let mut count = 0;
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    let (c, s) = calculate_dir_metrics(&entry.path());
                    count += c;
                    size += s;
                } else if metadata.is_file() {
                    count += 1;
                    size += metadata.len();
                }
            }
        }
    }
    (count, size)
}

#[tauri::command]
pub fn create_case_container(
    app: AppHandle,
    case_number: String,
    case_name: String,
    examiner_name: String,
    notes: String,
    root_path: String,
) -> Result<i64, String> {
    let db_path = get_db_path(&app)?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let case_root_path = std::path::Path::new(&root_path).join(&case_number.replace(' ', "_"));
    let case_root_str = case_root_path.to_string_lossy().to_string();

    let _ = create_case_folder_structure(&case_root_path, &case_number, &case_name, &examiner_name, &notes)?;

    let case_id: i64 = match conn.query_row(
        "SELECT id FROM cases WHERE case_number = ?1",
        params![case_number],
        |row| row.get(0),
    ) {
        Ok(id) => {
            conn.execute(
                "UPDATE cases SET examiner_name = ?1, notes = ?2, case_root = ?3 WHERE id = ?4",
                params![examiner_name, notes, case_root_str, id],
            ).map_err(|e| e.to_string())?;
            id
        }
        Err(_) => {
            conn.execute(
                "INSERT INTO cases (case_number, examiner_name, notes, case_root) VALUES (?1, ?2, ?3, ?4)",
                params![case_number, examiner_name, notes, case_root_str],
            ).map_err(|e| e.to_string())?;
            conn.last_insert_rowid()
        }
    };

    let _ = log_audit_event(&app, &examiner_name, &case_id.to_string(), "CASE_CREATED", &format!("Created unified case folder structure at {}", case_root_str));

    Ok(case_id)
}

#[tauri::command]
pub fn get_case_folder_structure(app: AppHandle, case_id: i64) -> Result<CaseFolderTree, String> {
    let details = get_case_details(app, case_id)?;
    if details.case.case_root.is_empty() {
        return Err("This case does not have a unified folder structure assigned.".to_string());
    }
    let root = std::path::Path::new(&details.case.case_root);
    if !root.exists() {
        return Err(format!("Case root directory {} does not exist on disk.", details.case.case_root));
    }

    let folders = ["Cache", "Export", "Log", "ModuleOutput", "Reports"];
    let mut folder_infos = Vec::new();
    for folder in &folders {
        let p = root.join(folder);
        let (file_count, total_size_bytes) = calculate_dir_metrics(&p);
        folder_infos.push(FolderInfo {
            name: folder.to_string(),
            path: p.to_string_lossy().to_string(),
            file_count,
            total_size_bytes,
        });
    }

    let mut manifest_path = root.join(format!("{}.ofc", details.case.case_number.replace(' ', "_")));
    if !manifest_path.exists() {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "ofc" {
                        manifest_path = entry.path();
                        break;
                    }
                }
            }
        }
    }
    let db_path = root.join("openforensic.db");

    Ok(CaseFolderTree {
        case_root: details.case.case_root.clone(),
        manifest_path: manifest_path.to_string_lossy().to_string(),
        db_path: db_path.to_string_lossy().to_string(),
        folders: folder_infos,
    })
}

#[tauri::command]
pub fn get_case_export_path(app: AppHandle, case_id: i64, filename: String, subfolder: String) -> Result<String, String> {
    let folder = if subfolder.is_empty() { "Export" } else { &subfolder };
    let dir = get_case_subfolder_path(&app, case_id, folder)?;
    Ok(dir.join(filename).to_string_lossy().to_string())
}

#[tauri::command]
pub async fn verify_case_audit_chain(app: AppHandle) -> Result<AuditChainVerificationReport, String> {
    verify_audit_log_chain(&app)
}
