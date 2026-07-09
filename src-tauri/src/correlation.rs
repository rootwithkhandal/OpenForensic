use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    Unchanged,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileDiffItem {
    pub path: String,
    pub change_type: ChangeType,
    pub baseline_hash: Option<String>,
    pub incident_hash: Option<String>,
    pub file_size_diff: i64,
    pub details: String,
    pub risk_level: String, // "High", "Medium", "Low", "Info"
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppDiffItem {
    pub app_name: String,
    pub app_type: String, // "Desktop/System App", "Android Package", "Browser Extension", "IM App"
    pub change_type: ChangeType,
    pub baseline_version: Option<String>,
    pub incident_version: Option<String>,
    pub details: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfigDiffItem {
    pub category: String, // "Process", "Network Connection", "Autostart/Persistence", "Registry/Config"
    pub item_key: String,
    pub change_type: ChangeType,
    pub baseline_value: Option<String>,
    pub incident_value: Option<String>,
    pub details: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationSummary {
    pub baseline_source: String,
    pub incident_source: String,
    pub files_added: usize,
    pub files_modified: usize,
    pub files_deleted: usize,
    pub apps_added: usize,
    pub apps_modified: usize,
    pub apps_deleted: usize,
    pub config_changes: usize,
    pub high_risk_anomalies: usize,
    pub correlation_timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationReport {
    pub summary: CorrelationSummary,
    pub file_diffs: Vec<FileDiffItem>,
    pub app_diffs: Vec<AppDiffItem>,
    pub config_diffs: Vec<ConfigDiffItem>,
}

/// Helper to compute SHA-256 hex string for a file
fn compute_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file {:?}: {}", path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("Read error on {:?}: {}", path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Helper to determine file risk based on extension or location
fn determine_file_risk(path: &str, change: &ChangeType) -> String {
    let lower = path.to_lowercase();
    if *change == ChangeType::Added || *change == ChangeType::Modified {
        if lower.contains("appdata") || lower.contains("temp") || lower.contains("/tmp") {
            if lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".ps1")
                || lower.ends_with(".vbs")
                || lower.ends_with(".bat")
                || lower.ends_with(".apk")
            {
                return "High".to_string();
            }
        }
        if lower.ends_with(".sys") || lower.ends_with(".scr") || lower.ends_with(".pif") {
            return "High".to_string();
        }
    }
    if *change == ChangeType::Deleted && (lower.contains("system32") || lower.contains("/etc/")) {
        return "Medium".to_string();
    }
    "Info".to_string()
}

/// Compare two mounted image directories (Baseline vs Incident) by recursing and diffing file hashes
pub fn compare_image_directories(
    baseline_dir: &Path,
    incident_dir: &Path,
) -> Result<CorrelationReport, String> {
    let mut baseline_files: HashMap<String, (u64, String)> = HashMap::new();
    let mut incident_files: HashMap<String, (u64, String)> = HashMap::new();

    fn scan_dir(
        root: &Path,
        current: &Path,
        map: &mut HashMap<String, (u64, String)>,
    ) {
        if let Ok(entries) = std::fs::read_dir(current) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan_dir(root, &path, map);
                } else if let Ok(meta) = path.metadata() {
                    let rel = path
                        .strip_prefix(root)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());
                    // Compute hash for files < 50MB to keep correlation swift
                    let hash = if meta.len() < 52_428_800 {
                        compute_sha256(&path).unwrap_or_default()
                    } else {
                        format!("SIZE_ONLY_{}", meta.len())
                    };
                    map.insert(rel, (meta.len(), hash));
                }
            }
        }
    }

    scan_dir(baseline_dir, baseline_dir, &mut baseline_files);
    scan_dir(incident_dir, incident_dir, &mut incident_files);

    let mut file_diffs = Vec::new();
    let all_paths: HashSet<String> = baseline_files
        .keys()
        .chain(incident_files.keys())
        .cloned()
        .collect();

    for rel_path in all_paths {
        let b_opt = baseline_files.get(&rel_path);
        let i_opt = incident_files.get(&rel_path);

        match (b_opt, i_opt) {
            (Some((b_size, b_hash)), Some((i_size, i_hash))) => {
                if b_hash != i_hash || b_size != i_size {
                    let risk = determine_file_risk(&rel_path, &ChangeType::Modified);
                    file_diffs.push(FileDiffItem {
                        path: rel_path.clone(),
                        change_type: ChangeType::Modified,
                        baseline_hash: Some(b_hash.clone()),
                        incident_hash: Some(i_hash.clone()),
                        file_size_diff: (*i_size as i64) - (*b_size as i64),
                        details: format!("Modified file content/size: {} -> {} bytes", b_size, i_size),
                        risk_level: risk,
                    });
                }
            }
            (None, Some((i_size, i_hash))) => {
                let risk = determine_file_risk(&rel_path, &ChangeType::Added);
                file_diffs.push(FileDiffItem {
                    path: rel_path.clone(),
                    change_type: ChangeType::Added,
                    baseline_hash: None,
                    incident_hash: Some(i_hash.clone()),
                    file_size_diff: *i_size as i64,
                    details: format!("New artifact introduced in incident image ({} bytes)", i_size),
                    risk_level: risk,
                });
            }
            (Some((b_size, b_hash)), None) => {
                let risk = determine_file_risk(&rel_path, &ChangeType::Deleted);
                file_diffs.push(FileDiffItem {
                    path: rel_path.clone(),
                    change_type: ChangeType::Deleted,
                    baseline_hash: Some(b_hash.clone()),
                    incident_hash: None,
                    file_size_diff: -(*b_size as i64),
                    details: "File present in baseline but wiped/removed in incident image".to_string(),
                    risk_level: risk,
                });
            }
            (None, None) => {}
        }
    }

    file_diffs.sort_by(|a, b| {
        let rank = |r: &str| match r {
            "High" => 0,
            "Medium" => 1,
            "Low" => 2,
            _ => 3,
        };
        rank(&a.risk_level).cmp(&rank(&b.risk_level))
    });

    let files_added = file_diffs.iter().filter(|d| d.change_type == ChangeType::Added).count();
    let files_modified = file_diffs.iter().filter(|d| d.change_type == ChangeType::Modified).count();
    let files_deleted = file_diffs.iter().filter(|d| d.change_type == ChangeType::Deleted).count();
    let high_risk = file_diffs.iter().filter(|d| d.risk_level == "High").count();

    let summary = CorrelationSummary {
        baseline_source: baseline_dir.to_string_lossy().to_string(),
        incident_source: incident_dir.to_string_lossy().to_string(),
        files_added,
        files_modified,
        files_deleted,
        apps_added: 0,
        apps_modified: 0,
        apps_deleted: 0,
        config_changes: 0,
        high_risk_anomalies: high_risk,
        correlation_timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(CorrelationReport {
        summary,
        file_diffs,
        app_diffs: Vec::new(),
        config_diffs: Vec::new(),
    })
}

/// Compare two SQLite Triage Databases (Baseline vs Incident)
pub fn compare_triage_databases(
    baseline_db: &Path,
    incident_db: &Path,
) -> Result<CorrelationReport, String> {
    let b_conn = Connection::open(baseline_db)
        .map_err(|e| format!("Failed to open baseline DB: {}", e))?;
    let i_conn = Connection::open(incident_db)
        .map_err(|e| format!("Failed to open incident DB: {}", e))?;

    let mut file_diffs = Vec::new();
    let mut app_diffs = Vec::new();
    let mut config_diffs = Vec::new();

    // 1. Diff Amcache / Carved / Executed Files across both databases
    let read_amcache = |conn: &Connection| -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT file_path, sha1_hash FROM amcache_entries") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0, r.1);
                }
            }
        }
        map
    };

    let b_amcache = read_amcache(&b_conn);
    let i_amcache = read_amcache(&i_conn);
    let all_files: HashSet<String> = b_amcache.keys().chain(i_amcache.keys()).cloned().collect();

    for path in all_files {
        match (b_amcache.get(&path), i_amcache.get(&path)) {
            (Some(bh), Some(ih)) if bh != ih => {
                file_diffs.push(FileDiffItem {
                    path: path.clone(),
                    change_type: ChangeType::Modified,
                    baseline_hash: Some(bh.clone()),
                    incident_hash: Some(ih.clone()),
                    file_size_diff: 0,
                    details: "Amcache binary hash mismatch between baseline and incident".to_string(),
                    risk_level: determine_file_risk(&path, &ChangeType::Modified),
                });
            }
            (None, Some(ih)) => {
                file_diffs.push(FileDiffItem {
                    path: path.clone(),
                    change_type: ChangeType::Added,
                    baseline_hash: None,
                    incident_hash: Some(ih.clone()),
                    file_size_diff: 0,
                    details: "New executable observed in Amcache post-baseline".to_string(),
                    risk_level: determine_file_risk(&path, &ChangeType::Added),
                });
            }
            (Some(bh), None) => {
                file_diffs.push(FileDiffItem {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    baseline_hash: Some(bh.clone()),
                    incident_hash: None,
                    file_size_diff: 0,
                    details: "Executable present in baseline Amcache missing from incident".to_string(),
                    risk_level: "Info".to_string(),
                });
            }
            _ => {}
        }
    }

    // 2. Diff Installed Applications & Browser Extensions / Packages
    let read_extensions = |conn: &Connection| -> HashMap<String, (String, String, String)> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT extension_id, name, version, permissions FROM browser_extensions")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0, (r.1, r.2, r.3));
                }
            }
        }
        map
    };

    let b_exts = read_extensions(&b_conn);
    let i_exts = read_extensions(&i_conn);
    let all_exts: HashSet<String> = b_exts.keys().chain(i_exts.keys()).cloned().collect();

    for id in all_exts {
        match (b_exts.get(&id), i_exts.get(&id)) {
            (None, Some((name, ver, perms))) => {
                let risk = if perms.to_lowercase().contains("all_urls")
                    || perms.to_lowercase().contains("cookies")
                    || perms.to_lowercase().contains("webRequest")
                {
                    "High"
                } else {
                    "Medium"
                };
                app_diffs.push(AppDiffItem {
                    app_name: format!("{} ({})", name, id),
                    app_type: "Browser Extension".to_string(),
                    change_type: ChangeType::Added,
                    baseline_version: None,
                    incident_version: Some(ver.clone()),
                    details: format!("New extension installed post-baseline. Permissions: {}", perms),
                    risk_level: risk.to_string(),
                });
            }
            (Some((name, bver, _)), Some((_, iver, iperms))) if bver != iver => {
                app_diffs.push(AppDiffItem {
                    app_name: format!("{} ({})", name, id),
                    app_type: "Browser Extension".to_string(),
                    change_type: ChangeType::Modified,
                    baseline_version: Some(bver.clone()),
                    incident_version: Some(iver.clone()),
                    details: format!("Extension updated/modified. Permissions: {}", iperms),
                    risk_level: "Info".to_string(),
                });
            }
            (Some((name, bver, _)), None) => {
                app_diffs.push(AppDiffItem {
                    app_name: format!("{} ({})", name, id),
                    app_type: "Browser Extension".to_string(),
                    change_type: ChangeType::Deleted,
                    baseline_version: Some(bver.clone()),
                    incident_version: None,
                    details: "Extension present in baseline removed post-incident".to_string(),
                    risk_level: "Info".to_string(),
                });
            }
            _ => {}
        }
    }

    // Read IM Apps / Packages
    let read_im_apps = |conn: &Connection| -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT app_name, app_type FROM im_apps") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0, r.1);
                }
            }
        }
        map
    };

    let b_im = read_im_apps(&b_conn);
    let i_im = read_im_apps(&i_conn);
    for (app_name, app_type) in &i_im {
        if !b_im.contains_key(app_name) {
            app_diffs.push(AppDiffItem {
                app_name: app_name.clone(),
                app_type: app_type.clone(),
                change_type: ChangeType::Added,
                baseline_version: None,
                incident_version: Some("Installed".to_string()),
                details: "Messaging/Communication application detected in incident image only".to_string(),
                risk_level: "Medium".to_string(),
            });
        }
    }

    // 3. Diff Config / Processes / Network State
    let read_processes = |conn: &Connection| -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT name, executable_path FROM processes") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0, r.1);
                }
            }
        }
        map
    };

    let b_procs = read_processes(&b_conn);
    let i_procs = read_processes(&i_conn);
    for (name, path) in &i_procs {
        if !b_procs.contains_key(name) {
            let lower = path.to_lowercase();
            let risk = if lower.contains("temp") || lower.contains("appdata") || lower.contains("public") {
                "High"
            } else {
                "Medium"
            };
            config_diffs.push(ConfigDiffItem {
                category: "Process".to_string(),
                item_key: name.clone(),
                change_type: ChangeType::Added,
                baseline_value: None,
                incident_value: Some(path.clone()),
                details: format!("New running process detected in incident snapshot: {}", path),
                risk_level: risk.to_string(),
            });
        }
    }

    let files_added = file_diffs.iter().filter(|d| d.change_type == ChangeType::Added).count();
    let files_modified = file_diffs.iter().filter(|d| d.change_type == ChangeType::Modified).count();
    let files_deleted = file_diffs.iter().filter(|d| d.change_type == ChangeType::Deleted).count();
    let apps_added = app_diffs.iter().filter(|d| d.change_type == ChangeType::Added).count();
    let apps_modified = app_diffs.iter().filter(|d| d.change_type == ChangeType::Modified).count();
    let apps_deleted = app_diffs.iter().filter(|d| d.change_type == ChangeType::Deleted).count();
    let config_changes = config_diffs.len();

    let high_risk = file_diffs.iter().filter(|d| d.risk_level == "High").count()
        + app_diffs.iter().filter(|d| d.risk_level == "High").count()
        + config_diffs.iter().filter(|d| d.risk_level == "High").count();

    let summary = CorrelationSummary {
        baseline_source: baseline_db.to_string_lossy().to_string(),
        incident_source: incident_db.to_string_lossy().to_string(),
        files_added,
        files_modified,
        files_deleted,
        apps_added,
        apps_modified,
        apps_deleted,
        config_changes,
        high_risk_anomalies: high_risk,
        correlation_timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(CorrelationReport {
        summary,
        file_diffs,
        app_diffs,
        config_diffs,
    })
}

/// Save correlation report findings into SQLite triage database
pub fn save_correlation_report_to_db(
    conn: &Connection,
    report: &CorrelationReport,
) -> Result<usize, String> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS image_correlation_results (
            id INTEGER PRIMARY KEY,
            baseline_source TEXT,
            incident_source TEXT,
            category TEXT,
            change_type TEXT,
            item_name TEXT,
            item_path TEXT,
            baseline_hash_or_state TEXT,
            incident_hash_or_state TEXT,
            risk_level TEXT,
            details TEXT,
            correlation_timestamp TEXT
        )",
        [],
    )
    .map_err(|e| format!("Failed to create table image_correlation_results: {}", e))?;

    let mut saved = 0usize;
    for file in &report.file_diffs {
        conn.execute(
            "INSERT INTO image_correlation_results (
                baseline_source, incident_source, category, change_type, item_name, item_path,
                baseline_hash_or_state, incident_hash_or_state, risk_level, details, correlation_timestamp
            ) VALUES (?1, ?2, 'File', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                report.summary.baseline_source,
                report.summary.incident_source,
                format!("{:?}", file.change_type),
                Path::new(&file.path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file.path.clone()),
                file.path,
                file.baseline_hash.as_deref().unwrap_or("-"),
                file.incident_hash.as_deref().unwrap_or("-"),
                file.risk_level,
                file.details,
                report.summary.correlation_timestamp,
            ],
        )
        .map_err(|e| format!("Insert error: {}", e))?;
        saved += 1;
    }

    for app in &report.app_diffs {
        conn.execute(
            "INSERT INTO image_correlation_results (
                baseline_source, incident_source, category, change_type, item_name, item_path,
                baseline_hash_or_state, incident_hash_or_state, risk_level, details, correlation_timestamp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                report.summary.baseline_source,
                report.summary.incident_source,
                app.app_type,
                format!("{:?}", app.change_type),
                app.app_name,
                app.app_name,
                app.baseline_version.as_deref().unwrap_or("-"),
                app.incident_version.as_deref().unwrap_or("-"),
                app.risk_level,
                app.details,
                report.summary.correlation_timestamp,
            ],
        )
        .map_err(|e| format!("Insert error: {}", e))?;
        saved += 1;
    }

    for cfg in &report.config_diffs {
        conn.execute(
            "INSERT INTO image_correlation_results (
                baseline_source, incident_source, category, change_type, item_name, item_path,
                baseline_hash_or_state, incident_hash_or_state, risk_level, details, correlation_timestamp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                report.summary.baseline_source,
                report.summary.incident_source,
                cfg.category,
                format!("{:?}", cfg.change_type),
                cfg.item_key,
                cfg.item_key,
                cfg.baseline_value.as_deref().unwrap_or("-"),
                cfg.incident_value.as_deref().unwrap_or("-"),
                cfg.risk_level,
                cfg.details,
                report.summary.correlation_timestamp,
            ],
        )
        .map_err(|e| format!("Insert error: {}", e))?;
        saved += 1;
    }

    Ok(saved)
}

/// Generate structured Markdown/HTML report for IR Triage
pub fn generate_markdown_report(report: &CorrelationReport) -> String {
    let mut md = String::new();
    md.push_str("# OpenForensic Multi-Image Correlation Report\n");
    md.push_str("## Baseline vs Incident Forensic Comparison\n\n");

    md.push_str("### Executive Summary\n");
    md.push_str(&format!("- **Baseline Image/DB**: `{}`\n", report.summary.baseline_source));
    md.push_str(&format!("- **Incident Image/DB**: `{}`\n", report.summary.incident_source));
    md.push_str(&format!("- **Correlation Timestamp**: `{}`\n", report.summary.correlation_timestamp));
    md.push_str(&format!("- **High-Risk Anomalies Detected**: **{}**\n\n", report.summary.high_risk_anomalies));

    md.push_str("| Category | Added | Modified | Deleted | Total Deltas |\n");
    md.push_str("|---|:---:|:---:|:---:|:---:|\n");
    md.push_str(&format!(
        "| **Files & Hashes** | {} | {} | {} | {} |\n",
        report.summary.files_added,
        report.summary.files_modified,
        report.summary.files_deleted,
        report.summary.files_added + report.summary.files_modified + report.summary.files_deleted
    ));
    md.push_str(&format!(
        "| **Installed Apps / Extensions** | {} | {} | {} | {} |\n",
        report.summary.apps_added,
        report.summary.apps_modified,
        report.summary.apps_deleted,
        report.summary.apps_added + report.summary.apps_modified + report.summary.apps_deleted
    ));
    md.push_str(&format!(
        "| **Config & Persistence State** | {} | 0 | 0 | {} |\n\n",
        report.summary.config_changes, report.summary.config_changes
    ));

    if !report.file_diffs.is_empty() {
        md.push_str("### File Hashes & Binary Changes\n");
        md.push_str("| Risk | Change | File Path | Baseline Hash -> Incident Hash | Details |\n");
        md.push_str("|:---:|:---:|---|---|---|\n");
        for f in &report.file_diffs {
            let risk_badge = match f.risk_level.as_str() {
                "High" => "🔴 HIGH",
                "Medium" => "🟡 MEDIUM",
                _ => "🟢 INFO",
            };
            let b = f.baseline_hash.as_deref().unwrap_or("None");
            let i = f.incident_hash.as_deref().unwrap_or("None");
            md.push_str(&format!(
                "| {} | {:?} | `{}` | `{} -> {}` | {} |\n",
                risk_badge, f.change_type, f.path, b, i, f.details
            ));
        }
        md.push('\n');
    }

    if !report.app_diffs.is_empty() {
        md.push_str("### Installed Applications & Packages\n");
        md.push_str("| Risk | Change | Type | Package / App Name | Version Delta | Details |\n");
        md.push_str("|:---:|:---:|---|---|---|---|\n");
        for a in &report.app_diffs {
            let risk_badge = match a.risk_level.as_str() {
                "High" => "🔴 HIGH",
                "Medium" => "🟡 MEDIUM",
                _ => "🟢 INFO",
            };
            md.push_str(&format!(
                "| {} | {:?} | {} | **{}** | `{} -> {}` | {} |\n",
                risk_badge,
                a.change_type,
                a.app_type,
                a.app_name,
                a.baseline_version.as_deref().unwrap_or("-"),
                a.incident_version.as_deref().unwrap_or("-"),
                a.details
            ));
        }
        md.push('\n');
    }

    if !report.config_diffs.is_empty() {
        md.push_str("### Registry, Config & Process Changes\n");
        md.push_str("| Risk | Change | Category | Item / Process | Incident Value | Details |\n");
        md.push_str("|:---:|:---:|---|---|---|---|\n");
        for c in &report.config_diffs {
            let risk_badge = match c.risk_level.as_str() {
                "High" => "🔴 HIGH",
                "Medium" => "🟡 MEDIUM",
                _ => "🟢 INFO",
            };
            md.push_str(&format!(
                "| {} | {:?} | {} | **{}** | `{}` | {} |\n",
                risk_badge,
                c.change_type,
                c.category,
                c.item_key,
                c.incident_value.as_deref().unwrap_or("-"),
                c.details
            ));
        }
        md.push('\n');
    }

    md
}
