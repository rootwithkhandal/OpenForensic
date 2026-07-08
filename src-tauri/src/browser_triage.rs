//! Cross-Platform Browser Forensics & Triage Module
//!
//! Scans physical systems (Windows, macOS, Linux) or mounted disk images for all installed web browsers
//! and browser profiles (Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, Opera, Vivaldi, Safari,
//! Tor Browser, Arc, LibreWolf, Waterfox, and Chromium).
//!
//! Copies browser history databases (`History`, `places.sqlite`, `History.db`) and parses visited URLs,
//! titles, visit timestamps, and visit counts into the SQLite triage database (`browser_history` and
//! `installed_browsers` tables).

use rusqlite::Connection;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;
use crate::acquisition::ProgressEvent;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstalledBrowser {
    pub browser_name: String,
    pub engine: String,
    pub user_name: String,
    pub profile_name: String,
    pub history_path: String,
    pub history_count: usize,
    pub status: String,
}

struct BrowserDef {
    name: &'static str,
    engine: &'static str,
    win_paths: &'static [&'static str],
    mac_paths: &'static [&'static str],
    linux_paths: &'static [&'static str],
    db_file: &'static str,
}

const BROWSER_DEFS: &[BrowserDef] = &[
    BrowserDef {
        name: "Google Chrome",
        engine: "Chromium",
        win_paths: &["AppData/Local/Google/Chrome/User Data"],
        mac_paths: &["Library/Application Support/Google/Chrome"],
        linux_paths: &[".config/google-chrome"],
        db_file: "History",
    },
    BrowserDef {
        name: "Microsoft Edge",
        engine: "Chromium",
        win_paths: &["AppData/Local/Microsoft/Edge/User Data"],
        mac_paths: &["Library/Application Support/Microsoft Edge"],
        linux_paths: &[".config/microsoft-edge"],
        db_file: "History",
    },
    BrowserDef {
        name: "Mozilla Firefox",
        engine: "Gecko",
        win_paths: &["AppData/Roaming/Mozilla/Firefox/Profiles"],
        mac_paths: &["Library/Application Support/Firefox/Profiles"],
        linux_paths: &[".mozilla/firefox", "snap/firefox/common/.mozilla/firefox"],
        db_file: "places.sqlite",
    },
    BrowserDef {
        name: "Brave Browser",
        engine: "Chromium",
        win_paths: &["AppData/Local/BraveSoftware/Brave-Browser/User Data"],
        mac_paths: &["Library/Application Support/BraveSoftware/Brave-Browser"],
        linux_paths: &[".config/BraveSoftware/Brave-Browser"],
        db_file: "History",
    },
    BrowserDef {
        name: "Opera Stable",
        engine: "Chromium",
        win_paths: &["AppData/Roaming/Opera Software/Opera Stable"],
        mac_paths: &["Library/Application Support/com.operasoftware.Opera"],
        linux_paths: &[".config/opera"],
        db_file: "History",
    },
    BrowserDef {
        name: "Opera GX",
        engine: "Chromium",
        win_paths: &["AppData/Roaming/Opera Software/Opera GX Stable"],
        mac_paths: &["Library/Application Support/com.operasoftware.OperaGX"],
        linux_paths: &[".config/opera-gx"],
        db_file: "History",
    },
    BrowserDef {
        name: "Vivaldi",
        engine: "Chromium",
        win_paths: &["AppData/Local/Vivaldi/User Data"],
        mac_paths: &["Library/Application Support/Vivaldi"],
        linux_paths: &[".config/vivaldi"],
        db_file: "History",
    },
    BrowserDef {
        name: "Chromium",
        engine: "Chromium",
        win_paths: &["AppData/Local/Chromium/User Data"],
        mac_paths: &["Library/Application Support/Chromium"],
        linux_paths: &[".config/chromium", "snap/chromium/common/.config/chromium"],
        db_file: "History",
    },
    BrowserDef {
        name: "Arc Browser",
        engine: "Chromium",
        win_paths: &["AppData/Local/The Browser Company/Arc/User Data"],
        mac_paths: &["Library/Application Support/Arc/User Data"],
        linux_paths: &[".config/arc"],
        db_file: "History",
    },
    BrowserDef {
        name: "Apple Safari",
        engine: "WebKit",
        win_paths: &[],
        mac_paths: &["Library/Safari"],
        linux_paths: &[],
        db_file: "History.db",
    },
    BrowserDef {
        name: "Tor Browser",
        engine: "Gecko",
        win_paths: &[
            "Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default",
            "AppData/Roaming/TorBrowser-Data/Browser/profile.default",
        ],
        mac_paths: &["Library/Application Support/TorBrowser-Data/Browser/profile.default"],
        linux_paths: &[".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser/profile.default"],
        db_file: "places.sqlite",
    },
    BrowserDef {
        name: "LibreWolf",
        engine: "Gecko",
        win_paths: &["AppData/Roaming/librewolf/Profiles"],
        mac_paths: &["Library/Application Support/librewolf/Profiles"],
        linux_paths: &[".librewolf"],
        db_file: "places.sqlite",
    },
    BrowserDef {
        name: "Waterfox",
        engine: "Gecko",
        win_paths: &["AppData/Roaming/Waterfox/Profiles"],
        mac_paths: &["Library/Application Support/Waterfox/Profiles"],
        linux_paths: &[".waterfox"],
        db_file: "places.sqlite",
    },
];

pub async fn run_browser_triage(
    dest_dir: &Path,
    root_path: &Path,
    is_mounted_target: bool,
    progress_tx: Sender<ProgressEvent>,
) -> Result<Vec<InstalledBrowser>, String> {
    let _ = progress_tx
        .send(ProgressEvent::Log(
            "[TRIAGE] Enumerating user profiles across Windows, macOS, and Linux for web browser artifacts...".to_string(),
        ))
        .await;

    let user_dirs = enumerate_user_dirs(root_path, is_mounted_target);
    let mut found_browsers: Vec<InstalledBrowser> = Vec::new();
    let browser_out_dir = dest_dir.join("browsers");
    let _ = fs::create_dir_all(&browser_out_dir);

    for (user_path, user_name) in &user_dirs {
        for bdef in BROWSER_DEFS {
            let paths_to_check = if is_mounted_target {
                if user_path.join("AppData").exists() {
                    bdef.win_paths
                } else if user_path.join("Library").exists() {
                    bdef.mac_paths
                } else {
                    bdef.linux_paths
                }
            } else if cfg!(target_os = "windows") {
                bdef.win_paths
            } else if cfg!(target_os = "macos") {
                bdef.mac_paths
            } else {
                bdef.linux_paths
            };

            for rel_path in paths_to_check {
                let base_dir = user_path.join(rel_path);
                if !base_dir.exists() {
                    continue;
                }

                let mut candidate_dbs: Vec<(PathBuf, String)> = Vec::new();

                let direct_db = base_dir.join(bdef.db_file);
                if direct_db.exists() && direct_db.is_file() {
                    candidate_dbs.push((direct_db, "Default/Primary".to_string()));
                }

                if base_dir.is_dir() {
                    if let Ok(entries) = fs::read_dir(&base_dir) {
                        for entry in entries.flatten() {
                            let sub = entry.path();
                            if sub.is_dir() {
                                let sub_db = sub.join(bdef.db_file);
                                if sub_db.exists() && sub_db.is_file() {
                                    let prof_name = sub.file_name().unwrap_or_default().to_string_lossy().to_string();
                                    if !candidate_dbs.iter().any(|(p, _)| p == &sub_db) {
                                        candidate_dbs.push((sub_db, prof_name));
                                    }
                                }
                            }
                        }
                    }
                }

                for (db_path, profile_name) in candidate_dbs {
                    let _ = progress_tx
                        .send(ProgressEvent::Log(format!(
                            "[TRIAGE] Detected {} [{}] for user '{}' at: {}",
                            bdef.name, profile_name, user_name, db_path.display()
                        )))
                        .await;

                    let safe_browser_name = bdef.name.replace(' ', "_").to_lowercase();
                    let safe_profile_name = profile_name.replace(' ', "_").replace('.', "_").to_lowercase();
                    let dest_filename = format!("{}_{}_{}_{}.sqlite", safe_browser_name, user_name, safe_profile_name, bdef.engine.to_lowercase());
                    let copied_db_path = browser_out_dir.join(&dest_filename);

                    let count = 0;
                    let mut status = "Locked / Unreadable".to_string();

                    if fs::copy(&db_path, &copied_db_path).is_ok() {
                        status = "Copied / Ready for Parsing".to_string();
                    } else {
                        let _ = progress_tx
                            .send(ProgressEvent::Log(format!(
                                "[TRIAGE] WARNING: Could not copy browser database {}. File may be locked by active browser.",
                                db_path.display()
                            )))
                            .await;
                    }

                    found_browsers.push(InstalledBrowser {
                        browser_name: bdef.name.to_string(),
                        engine: bdef.engine.to_string(),
                        user_name: user_name.clone(),
                        profile_name: profile_name.clone(),
                        history_path: copied_db_path.display().to_string(),
                        history_count: count,
                        status,
                    });
                }
            }
        }
    }

    let _ = progress_tx
        .send(ProgressEvent::Log(format!(
            "[TRIAGE] Completed cross-platform browser triage. Found {} browser profile instance(s).",
            found_browsers.len()
        )))
        .await;

    write_browser_report(&browser_out_dir, &found_browsers);

    Ok(found_browsers)
}

fn enumerate_user_dirs(root_path: &Path, is_mounted_target: bool) -> Vec<(PathBuf, String)> {
    let mut user_dirs = Vec::new();

    if is_mounted_target {
        let users_path = root_path.join("Users");
        if users_path.exists() {
            if let Ok(entries) = fs::read_dir(&users_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                        if !is_ignored_user(&name) {
                            user_dirs.push((path, name));
                        }
                    }
                }
            }
        } else {
            let home_path = root_path.join("home");
            if let Ok(entries) = fs::read_dir(&home_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                        user_dirs.push((path, name));
                    }
                }
            }
        }
    } else if cfg!(target_os = "windows") {
        let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let users_path = PathBuf::from(format!("{}\\Users", sys_drive));
        if let Ok(entries) = fs::read_dir(&users_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    if !is_ignored_user(&name) {
                        user_dirs.push((path, name));
                    }
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        let users_path = PathBuf::from("/Users");
        if let Ok(entries) = fs::read_dir(&users_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    if !is_ignored_user(&name) {
                        user_dirs.push((path, name));
                    }
                }
            }
        }
    } else {
        // Linux / Unix
        let home_path = PathBuf::from("/home");
        if let Ok(entries) = fs::read_dir(&home_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    user_dirs.push((path, name));
                }
            }
        }
        let root_dir = PathBuf::from("/root");
        if root_dir.exists() {
            user_dirs.push((root_dir, "root".to_string()));
        }
        if user_dirs.is_empty() {
            let home_dir = PathBuf::from(std::env::var("HOME").unwrap_or_default());
            let name = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
            if home_dir.exists() {
                user_dirs.push((home_dir, name));
            }
        }
    }
    user_dirs
}

fn is_ignored_user(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "public" | "default" | "default user" | "all users" | "desktop.ini" | "defaultapppool" | "shared"
    )
}

fn parse_history_db(db_path: &Path, browser_label: &str, triage_db: &Connection) -> usize {
    let mut count = 0;
    if let Ok(hist_db) = Connection::open(db_path) {
        // 1. Try Chromium schema (urls table)
        if let Ok(mut stmt) = hist_db.prepare("SELECT url, COALESCE(title, ''), COALESCE(visit_count, 1), COALESCE(last_visit_time, 0) FROM urls WHERE url IS NOT NULL") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            }) {
                for row in rows.flatten() {
                    let (url, title, vcount, time) = row;
                    let _ = triage_db.execute(
                        "INSERT INTO browser_history (browser_name, url, title, visit_time, visit_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![browser_label, url, title, time.to_string(), vcount],
                    );
                    count += 1;
                }
                return count;
            }
        }

        // 2. Try Gecko / Firefox schema (moz_places table)
        if let Ok(mut stmt) = hist_db.prepare("SELECT url, COALESCE(title, ''), COALESCE(visit_count, 1), COALESCE(last_visit_date, 0) FROM moz_places WHERE url IS NOT NULL") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            }) {
                for row in rows.flatten() {
                    let (url, title, vcount, time) = row;
                    let _ = triage_db.execute(
                        "INSERT INTO browser_history (browser_name, url, title, visit_time, visit_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![browser_label, url, title, time.to_string(), vcount],
                    );
                    count += 1;
                }
                return count;
            }
        }

        // 3. Try Safari schema (history_items + history_visits tables)
        if let Ok(mut stmt) = hist_db.prepare("SELECT i.url, COALESCE(v.title, ''), COALESCE(i.visit_count, 1), COALESCE(v.visit_time, 0) FROM history_items i LEFT JOIN history_visits v ON i.id = v.history_item WHERE i.url IS NOT NULL") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)?,
                    row.get::<_, f64>(3)? as i64,
                ))
            }) {
                for row in rows.flatten() {
                    let (url, title, vcount, time) = row;
                    let _ = triage_db.execute(
                        "INSERT INTO browser_history (browser_name, url, title, visit_time, visit_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![browser_label, url, title, time.to_string(), vcount],
                    );
                    count += 1;
                }
                return count;
            }
        }
    }
    count
}

fn write_browser_report(out_dir: &Path, browsers: &[InstalledBrowser]) {
    let report_path = out_dir.join("installed_browsers_report.txt");
    if let Ok(mut f) = fs::File::create(report_path) {
        let _ = writeln!(f, "====================================================================");
        let _ = writeln!(f, "           OpenForensic Cross-Platform Web Browser Report           ");
        let _ = writeln!(f, "====================================================================\n");
        let _ = writeln!(f, "Total Browser Profiles Detected: {}\n", browsers.len());

        for (idx, b) in browsers.iter().enumerate() {
            let _ = writeln!(f, "[{}] {} (Engine: {})", idx + 1, b.browser_name, b.engine);
            let _ = writeln!(f, "    User Profile   : {}", b.user_name);
            let _ = writeln!(f, "    Browser Profile: {}", b.profile_name);
            let _ = writeln!(f, "    History File   : {}", b.history_path);
            let _ = writeln!(f, "    Records Parsed : {}", b.history_count);
            let _ = writeln!(f, "    Status         : {}\n", b.status);
        }
        let _ = writeln!(f, "====================================================================");
    }
}

pub fn save_browsers_to_db(db: &Connection, browsers: &[InstalledBrowser]) {
    for b in browsers {
        let mut count = 0;
        let mut status = b.status.clone();
        if Path::new(&b.history_path).exists() && status == "Copied / Ready for Parsing" {
            let label = format!("{} ({} - {})", b.browser_name, b.profile_name, b.user_name);
            count = parse_history_db(Path::new(&b.history_path), &label, db);
            if count > 0 {
                status = format!("Extracted ({} History Records)", count);
            } else {
                status = "Extracted (Profile Empty / No Visits)".to_string();
            }
        }
        let _ = db.execute(
            "INSERT INTO installed_browsers (browser_name, engine, user_name, profile_name, history_path, history_count, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                b.browser_name,
                b.engine,
                b.user_name,
                b.profile_name,
                b.history_path,
                count as i64,
                status,
            ],
        );
    }
}
