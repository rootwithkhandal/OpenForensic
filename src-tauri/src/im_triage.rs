//! Desktop Messaging & Communication Apps Triage Module
//!
//! Scans physical systems or mounted disk images for installed messaging and communication applications
//! (WhatsApp Desktop, Telegram Desktop, Discord, Signal, Slack, Microsoft Teams, Skype, Viber, WeChat, Zoom).
//! Extracts database artifacts, IndexedDB storage, session logs, and config files into the triage folder
//! and records findings into the SQLite triage database (`im_apps` table).

use rusqlite::Connection;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;
use crate::acquisition::ProgressEvent;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstalledImApp {
    pub app_name: String,
    pub app_type: String,
    pub user_name: String,
    pub install_path: String,
    pub data_path: String,
    pub artifacts_count: usize,
    pub status: String,
}

struct AppDefinition {
    app_name: &'static str,
    app_type: &'static str,
    win_paths: &'static [&'static str],
    unix_paths: &'static [&'static str],
}

const APP_DEFINITIONS: &[AppDefinition] = &[
    AppDefinition {
        app_name: "WhatsApp Desktop",
        app_type: "Instant Messaging",
        win_paths: &[
            "AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalState",
            "AppData/Local/WhatsApp",
            "AppData/Roaming/WhatsApp",
        ],
        unix_paths: &[
            "Library/Application Support/WhatsApp",
            "Library/Containers/desktop.WhatsApp/Data",
        ],
    },
    AppDefinition {
        app_name: "Telegram Desktop",
        app_type: "Instant Messaging",
        win_paths: &[
            "AppData/Roaming/Telegram Desktop/tdata",
            "AppData/Roaming/Telegram Desktop",
            "AppData/Local/Telegram Desktop",
        ],
        unix_paths: &[
            ".local/share/TelegramDesktop",
            "Library/Application Support/Telegram Desktop",
        ],
    },
    AppDefinition {
        app_name: "Discord",
        app_type: "VoIP & Community",
        win_paths: &[
            "AppData/Roaming/discord",
            "AppData/Local/Discord",
        ],
        unix_paths: &[
            ".config/discord",
            "Library/Application Support/discord",
        ],
    },
    AppDefinition {
        app_name: "Signal Desktop",
        app_type: "Encrypted IM",
        win_paths: &[
            "AppData/Roaming/Signal",
            "AppData/Local/Programs/signal-desktop",
        ],
        unix_paths: &[
            ".config/Signal",
            "Library/Application Support/Signal",
        ],
    },
    AppDefinition {
        app_name: "Slack",
        app_type: "Workplace Collaboration",
        win_paths: &[
            "AppData/Roaming/Slack",
            "AppData/Local/slack",
        ],
        unix_paths: &[
            ".config/Slack",
            "Library/Application Support/Slack",
        ],
    },
    AppDefinition {
        app_name: "Microsoft Teams",
        app_type: "Workplace Collaboration",
        win_paths: &[
            "AppData/Roaming/Microsoft/Teams",
            "AppData/Local/Packages/MSTeams_8wekyb3d8bbwe/LocalCache",
            "AppData/Local/Microsoft/Teams",
        ],
        unix_paths: &[
            ".config/Microsoft/Teams",
            "Library/Application Support/Microsoft/Teams",
        ],
    },
    AppDefinition {
        app_name: "Skype for Desktop",
        app_type: "VoIP & Video Calling",
        win_paths: &[
            "AppData/Roaming/Microsoft/Skype for Desktop",
            "AppData/Local/Packages/Microsoft.SkypeApp_kzf8qxf38zg5c/LocalState",
        ],
        unix_paths: &[
            ".config/skypeforlinux",
            "Library/Application Support/Skype",
        ],
    },
    AppDefinition {
        app_name: "Viber PC",
        app_type: "Instant Messaging",
        win_paths: &[
            "AppData/Roaming/ViberPC",
            "AppData/Local/Viber",
        ],
        unix_paths: &[
            ".viberPC",
            "Library/Application Support/ViberPC",
        ],
    },
    AppDefinition {
        app_name: "WeChat Desktop",
        app_type: "Instant Messaging",
        win_paths: &[
            "Documents/WeChat Files",
            "AppData/Roaming/Tencent/WeChat",
        ],
        unix_paths: &[
            "Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat",
        ],
    },
    AppDefinition {
        app_name: "Zoom Client",
        app_type: "Video Conferencing",
        win_paths: &[
            "AppData/Roaming/Zoom",
        ],
        unix_paths: &[
            ".zoom",
            "Library/Application Support/zoom.us",
        ],
    },
];

pub async fn run_im_triage(
    dest_dir: &Path,
    root_path: &Path,
    is_mounted_target: bool,
    progress_tx: Sender<ProgressEvent>,
) -> Result<Vec<InstalledImApp>, String> {
    let _ = progress_tx
        .send(ProgressEvent::Log(
            "[TRIAGE] Enumerating user profiles for messaging & communication apps...".to_string(),
        ))
        .await;

    let mut user_dirs: Vec<(PathBuf, String)> = Vec::new();

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
    } else {
        let home_dir = PathBuf::from(std::env::var("HOME").unwrap_or_default());
        let name = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
        if home_dir.exists() {
            user_dirs.push((home_dir, name));
        }
    }

    let mut found_apps: Vec<InstalledImApp> = Vec::new();
    let im_output_dir = dest_dir.join("im_apps");
    let _ = fs::create_dir_all(&im_output_dir);

    for (user_path, user_name) in &user_dirs {
        for app_def in APP_DEFINITIONS {
            let paths_to_check = if cfg!(target_os = "windows") || is_mounted_target {
                app_def.win_paths
            } else {
                app_def.unix_paths
            };

            for rel_path in paths_to_check {
                let full_data_path = user_path.join(rel_path);
                if full_data_path.exists() {
                    let _ = progress_tx
                        .send(ProgressEvent::Log(format!(
                            "[TRIAGE] Detected {} for user '{}' at: {}",
                            app_def.app_name,
                            user_name,
                            full_data_path.display()
                        )))
                        .await;

                    let app_dest_dir = im_output_dir.join(format!(
                        "{}_{}",
                        app_def.app_name.replace(' ', "_"),
                        user_name
                    ));
                    let _ = fs::create_dir_all(&app_dest_dir);

                    let count = copy_forensic_artifacts(&full_data_path, &app_dest_dir, 0);
                    let status = if count > 0 {
                        format!("Installed ({} Evidence Artifacts Copied)", count)
                    } else {
                        "Installed (Directory Found / No DBs)".to_string()
                    };

                    found_apps.push(InstalledImApp {
                        app_name: app_def.app_name.to_string(),
                        app_type: app_def.app_type.to_string(),
                        user_name: user_name.clone(),
                        install_path: full_data_path.display().to_string(),
                        data_path: full_data_path.display().to_string(),
                        artifacts_count: count,
                        status,
                    });

                    break; // Found primary data path for this app/user, move to next app
                }
            }
        }
    }

    let _ = progress_tx
        .send(ProgressEvent::Log(format!(
            "[TRIAGE] Completed messaging apps triage. Found {} installed application instance(s).",
            found_apps.len()
        )))
        .await;

    write_im_report(&im_output_dir, &found_apps);

    Ok(found_apps)
}

fn is_ignored_user(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "public" | "default" | "default user" | "all users" | "desktop.ini" | "defaultapppool"
    )
}

fn copy_forensic_artifacts(src_dir: &Path, dst_dir: &Path, depth: usize) -> usize {
    if depth > 4 {
        return 0;
    }
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                if dir_name.eq_ignore_ascii_case("Cache")
                    || dir_name.eq_ignore_ascii_case("Code Cache")
                    || dir_name.eq_ignore_ascii_case("GPUCache")
                    || dir_name.eq_ignore_ascii_case("temp")
                    || dir_name.eq_ignore_ascii_case("tmp")
                {
                    continue;
                }
                let sub_dst = dst_dir.join(&dir_name);
                let _ = fs::create_dir_all(&sub_dst);
                count += copy_forensic_artifacts(&path, &sub_dst, depth + 1);
            } else if path.is_file() {
                if is_valuable_artifact(&path) {
                    if let Ok(meta) = fs::metadata(&path) {
                        if meta.len() <= 100 * 1024 * 1024 {
                            if let Some(file_name) = path.file_name() {
                                if fs::copy(&path, dst_dir.join(file_name)).is_ok() {
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    count
}

fn is_valuable_artifact(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        matches!(
            ext_lower.as_str(),
            "db" | "sqlite" | "sqlite3" | "json" | "log" | "txt" | "ini" | "cfg"
                | "s" | "dat" | "key" | "ldb" | "pouch" | "storage" | "bak" | "tdata"
        )
    } else {
        // Files without extension in tdata / Local Storage
        true
    }
}

fn write_im_report(output_dir: &Path, apps: &[InstalledImApp]) {
    let report_path = output_dir.join("installed_messaging_apps_report.txt");
    if let Ok(mut f) = std::fs::File::create(&report_path) {
        let _ = writeln!(f, "====================================================================");
        let _ = writeln!(f, "         OpenForensic Installed Messaging Apps Triage Report        ");
        let _ = writeln!(f, "====================================================================\n");
        let _ = writeln!(f, "Total Installed Instances Detected: {}\n", apps.len());

        for (idx, app) in apps.iter().enumerate() {
            let _ = writeln!(f, "[{}] {} ({})", idx + 1, app.app_name, app.app_type);
            let _ = writeln!(f, "    User Profile   : {}", app.user_name);
            let _ = writeln!(f, "    Data Path      : {}", app.data_path);
            let _ = writeln!(f, "    Evidence Copied: {} file(s)", app.artifacts_count);
            let _ = writeln!(f, "    Status         : {}\n", app.status);
        }
        let _ = writeln!(f, "====================================================================");
    }
}

pub fn save_im_apps_to_db(db: &Connection, apps: &[InstalledImApp]) {
    for app in apps {
        insert_im_app(db, app);
    }
}

pub fn insert_im_app(db: &Connection, app: &InstalledImApp) {
    let _ = db.execute(
        "INSERT INTO im_apps (app_name, app_type, user_name, install_path, data_path, artifacts_count, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            app.app_name,
            app.app_type,
            app.user_name,
            app.install_path,
            app.data_path,
            app.artifacts_count as i64,
            app.status,
        ],
    );
}
