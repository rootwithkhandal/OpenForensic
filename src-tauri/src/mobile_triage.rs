//! Mobile Device Triage Module
//!
//! Detects connected Android devices via ADB, extracts device metadata,
//! enumerates installed packages (system & user), and optionally pulls
//! APK files for offline forensic analysis. All results are persisted
//! to the triage SQLite database (`mobile_devices` / `mobile_apps` tables).

use crate::acquisition::ProgressEvent;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;

// ── Public Configuration ──────────────────────────────────────────────

/// Configuration for a mobile triage collection run.
pub struct MobileTriageConfig {
    /// Root output directory (mobile artifacts land under `<dest_dir>/mobile/<serial>/`).
    pub dest_dir: PathBuf,
    /// Optional explicit path to the `adb` binary. Auto-detected if `None`.
    pub adb_path: Option<String>,
    /// Whether to `adb pull` each user-installed APK to disk.
    pub pull_apks: bool,
}

// ── Result Types ──────────────────────────────────────────────────────

/// Metadata extracted from a single connected Android device.
#[derive(Debug, Clone)]
pub struct MobileDeviceInfo {
    pub device_id: String,
    pub model: String,
    pub os_version: String,
    pub connection_type: String,
    pub serial_number: String,
    pub state: String,
}

/// Metadata for a single installed Android package.
#[derive(Debug, Clone)]
pub struct MobileAppInfo {
    pub package_name: String,
    pub app_name: String,
    pub version: String,
    pub apk_path: String,
    pub installer: String,
    pub is_system: bool,
    pub pulled_local_path: Option<String>,
}

// ── ADB Discovery ─────────────────────────────────────────────────────

/// Locate the `adb` binary, checking (in order):
/// 1. An explicit user-supplied path
/// 2. The system PATH
/// 3. Common platform-tools install locations
fn resolve_adb_path(explicit: Option<&str>) -> Option<PathBuf> {
    // 1. Explicit path
    if let Some(p) = explicit {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }

    // 2. Try running `adb version` to check if it's on PATH
    let adb_name = if cfg!(target_os = "windows") { "adb.exe" } else { "adb" };
    if std::process::Command::new(adb_name)
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
    {
        return Some(PathBuf::from(adb_name));
    }

    // 3. Common install locations
    let candidates: Vec<PathBuf> = if cfg!(target_os = "windows") {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        vec![
            PathBuf::from(format!("{}\\Android\\Sdk\\platform-tools\\adb.exe", local)),
            PathBuf::from("C:\\Android\\platform-tools\\adb.exe"),
            PathBuf::from("C:\\Program Files\\Android\\platform-tools\\adb.exe"),
        ]
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_default();
        vec![
            PathBuf::from(format!("{}/Library/Android/sdk/platform-tools/adb", home)),
            PathBuf::from("/usr/local/bin/adb"),
        ]
    } else {
        let home = std::env::var("HOME").unwrap_or_default();
        vec![
            PathBuf::from(format!("{}/Android/Sdk/platform-tools/adb", home)),
            PathBuf::from("/usr/bin/adb"),
            PathBuf::from("/usr/local/bin/adb"),
        ]
    };

    candidates.into_iter().find(|p| p.exists())
}

// ── Core Triage Pipeline ──────────────────────────────────────────────

/// Execute the full mobile triage pipeline: detect devices → extract metadata
/// → enumerate packages → (optionally) pull APKs → insert into triage DB.
pub async fn run_mobile_triage(
    config: &MobileTriageConfig,
    progress_tx: Sender<ProgressEvent>,
) -> std::result::Result<(Vec<MobileDeviceInfo>, Vec<MobileAppInfo>), String> {
    let mut collected_devices = Vec::new();
    let mut collected_apps = Vec::new();

    // Resolve ADB
    let adb = match resolve_adb_path(config.adb_path.as_deref()) {
        Some(p) => p,
        None => {
            let _ = progress_tx
                .send(ProgressEvent::Log(
                    "[MOBILE] ADB binary not found. Skipping mobile triage. Install Android platform-tools or pass --adb-path.".to_string(),
                ))
                .await;
            return Ok((collected_devices, collected_apps));
        }
    };

    let _ = progress_tx
        .send(ProgressEvent::Log(format!(
            "[MOBILE] ADB binary located: {}",
            adb.display()
        )))
        .await;

    // ── Step 1: Enumerate connected devices ──
    let _ = progress_tx
        .send(ProgressEvent::Log(
            "[MOBILE] Enumerating connected Android devices...".to_string(),
        ))
        .await;

    let devices = enumerate_devices(&adb).map_err(|e| format!("ADB device enumeration failed: {}", e))?;

    if devices.is_empty() {
        let _ = progress_tx
            .send(ProgressEvent::Log(
                "[MOBILE] No connected Android devices detected.".to_string(),
            ))
            .await;
        return Ok((collected_devices, collected_apps));
    }

    let _ = progress_tx
        .send(ProgressEvent::Log(format!(
            "[MOBILE] Detected {} connected device(s).",
            devices.len()
        )))
        .await;

    // ── Step 2: For each device, collect metadata + packages ──
    for device in &devices {
        let _ = progress_tx
            .send(ProgressEvent::Log(format!(
                "[MOBILE] Processing device: {} ({}) [{}]",
                device.serial_number, device.model, device.state
            )))
            .await;

        // Skip unauthorized / offline devices
        if device.state != "device" {
            let _ = progress_tx
                .send(ProgressEvent::Log(format!(
                    "[MOBILE] Skipping device {} — state is '{}' (requires 'device'). Authorize USB debugging on the device.",
                    device.serial_number, device.state
                )))
                .await;

            collected_devices.push(device.clone());
            continue;
        }

        // Collect enriched device metadata
        let enriched = enrich_device_info(&adb, device);
        collected_devices.push(enriched.clone());

        // Create output directory for this device
        let device_dir = config.dest_dir.join("mobile").join(&enriched.serial_number);
        let _ = std::fs::create_dir_all(&device_dir);

        // Write device info to file
        write_device_report(&device_dir, &enriched);

        // ── Step 2.5: Deep AndroidForensics Data Collection ──
        let _ = progress_tx
            .send(ProgressEvent::Log(format!(
                "[MOBILE] Running deep AndroidForensics collection on {} (Logs, Battery, Network, Accounts, SMS/Calls)...",
                enriched.serial_number
            )))
            .await;

        let af_dir = device_dir.join("android_forensics");
        let _ = std::fs::create_dir_all(&af_dir);

        // 1. System Logs (logcat)
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting real-time system logs (logcat)...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["logcat", "-d"], &af_dir.join("system_logcat.txt"));

        // 2. Battery & Power Diagnostics
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting battery & power metrics (dumpsys battery)...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "dumpsys", "battery"], &af_dir.join("dumpsys_battery.txt"));

        // 3. Network Configuration & Connections
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting network connectivity & routing...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "dumpsys", "connectivity"], &af_dir.join("dumpsys_connectivity.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "ifconfig"], &af_dir.join("ifconfig.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "netstat"], &af_dir.join("netstat.txt"));

        // 4. Usage Stats & Timeline Data
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting application usage statistics & system settings...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "dumpsys", "usagestats"], &af_dir.join("dumpsys_usagestats.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "settings", "list", "system"], &af_dir.join("settings_system.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "settings", "list", "global"], &af_dir.join("settings_global.txt"));

        // 5. Registered Accounts & Emails
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting registered device accounts & emails...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "dumpsys", "account"], &af_dir.join("dumpsys_account.txt"));
        extract_registered_emails(&adb, &enriched.serial_number, &af_dir.join("registered_emails.txt"));

        // 6. User Communications: Contacts, Call Logs, and SMS Messages (via Content Provider)
        let _ = progress_tx.send(ProgressEvent::Log("  -> Extracting user communications (Contacts, Call Logs, SMS)...".to_string())).await;
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "content", "query", "--uri", "content://contacts/phones/"], &af_dir.join("contacts.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "content", "query", "--uri", "content://call_log/calls"], &af_dir.join("call_logs.txt"));
        run_adb_to_file(&adb, &enriched.serial_number, &["shell", "content", "query", "--uri", "content://sms/"], &af_dir.join("sms_messages.txt"));

        // ── Step 3: Enumerate packages ──
        let _ = progress_tx
            .send(ProgressEvent::Log(format!(
                "[MOBILE] Enumerating installed packages on {}...",
                enriched.serial_number
            )))
            .await;

        let apps = enumerate_packages(&adb, &enriched.serial_number);
        collected_apps.extend(apps.clone());

        let _ = progress_tx
            .send(ProgressEvent::Log(format!(
                "[MOBILE] Found {} installed package(s) on {}.",
                apps.len(),
                enriched.serial_number
            )))
            .await;

        // ── Step 3.5: Triage Instant Messaging / Communication Apps ──
        let im_apps: Vec<&MobileAppInfo> = apps.iter().filter(|a| get_known_app_name(&a.package_name).is_some()).collect();
        if !im_apps.is_empty() {
            let _ = progress_tx
                .send(ProgressEvent::Log(format!(
                    "[MOBILE FORENSIC ALERT] Detected {} high-value communication/IM app(s) on {}:",
                    im_apps.len(),
                    enriched.serial_number
                )))
                .await;

            let im_dir = device_dir.join("im_artifacts");
            let _ = std::fs::create_dir_all(&im_dir);

            for im in &im_apps {
                let _ = progress_tx
                    .send(ProgressEvent::Log(format!(
                        "  -> {} ({}) v{}",
                        im.app_name, im.package_name, im.version
                    )))
                    .await;

                // Check known backup & database locations on shared storage
                let backup_paths = get_known_backup_paths(&im.package_name);
                for remote_path in backup_paths {
                    if check_remote_path_exists(&adb, &enriched.serial_number, remote_path) {
                        let _ = progress_tx
                            .send(ProgressEvent::Log(format!(
                                "[MOBILE ARTIFACT] Found IM backup/storage directory for {}: {}",
                                im.app_name, remote_path
                            )))
                            .await;

                        // Automatically pull backup database files (*.db, *.crypt*, *.backup) if accessible
                        let app_im_dir = im_dir.join(&im.package_name);
                        let _ = std::fs::create_dir_all(&app_im_dir);
                        let _ = pull_im_backups(&adb, &enriched.serial_number, remote_path, &app_im_dir);
                    }
                }
            }

            // Write summary IM report
            write_im_report(&device_dir, &enriched, &im_apps);
        }

        // ── Step 4: Optionally pull APKs ──
        if config.pull_apks {
            let user_apps: Vec<&MobileAppInfo> = apps.iter().filter(|a| !a.is_system).collect();
            let total = user_apps.len();
            let _ = progress_tx
                .send(ProgressEvent::Log(format!(
                    "[MOBILE] Pulling {} user-installed APK(s) from {}...",
                    total, enriched.serial_number
                )))
                .await;

            let apk_dir = device_dir.join("apks");
            let _ = std::fs::create_dir_all(&apk_dir);

            let mut pulled = 0usize;
            for app in &user_apps {
                if !app.apk_path.is_empty() {
                    let dest_name = format!("{}.apk", app.package_name);
                    let dest_path = apk_dir.join(&dest_name);
                    if pull_apk(&adb, &enriched.serial_number, &app.apk_path, &dest_path) {
                        pulled += 1;
                    }
                }
            }

            let _ = progress_tx
                .send(ProgressEvent::Log(format!(
                    "[MOBILE] Successfully pulled {}/{} APK(s) from {}.",
                    pulled, total, enriched.serial_number
                )))
                .await;
        }
    }

    let _ = progress_tx
        .send(ProgressEvent::Log(
            "[MOBILE] Mobile device triage completed.".to_string(),
        ))
        .await;

    Ok((collected_devices, collected_apps))
}

// ── Internal Helpers ──────────────────────────────────────────────────

/// Parse `adb devices -l` output into device info structs.
fn enumerate_devices(adb: &Path) -> std::result::Result<Vec<MobileDeviceInfo>, String> {
    let output = std::process::Command::new(adb)
        .args(["devices", "-l"])
        .output()
        .map_err(|e| format!("Failed to execute adb devices: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    for line in stdout.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let serial = parts[0].to_string();
        let state = parts[1].to_string();

        // Parse optional key:value pairs (model:xxx, device:xxx, transport_id:xxx)
        let mut model = String::new();
        let mut connection_type = "USB".to_string();

        for part in parts.iter().skip(2) {
            if let Some(val) = part.strip_prefix("model:") {
                model = val.replace('_', " ");
            }
        }

        // Detect WiFi connections (serial contains colon with IP pattern)
        if serial.contains(':') && serial.contains('.') {
            connection_type = "WiFi".to_string();
        }

        devices.push(MobileDeviceInfo {
            device_id: serial.clone(),
            model,
            os_version: String::new(), // Enriched later
            connection_type,
            serial_number: serial,
            state,
        });
    }

    Ok(devices)
}

/// Enrich a device with additional `getprop` metadata.
fn enrich_device_info(adb: &Path, device: &MobileDeviceInfo) -> MobileDeviceInfo {
    let mut enriched = device.clone();

    let get_prop = |prop: &str| -> String {
        std::process::Command::new(adb)
            .args(["-s", &device.serial_number, "shell", "getprop", prop])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    let model = get_prop("ro.product.model");
    if !model.is_empty() {
        enriched.model = model;
    }

    enriched.os_version = get_prop("ro.build.version.release");

    let serial = get_prop("ro.serialno");
    if !serial.is_empty() && enriched.serial_number != serial {
        // Keep the ADB transport serial as device_id, use hardware serial
        enriched.device_id = enriched.serial_number.clone();
    }

    enriched
}

/// Enumerate installed packages via `pm list packages -f`.
fn enumerate_packages(
    adb: &Path,
    serial: &str,
) -> Vec<MobileAppInfo> {
    let mut apps = Vec::new();

    // Get all packages with their APK paths
    let output = match std::process::Command::new(adb)
        .args(["-s", serial, "shell", "pm", "list", "packages", "-f"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return apps,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Get system packages separately so we can flag them
    let system_output = std::process::Command::new(adb)
        .args(["-s", serial, "shell", "pm", "list", "packages", "-s"])
        .output()
        .ok();

    let system_packages: Vec<String> = system_output
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.strip_prefix("package:").map(|s| s.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Parse `package:/data/app/com.example-xxx/base.apk=com.example` lines
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("package:") {
            // Format: /path/to/base.apk=package.name
            if let Some(eq_pos) = rest.rfind('=') {
                let apk_path = rest[..eq_pos].trim().to_string();
                let package_name = rest[eq_pos + 1..].trim().to_string();
                let is_system = system_packages.contains(&package_name);

                let app_name = get_known_app_name(&package_name)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| package_name.clone());

                apps.push(MobileAppInfo {
                    package_name: package_name.clone(),
                    app_name,
                    version: get_package_version(adb, serial, &package_name),
                    apk_path,
                    installer: get_installer(adb, serial, &package_name),
                    is_system,
                    pulled_local_path: None,
                });
            }
        }
    }

    apps
}

/// Get the version name of a package via `dumpsys package`.
fn get_package_version(adb: &Path, serial: &str, package: &str) -> String {
    let output = match std::process::Command::new(adb)
        .args([
            "-s", serial, "shell", "dumpsys", "package", package,
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("versionName=") {
            return rest.trim().to_string();
        }
    }

    String::new()
}

/// Get the installer package name (e.g., com.android.vending for Play Store).
fn get_installer(adb: &Path, serial: &str, package: &str) -> String {
    // Try to get installer via `cmd package get-installer` on newer Android
    let output = match std::process::Command::new(adb)
        .args([
            "-s", serial, "shell", "cmd", "package", "get-installer", package,
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return "unknown".to_string(),
    };

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if result.contains("not found") || result.is_empty() || result == "null" {
        "unknown".to_string()
    } else {
        result
    }
}

/// Pull a single APK from the device to the local filesystem.
fn pull_apk(adb: &Path, serial: &str, remote_path: &str, local_path: &Path) -> bool {
    std::process::Command::new(adb)
        .args([
            "-s",
            serial,
            "pull",
            remote_path,
            &local_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Write a human-readable device metadata report file.
fn write_device_report(device_dir: &Path, device: &MobileDeviceInfo) {
    let report_path = device_dir.join("device_info.txt");
    if let Ok(mut f) = std::fs::File::create(report_path) {
        use std::io::Write;
        let _ = writeln!(f, "============================================");
        let _ = writeln!(f, "  OpenForensic Mobile Device Triage Report  ");
        let _ = writeln!(f, "============================================");
        let _ = writeln!(f, "Device ID:       {}", device.device_id);
        let _ = writeln!(f, "Serial Number:   {}", device.serial_number);
        let _ = writeln!(f, "Model:           {}", device.model);
        let _ = writeln!(f, "Android Version: {}", device.os_version);
        let _ = writeln!(f, "Connection:      {}", device.connection_type);
        let _ = writeln!(f, "State:           {}", device.state);
        let _ = writeln!(f, "Triage Time:     {}", chrono::Utc::now().to_rfc2822());
        let _ = writeln!(f, "============================================");
    }
}

// ── Database Helpers ──────────────────────────────────────────────────

pub fn save_mobile_triage_to_db(
    db: &Connection,
    devices: &[MobileDeviceInfo],
    apps: &[MobileAppInfo],
) {
    for device in devices {
        insert_device(db, device);
    }
    for app in apps {
        insert_app(db, app);
    }
}

pub fn insert_device(db: &Connection, device: &MobileDeviceInfo) {
    let _ = db.execute(
        "INSERT INTO mobile_devices (device_id, model, os_version, connection_type, serial_number, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            device.device_id,
            device.model,
            device.os_version,
            device.connection_type,
            device.serial_number,
            device.state,
        ],
    );
}

pub fn insert_app(db: &Connection, app: &MobileAppInfo) {
    let _ = db.execute(
        "INSERT INTO mobile_apps (package_name, app_name, version, apk_path, installer, is_system, pulled_local_path) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            app.package_name,
            app.app_name,
            app.version,
            app.apk_path,
            app.installer,
            app.is_system as i32,
            app.pulled_local_path,
        ],
    );
}

// ── Instant Messaging (IM) Triage Helpers ─────────────────────────────

#[allow(dead_code)]
pub fn evaluate_app_risk(app: &MobileAppInfo) -> (&'static str, &'static str) {
    if !app.is_system && !app.installer.eq_ignore_ascii_case("com.android.vending") && !app.installer.is_empty() && app.installer != "null" {
        ("HIGH RISK", "Side-loaded APK (Non-Play Store Installer)")
    } else if get_known_app_name(&app.package_name).is_some() {
        ("MEDIUM RISK", "Communication / IM Messaging App")
    } else if app.is_system && app.apk_path.starts_with("/data/") {
        ("HIGH RISK", "System App Anomaly (Executing from /data/)")
    } else {
        ("LOW RISK", "Standard App")
    }
}

pub fn get_known_app_name(package: &str) -> Option<&'static str> {

    match package {
        "com.whatsapp" => Some("WhatsApp Messenger"),
        "com.whatsapp.w4b" => Some("WhatsApp Business"),
        "org.telegram.messenger" => Some("Telegram Messenger"),
        "org.telegram.plus" => Some("Telegram Plus"),
        "org.telegram.messenger.web" => Some("Telegram Web"),
        "org.thoughtcrime.securesms" => Some("Signal Private Messenger"),
        "com.facebook.orca" => Some("Facebook Messenger"),
        "com.facebook.mlite" => Some("Messenger Lite"),
        "com.viber.voip" => Some("Viber Messenger"),
        "com.tencent.mm" => Some("WeChat"),
        "com.discord" => Some("Discord"),
        "com.skype.raider" => Some("Skype"),
        "com.snapchat.android" => Some("Snapchat"),
        "com.google.android.apps.tachyon" => Some("Google Meet"),
        "com.kakao.talk" => Some("KakaoTalk"),
        "jp.naver.line.android" => Some("LINE"),
        "com.threema.app" => Some("Threema"),
        "im.vector.app" => Some("Element / Matrix"),
        "com.session.session" => Some("Session Messenger"),
        "com.wire" => Some("Wire Secure Messenger"),
        "com.wickr.pro" => Some("Wickr Pro"),
        _ => None,
    }
}

fn get_known_backup_paths(package: &str) -> &'static [&'static str] {
    match package {
        "com.whatsapp" | "com.whatsapp.w4b" => &[
            "/sdcard/WhatsApp/Databases",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
            "/sdcard/WhatsApp/Backups",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups",
        ],
        "org.telegram.messenger" | "org.telegram.plus" => &[
            "/sdcard/Telegram",
            "/sdcard/Android/media/org.telegram.messenger/Telegram",
            "/sdcard/Telegram/Telegram Documents",
        ],
        "org.thoughtcrime.securesms" => &[
            "/sdcard/Signal/Backups",
            "/sdcard/Android/media/org.thoughtcrime.securesms/Signal/Backups",
        ],
        "com.viber.voip" => &[
            "/sdcard/viber",
            "/sdcard/Android/media/com.viber.voip",
        ],
        "com.tencent.mm" => &[
            "/sdcard/tencent/MicroMsg",
            "/sdcard/Android/media/com.tencent.mm",
        ],
        "jp.naver.line.android" => &[
            "/sdcard/Android/data/jp.naver.line.android/backup",
        ],
        "com.kakao.talk" => &[
            "/sdcard/Android/data/com.kakao.talk/backup",
        ],
        _ => &[],
    }
}

fn check_remote_path_exists(adb: &Path, serial: &str, remote_path: &str) -> bool {
    std::process::Command::new(adb)
        .args(["-s", serial, "shell", "ls", "-d", remote_path])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).contains("No such file"))
        .unwrap_or(false)
}

fn pull_im_backups(adb: &Path, serial: &str, remote_path: &str, local_dir: &Path) {
    let _ = std::process::Command::new(adb)
        .args([
            "-s",
            serial,
            "pull",
            remote_path,
            &local_dir.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn write_im_report(device_dir: &Path, device: &MobileDeviceInfo, im_apps: &[&MobileAppInfo]) {
    let report_path = device_dir.join("im_triage_report.txt");
    if let Ok(mut f) = std::fs::File::create(report_path) {
        use std::io::Write;
        let _ = writeln!(f, "=================================================");
        let _ = writeln!(f, " OpenForensic Instant Messaging (IM) Triage Report ");
        let _ = writeln!(f, "=================================================");
        let _ = writeln!(f, "Device: {} ({})", device.model, device.serial_number);
        let _ = writeln!(f, "Date:   {}", chrono::Utc::now().to_rfc2822());
        let _ = writeln!(f, "-------------------------------------------------");
        let _ = writeln!(f, "Detected Communication & IM Applications:");
        for im in im_apps {
            let _ = writeln!(f, "  * {} [{}] v{} (Installer: {})", im.app_name, im.package_name, im.version, im.installer);
            let backup_paths = get_known_backup_paths(&im.package_name);
            if !backup_paths.is_empty() {
                let _ = writeln!(f, "    Known Artifact Paths Checked: {:?}", backup_paths);
            }
        }
        let _ = writeln!(f, "=================================================");
    }
}

// ── Deep AndroidForensics Helpers ─────────────────────────────────────

fn run_adb_to_file(adb: &Path, serial: &str, args: &[&str], out_path: &Path) {
    let mut cmd_args = vec!["-s", serial];
    cmd_args.extend_from_slice(args);

    if let Ok(output) = std::process::Command::new(adb).args(&cmd_args).output() {
        if output.status.success() || !output.stdout.is_empty() {
            let _ = std::fs::write(out_path, &output.stdout);
        }
    }
}

fn extract_registered_emails(adb: &Path, serial: &str, out_path: &Path) {
    if let Ok(output) = std::process::Command::new(adb)
        .args(["-s", serial, "shell", "dumpsys", "account"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        let mut emails = Vec::new();
        for word in text.split_whitespace() {
            let clean = word.trim_matches(|c| c == '{' || c == '}' || c == ',' || c == '=' || c == '[' || c == ']');
            if clean.contains('@') && clean.contains('.') && !clean.starts_with('@') && !clean.ends_with('.') {
                if !emails.contains(&clean.to_string()) {
                    emails.push(clean.to_string());
                }
            }
        }
        if !emails.is_empty() {
            let mut content = String::from("=== Extracted Registered Email Addresses ===\n\n");
            for email in emails {
                content.push_str(&email);
                content.push('\n');
            }
            let _ = std::fs::write(out_path, content);
        }
    }
}
