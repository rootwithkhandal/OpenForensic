use serde::Deserialize;
use std::process::Stdio;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use crate::ActiveTaskState;
use crate::acquisition::ProgressEvent;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

/// Sentinel values that indicate the built-in native Rust engine should be used.
const BUILTIN_SENTINELS: &[&str] = &[
    "",
    "builtin",
    "default",
    "Built-in Rust Volatility Engine (Default)",
];

/// Check if the given vol_path indicates the built-in engine should be used.
fn is_builtin_engine(vol_path: &str) -> bool {
    let trimmed = vol_path.trim();
    if BUILTIN_SENTINELS.iter().any(|s| s.eq_ignore_ascii_case(trimmed)) {
        return true;
    }
    // Also use builtin if the path doesn't exist on disk (e.g., "vol.py" with no Python installed)
    if !trimmed.is_empty() && !std::path::Path::new(trimmed).exists() {
        return true;
    }
    false
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VolatilityConfig {
    pub image_path: String,
    pub vol_path: String,
    pub profile: String,
    pub enrich_vt: bool,
    pub enrich_mb: bool,
    pub enrich_abuseip: bool,
    pub vt_key: String,
    pub mb_key: String,
    pub abuseip_key: String,
}

#[tauri::command]
pub async fn start_volatility_analysis(
    config: VolatilityConfig,
    state: State<'_, ActiveTaskState>,
    mode_state: State<'_, crate::state::AcquisitionModeState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    crate::state::require_analysis_mode(&mode_state)?;
    let mut lock = state.lock().map_err(|_| "ActiveTaskState mutex poisoned".to_string())?;
    if lock.is_some() {
        return Err("A task is already running.".to_string());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(100);
    *lock = Some(tx.clone());

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_handle_clone.emit("volatility-event", event);
        }
    });

    let app_clone = app_handle.clone();
    tokio::spawn(async move {
        let _ = start_volatility_analysis_backend(&config, tx).await;
        crate::clear_active_task(&app_clone);
    });

    Ok(())
}

pub async fn start_volatility_analysis_backend(
    config: &VolatilityConfig,
    tx: tokio::sync::mpsc::Sender<ProgressEvent>,
) -> Result<(), String> {
    // ── Decide: native Rust engine vs. external subprocess ──
    if is_builtin_engine(&config.vol_path) {
        return run_builtin_engine(config, tx).await;
    }

    // ── External subprocess path (legacy/custom tool) ──
    let _ = tx.send(ProgressEvent::Log(format!("Executing external: {} -f {} {}", config.vol_path, config.image_path, config.profile))).await;
    run_external_engine(config, tx).await
}

/// Run the built-in native Rust volatility engine in-process.
async fn run_builtin_engine(
    config: &VolatilityConfig,
    tx: tokio::sync::mpsc::Sender<ProgressEvent>,
) -> Result<(), String> {
    let _ = tx.send(ProgressEvent::Log(
        "[VOLATILITY] Using built-in native Rust Volatility engine (no Python required)".to_string()
    )).await;

    let (vol_tx, mut vol_rx) = tokio::sync::mpsc::channel::<String>(256);

    // Set up enrichment pipeline on the output lines
    let tx_enrich = tx.clone();
    let vt_key = config.vt_key.clone();
    let abuseip_key = config.abuseip_key.clone();
    let enrich_vt = config.enrich_vt;
    let enrich_abuseip = config.enrich_abuseip;

    // Genuinely infallible: regex pattern is compiled from a static constant string with valid syntax
    #[allow(clippy::unwrap_used)]
    let ip_re = regex::Regex::new(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();

    #[allow(clippy::unwrap_used)]
    let hash_re = regex::Regex::new(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b").unwrap();

    let vt_cache = Arc::new(AsyncMutex::new(HashSet::new()));

    // Spawn enrichment consumer that reads from the native engine output channel
    let enrichment_task = tokio::spawn(async move {
        while let Some(line) = vol_rx.recv().await {
            let _ = tx_enrich.send(ProgressEvent::Log(line.clone())).await;

            // AbuseIPDB enrichment
            if enrich_abuseip && !abuseip_key.is_empty() {
                if let Some(caps) = ip_re.captures(&line) {
                    let ip = &caps[0];
                    if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("172.16.") && ip != "0.0.0.0" {
                        let key = abuseip_key.clone();
                        let ip_str = ip.to_string();
                        let tx_inner = tx_enrich.clone();
                        tokio::spawn(async move {
                            if let Ok(res) = check_abuseip(&ip_str, &key).await {
                                let _ = tx_inner.send(ProgressEvent::Log(format!("  [AbuseIPDB] Result for {}: {}", ip_str, res))).await;
                            }
                        });
                    }
                }
            }

            // VirusTotal enrichment
            if enrich_vt && !vt_key.is_empty() {
                if let Some(caps) = hash_re.captures(&line) {
                    let hash_str = caps[0].to_lowercase();
                    if !hash_str.chars().all(|c| c == '0') && !hash_str.chars().all(|c| c == 'f') {
                        let mut cache_guard = vt_cache.lock().await;
                        if !cache_guard.contains(&hash_str) {
                            cache_guard.insert(hash_str.clone());
                            drop(cache_guard);
                            let key = vt_key.clone();
                            let tx_inner = tx_enrich.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                if let Ok(res) = check_virustotal(&hash_str, &key).await {
                                    let _ = tx_inner.send(ProgressEvent::Log(format!("  [VirusTotal] Result for {}: {}", hash_str, res))).await;
                                }
                            });
                        }
                    }
                }
            }
        }
    });

    // Run the native Rust volatility engine
    let image_path = config.image_path.clone();
    let profile = config.profile.clone();

    let analysis_result = volatility::run_analysis(&image_path, &profile, vol_tx).await;

    // Wait for enrichment pipeline to drain
    let _ = enrichment_task.await;

    // Send completion event
    let _ = tx.send(ProgressEvent::Finished {
        bytes_read: 0,
        bad_sectors: 0,
        hashes: HashMap::new(),
    }).await;

    analysis_result
}

/// Run an external volatility tool as a subprocess (legacy fallback for custom tools).
async fn run_external_engine(
    config: &VolatilityConfig,
    tx: tokio::sync::mpsc::Sender<ProgressEvent>,
) -> Result<(), String> {
    let mut cmd;
    if config.vol_path.ends_with(".py") {
        cmd = Command::new("python");
        cmd.arg(&config.vol_path);
    } else {
        cmd = Command::new(&config.vol_path);
    }

    cmd.arg("-f")
       .arg(&config.image_path)
       .arg(&config.profile)
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(ProgressEvent::Error(format!("Failed to start Volatility: {}", e))).await;
            return Err(format!("Failed to start Volatility: {}", e));
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return Err("Failed to open Volatility stdout".to_string()),
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => return Err("Failed to open Volatility stderr".to_string()),
    };

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    let tx_out = tx.clone();
    let vt_key = config.vt_key.clone();
    let abuseip_key = config.abuseip_key.clone();
    let enrich_vt = config.enrich_vt;
    let enrich_abuseip = config.enrich_abuseip;
    
    // Genuinely infallible: regex pattern is compiled from a static constant string with valid syntax
    #[allow(clippy::unwrap_used)]
    let ip_re = regex::Regex::new(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();

    #[allow(clippy::unwrap_used)]
    let hash_re = regex::Regex::new(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b").unwrap();

    let vt_cache = Arc::new(AsyncMutex::new(HashSet::new()));

    let stdout_task = tokio::spawn(async move {
        while let Ok(Some(line)) = stdout_reader.next_line().await {
            let _ = tx_out.send(ProgressEvent::Log(line.clone())).await;

            if enrich_abuseip && !abuseip_key.is_empty()
                && let Some(caps) = ip_re.captures(&line)
            {
                let ip = &caps[0];
                if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("172.16.") && ip != "0.0.0.0" {
                    let key = abuseip_key.clone();
                    let ip_str = ip.to_string();
                    let tx_inner = tx_out.clone();
                    tokio::spawn(async move {
                        if let Ok(res) = check_abuseip(&ip_str, &key).await {
                            let _ = tx_inner.send(ProgressEvent::Log(format!("  [AbuseIPDB] Result for {}: {}", ip_str, res))).await;
                        }
                    });
                }
            }

            if enrich_vt && !vt_key.is_empty()
                && let Some(caps) = hash_re.captures(&line)
            {
                let hash_str = caps[0].to_lowercase();
                if !hash_str.chars().all(|c| c == '0') && !hash_str.chars().all(|c| c == 'f') {
                    let mut cache_guard = vt_cache.lock().await;
                    if !cache_guard.contains(&hash_str) {
                        cache_guard.insert(hash_str.clone());
                        drop(cache_guard);
                        let key = vt_key.clone();
                        let tx_inner = tx_out.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if let Ok(res) = check_virustotal(&hash_str, &key).await {
                                let _ = tx_inner.send(ProgressEvent::Log(format!("  [VirusTotal] Result for {}: {}", hash_str, res))).await;
                            }
                        });
                    }
                }
            }
        }
    });

    let tx_err = tx.clone();
    let stderr_task = tokio::spawn(async move {
        while let Ok(Some(line)) = stderr_reader.next_line().await {
            let _ = tx_err.send(ProgressEvent::Log(format!("[STDERR] {}", line))).await;
        }
    });

    let _ = tokio::join!(stdout_task, stderr_task);
    let _ = child.wait().await;

    let _ = tx.send(ProgressEvent::Finished {
        bytes_read: 0,
        bad_sectors: 0,
        hashes: HashMap::new(),
    }).await;

    Ok(())
}

async fn check_abuseip(ip: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let res = client.get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
        
    let json: serde_json::Value = res.json().await?;
    if let Some(data) = json.get("data") {
        let score = data.get("abuseConfidenceScore").and_then(|v| v.as_i64()).unwrap_or(0);
        let country = data.get("countryCode").and_then(|v| v.as_str()).unwrap_or("Unknown");
        Ok(format!("Confidence Score: {}%, Country: {}", score, country))
    } else {
        Ok("No data".to_string())
    }
}

async fn check_virustotal(hash: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let res = client.get(&url)
        .header("x-apikey", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
        
    if res.status().as_u16() == 404 {
        return Ok("Not found in VirusTotal database".to_string());
    }
    
    let json: serde_json::Value = res.json().await?;
    if let Some(stats) = json.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("last_analysis_stats")) {
        let malicious = stats.get("malicious").and_then(|v| v.as_i64()).unwrap_or(0);
        let undetected = stats.get("undetected").and_then(|v| v.as_i64()).unwrap_or(0);
        let total = malicious + undetected;
        if malicious > 0 {
            Ok(format!("⚠️ MALICIOUS: flagged by {}/{} security vendors", malicious, total))
        } else {
            Ok(format!("CLEAN: 0/{} security vendors flagged this file", total))
        }
    } else {
        Ok("No analysis stats available".to_string())
    }
}
