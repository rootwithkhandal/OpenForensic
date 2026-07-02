# Guide: Enabling Post-Acquisition & Analysis Suite Features

Forgelens Disk Imager adheres to a strict forensic design principle: **separation of capture and analysis**. To keep the live acquisition footprint lightweight and prevent accidental evidence modification during field triage, several post-acquisition analytical features are disabled and hidden by default.

These migrated features include:
1. **Triage SQL Workbench**: Interactive SQLite query inspection over collected triage databases.
2. **Headless CLI Volatility 3 Analysis (`ram` / `volatility`)**: Automated memory analysis and IOC reputation enrichment via AbuseIPDB/VirusTotal.
3. **Memory Forensics Tab (`RAM Analysis`)**: Built-in Volatility 3 UI orchestration and log streaming.
4. **RAM Master-Key Extraction**: In-memory scanning for BitLocker VMKs, LUKS master keys, and Android Gatekeeper CE keys.
5. **Timeline Generation Tab (`Timeline`)**: Chronological reconstruction of file system metadata ($MFT, $LogFile, Ext4 journals).
6. **SIEM & SOC Integration (Wazuh / Splunk HEC)**: Real-time event streaming and direct ingestion of triage databases into SIEM collectors.

For investigators or organizations wishing to deploy Forgelens as an **all-in-one capture and analysis suite**, follow the step-by-step instructions below to re-enable these features.

---

## 1. Re-Enabling Triage SQL Workbench

By default, the Triage SQL Workbench is hidden inside `frontend/index.html` behind an informational banner.

### Step 1: Modify `frontend/index.html`
Locate the Triage Analysis Workbench section inside the `#tab-triage-content` panel (around line 340).

1. Remove the informational warning banner:
```html
<!-- REMOVE OR COMMENT OUT THIS BANNER -->
<div style="margin: 20px 0; padding: 16px; background: rgba(59, 130, 246, 0.1); border: 1px dashed var(--color-border); border-radius: 8px; color: var(--text-muted); text-align: center;">
  ℹ️ <strong>Triage SQL Workbench Disabled & Hidden</strong><br/>
  ...
</div>
```

2. Remove `style="display: none;"` from the workbench wrapper ID:
```diff
- <div id="triage-workbench-disabled-wrapper" style="display: none;">
+ <div id="triage-workbench-disabled-wrapper">
```

---

## 2. Re-Enabling Headless CLI Volatility 3 Analysis (`ram` / `volatility`)

In headless CLI mode, the `ram` subcommand is hidden from clap help menus and returns an informational notice when executed.

### Step 1: Unhide the Subcommand in `src-tauri/src/cli/args.rs`
Locate `Ram` in the `CliSubcommand` enum (around line 160) and remove `hide = true`:
```diff
- /// [DISABLED & HIDDEN] Analyze RAM dump using Volatility 3 engine & Threat Intelligence (Moved to Analysis Suite)
- #[command(name = "ram", alias = "volatility", hide = true)]
+ /// Analyze RAM dump using Volatility 3 engine & Threat Intelligence
+ #[command(name = "ram", alias = "volatility")]
  Ram {
      dump: String,
      profile: String,
      ioc_enrich: bool,
  },
```

### Step 2: Restore Command Execution in `src-tauri/src/cli/runner.rs`
Locate the matching arm for `CliSubcommand::Ram` (around line 364) and replace the disabled handler with the active Volatility execution engine:
```rust
CliSubcommand::Ram {
    dump,
    profile,
    ioc_enrich,
} => rt.block_on(async {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::acquisition::ProgressEvent>(100);

    let log_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                crate::acquisition::ProgressEvent::Log(msg) => {
                    println!("[VOLATILITY] {}", msg);
                }
                crate::acquisition::ProgressEvent::Error(err) => {
                    eprintln!("[ERROR] {}", err);
                }
                _ => {}
            }
        }
    });

    let config = crate::ram_analysis::VolatilityConfig {
        image_path: dump.clone(),
        vol_path: "vol".to_string(),
        profile: profile.clone(),
        enrich_vt: ioc_enrich,
        enrich_mb: false,
        enrich_abuseip: ioc_enrich,
        vt_key: "".to_string(),
        mb_key: "".to_string(),
        abuseip_key: "".to_string(),
    };

    println!("Starting Volatility 3 RAM analysis on {} (profile: {})", dump, profile);
    match crate::ram_analysis::start_volatility_analysis_backend(&config, tx).await {
        Ok(_) => {
            let _ = log_handle.await;
            println!("RAM analysis completed successfully.");
            Ok(())
        }
        Err(e) => {
            let _ = log_handle.await;
            Err(format!("RAM analysis failed: {}", e))
        }
    }
}),
```

---

## 3. Re-Enabling Memory Forensics Tab (`RAM Analysis`)

To restore the graphical UI tab for Volatility 3 RAM Analysis:

### Step 1: Unhide the Tab in `frontend/index.html`
Locate the navigation bar `<div class="tab-navigation">` (around line 33) and remove `style="display: none;"` from the RAM analysis tab button:
```diff
- <button class="tab-btn" id="btn-tab-ram" data-tab="ram" style="display: none;">🧠 RAM Analysis</button>
+ <button class="tab-btn" id="btn-tab-ram" data-tab="ram">🧠 RAM Analysis</button>
```

---

## 4. Re-Enabling RAM Master-Key Extraction

During capture, live memory scanning for encryption keys is disabled. To enable automatic memory extraction of BitLocker VMKs, LUKS master keys, and Android Gatekeeper CE keys:

### Step 1: Restore Memory Scanner in `src-tauri/src/encryption.rs`
Locate `pub fn extract_keys_from_ram` and replace the stubbed error return with the scanning loop:
```rust
pub fn extract_keys_from_ram(ram_dump_path: &str, target_type: Option<EncryptionType>) -> Result<Vec<ExtractedKey>> {
    let mut file = std::fs::File::open(ram_dump_path).map_err(|e| {
        ForgelensError::Backend(format!("Failed to open RAM dump '{}' for key extraction: {}", ram_dump_path, e))
    })?;

    let file_size = file.metadata()?.len();
    let mut extracted = Vec::new();
    let chunk_size = 4 * 1024 * 1024; // 4 MB chunks
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;

    while offset < file_size {
        let n = file.read(&mut buf).map_err(|e| {
            ForgelensError::Backend(format!("Read error at offset 0x{:x} during RAM key scan: {}", offset, e))
        })?;
        if n == 0 { break; }

        let slice = &buf[..n];

        // 1. BitLocker FVK / VMK pool tags
        if target_type.is_none() || target_type == Some(EncryptionType::BitLocker) {
            for (idx, window) in slice.windows(8).enumerate() {
                if window == b"Fvec\x00\x00\x00\x00" || window == b"FveS\x01\x00\x00\x00" {
                    let abs_off = offset + idx as u64;
                    if idx + 48 <= slice.len() {
                        let hex_key = slice[idx + 16..idx + 48].iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        if !hex_key.chars().all(|c| c == '0') {
                            extracted.push(ExtractedKey {
                                key_type: "BitLocker Volume Master Key (VMK)".to_string(),
                                hex_key,
                                offset: abs_off,
                                details: format!("Found BitLocker Fvec memory pool tag at physical offset 0x{:08X}.", abs_off),
                            });
                        }
                    }
                }
            }
        }

        // 2. LUKS AES Master Key structures
        if target_type.is_none() || target_type == Some(EncryptionType::Luks1) || target_type == Some(EncryptionType::Luks2) {
            for (idx, window) in slice.windows(8).enumerate() {
                if window == b"LUKS_KEY" || window == b"dm-crypt" {
                    let abs_off = offset + idx as u64;
                    if idx + 40 <= slice.len() {
                        let hex_key = slice[idx + 8..idx + 40].iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        extracted.push(ExtractedKey {
                            key_type: "LUKS AES Master Key".to_string(),
                            hex_key,
                            offset: abs_off,
                            details: format!("Found dm-crypt / LUKS master key structure at offset 0x{:08X}.", abs_off),
                        });
                    }
                }
            }
        }

        // 3. Android FBE Gatekeeper CE Keys
        if target_type.is_none() || target_type == Some(EncryptionType::AndroidFbe) {
            for (idx, window) in slice.windows(12).enumerate() {
                if window == b"fscrypt_key\x00" || window == b"gatekeeper_k" || window == b"vold_ce_key\x00" {
                    let abs_off = offset + idx as u64;
                    if idx + 44 <= slice.len() {
                        let hex_key = slice[idx + 12..idx + 44].iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        extracted.push(ExtractedKey {
                            key_type: "Android FBE Gatekeeper CE Key".to_string(),
                            hex_key,
                            offset: abs_off,
                            details: format!("Found Android FBE Credential Encrypted (CE) AES-256-XTS key at RAM offset 0x{:08X}.", abs_off),
                        });
                    }
                }
            }
        }

        if n < chunk_size { break; }
        offset += (chunk_size - 64) as u64;
        let _ = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset));
    }

    Ok(extracted)
}
```

---

## 5. Re-Enabling Timeline Generation Tab (`Timeline`)

To restore the Timeline tab for post-acquisition artifact reconstruction:

### Step 1: Unhide the Tab in `frontend/index.html`
Locate the navigation bar `<div class="tab-navigation">` (around line 33) and remove `style="display: none;"` from the Timeline tab button:
```diff
- <button class="tab-btn" id="btn-tab-timeline" data-tab="timeline" style="display: none;">⏱️ Timeline</button>
+ <button class="tab-btn" id="btn-tab-timeline" data-tab="timeline">⏱️ Timeline</button>
```

---

## 6. Re-Enabling SIEM & SOC Integration (Wazuh / Splunk HEC)

During field capture, real-time streaming to SIEM infrastructure is disabled by default to prevent network contamination and maintain air-gapped evidence integrity.

### Step 1: Unhide SIEM Settings in `frontend/index.html`
Locate the SIEM integration section inside `#tab-triage-content` (around line 297) and remove `style="display: none;"` from the wrapper div:
```diff
- <div id="siem-integration-disabled-wrapper" style="display: none;">
+ <div id="siem-integration-disabled-wrapper">
```

### Step 2: Unhide CLI Flags in `src-tauri/src/cli/args.rs`
Locate the Triage subcommand arguments (around line 108) and remove `hide = true` from all SIEM flags (`--siem-export`, `--siem-endpoint`, `--siem-type`, `--siem-token`, `--siem-index`).

### Step 3: Restore SIEM Engine in `src-tauri/src/cli/runner.rs`
In `runner.rs` under `CliSubcommand::Triage` (around line 275), restore the SIEM configuration builder:
```rust
let siem_config = if siem_export {
    let dest_type = match siem_type.to_lowercase().as_str() {
        "wazuh_socket" => crate::siem::SiemDestinationType::WazuhSocket,
        "wazuh_local_log" => crate::siem::SiemDestinationType::WazuhLocalLog,
        _ => crate::siem::SiemDestinationType::SplunkHec,
    };
    Some(crate::siem::SiemConfig {
        destination_type: dest_type,
        endpoint: siem_endpoint,
        auth_token: siem_token,
        index: siem_index,
        enabled: true,
    })
} else {
    None
};
```

---

## Verification & Rebuilding

After modifying the code to re-enable your desired analysis features, verify and compile the suite:

```bash
# 1. Verify Rust backend syntax and type checking
cd src-tauri
cargo check

# 2. Build production release bundle
cd ..
mise run build
```
