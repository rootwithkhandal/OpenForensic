use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;
use crate::error::Result;
use crate::hasher::HashAlgorithm;

pub struct ReportData {
    pub case_number: String,
    pub examiner: String,
    pub evidence_id: String,
    pub notes: String,
    pub imaging_mode: String,
    pub format: String,
    pub source_device: String,
    pub source_size: u64,
    pub source_model: String,
    pub source_serial: String,
    pub dest_file: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub bad_sectors: u64,
    pub pre_hashes: HashMap<HashAlgorithm, String>,
    pub hashes: HashMap<HashAlgorithm, String>,
}

fn to_ist_rfc2822(dt: &chrono::DateTime<chrono::Utc>) -> String {
    let ist_offset = chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
    dt.with_timezone(&ist_offset).to_rfc2822()
}

pub fn generate_txt_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "==================================================")?;
    writeln!(file, "          FORGELENS DISK IMAGER REPORT            ")?;
    writeln!(file, "==================================================")?;
    writeln!(file, "Case Number:     {}", data.case_number)?;
    writeln!(file, "Examiner:        {}", data.examiner)?;
    writeln!(file, "Evidence ID:     {}", data.evidence_id)?;
    writeln!(file, "Notes/Summary:   {}", data.notes)?;
    writeln!(file, "Report Date:     {}", to_ist_rfc2822(&chrono::Utc::now()))?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "IMAGING PARAMETERS")?;
    writeln!(file, "  Mode:          {}", data.imaging_mode)?;
    writeln!(file, "  Target Format: {}", data.format)?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "SOURCE DETAILS")?;
    writeln!(file, "  Device Path:   {}", data.source_device)?;
    writeln!(file, "  Model:         {}", data.source_model)?;
    writeln!(file, "  Serial Number: {}", data.source_serial)?;
    writeln!(file, "  Total Size:    {} bytes ({:.2} GB)", data.source_size, data.source_size as f64 / 1_000_000_000.0)?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "ACQUISITION DETAILS")?;
    writeln!(file, "  Destination:   {}", data.dest_file)?;
    writeln!(file, "  Start Time:    {}", to_ist_rfc2822(&data.start_time))?;
    writeln!(file, "  End Time:      {}", to_ist_rfc2822(&data.end_time))?;
    let duration = data.end_time.signed_duration_since(data.start_time);
    writeln!(file, "  Duration:      {}h {}m {}s", duration.num_hours(), duration.num_minutes() % 60, duration.num_seconds() % 60)?;
    writeln!(file, "  Bad Sectors:   {}", data.bad_sectors)?;
    
    if !data.pre_hashes.is_empty() {
        writeln!(file, "--------------------------------------------------")?;
        writeln!(file, "PRE-ACQUISITION HASHES")?;
        for (algo, hash_val) in &data.pre_hashes {
            writeln!(file, "  {}: {}", algo, hash_val)?;
        }
    }

    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "VERIFICATION HASHES (POST-ACQUISITION)")?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "  {}: {}", algo, hash_val)?;
    }

    writeln!(file, "--------------------------------------------------")?;
    
    // Perform Verification matching
    let mut verified = true;
    if !data.pre_hashes.is_empty() {
        writeln!(file, "INTEGRITY VERIFICATION LOG")?;
        for (algo, post_hash) in &data.hashes {
            if let Some(pre_hash) = data.pre_hashes.get(algo) {
                if pre_hash == post_hash {
                    writeln!(file, "  {}: MATCHED (Integrity Confirmed)", algo)?;
                } else {
                    writeln!(file, "  {}: MISMATCHED (WARNING: Integrity Compromised!)", algo)?;
                    verified = false;
                }
            }
        }
        writeln!(file, "--------------------------------------------------")?;
    }

    if verified {
        writeln!(file, "Acquisition Status: COMPLETED / VERIFIED")?;
    } else {
        writeln!(file, "Acquisition Status: WARNING - HASH MISMATCH")?;
    }
    writeln!(file, "==================================================")?;
    Ok(())
}

pub fn generate_html_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    
    let duration = data.end_time.signed_duration_since(data.start_time);
    let hours = duration.num_hours();
    let minutes = duration.num_minutes() % 60;
    let seconds = duration.num_seconds() % 60;
    let duration_str = format!("{}h {}m {}s", hours, minutes, seconds);
    let short_duration_str = format!("{}h {}m", hours, minutes);
    
    let duration_secs = duration.num_seconds().max(1);
    let speed_mb = (data.source_size as f64 / 1_048_576.0) / (duration_secs as f64);
    
    let mut hashes_html = String::new();
    let mut verified_all = true;
    for (algo, post_hash) in &data.hashes {
        let pre_hash = data.pre_hashes.get(algo).cloned().unwrap_or_else(|| "N/A".to_string());
        let matched = if pre_hash == *post_hash {
            true
        } else {
            verified_all = false;
            false
        };
        
        let match_text = if matched {
            "MATCHED — Integrity Confirmed"
        } else if pre_hash == "N/A" {
            "NO PRE-HASH — Verify Manually"
        } else {
            "<span style=\"color: var(--warn);\">MISMATCH — Integrity Compromised</span>"
        };

        hashes_html.push_str(&format!(r#"
      <div class="hash-row">
        <div class="hash-algo">{algo}</div>
        <div class="hash-content">
          <div class="hash-label">Pre-Acquisition (Source Device)</div>
          <div class="hash-value">{pre_hash}</div>
          <div class="hash-label" style="margin-top:8px;">Post-Acquisition (Image File)</div>
          <div class="hash-value">{post_hash}</div>
          <div class="hash-match">{match_text}</div>
        </div>
      </div>
"#, algo=algo, pre_hash=pre_hash, post_hash=post_hash, match_text=match_text));
    }

    let status_badge = if verified_all {
        "Completed &amp; Verified"
    } else {
        "Warning — Mismatch"
    };

    // ponytail: minimalist HTML report without 600 lines of CSS boilerplate
    let template = r#"<!DOCTYPE html><html><body>
<h1>ForgeLens Forensic Report — {{CASE_NUMBER}}</h1>
<p><b>Status:</b> {{STATUS_BADGE}}</p>
<p><b>Imaging Mode:</b> {{IMAGING_MODE}} | <b>Format:</b> {{FORMAT}}</p>
<p><b>Duration:</b> {{DURATION_FULL}}</p>
<p><b>Bad Sectors:</b> {{BAD_SECTORS}}</p>
<h3>Hash Verification</h3>
{{HASHES_HTML}}
</body></html>"#;

    let html_content = template
        .replace("{{CASE_NUMBER}}", &data.case_number)
        .replace("{{IMAGING_MODE}}", &data.imaging_mode)
        .replace("{{FORMAT}}", &data.format)
        .replace("{{STATUS_BADGE}}", status_badge)
        .replace("{{REPORT_DATE}}", &to_ist_rfc2822(&chrono::Utc::now()))
        .replace("{{EXAMINER}}", &data.examiner)
        .replace("{{EVIDENCE_ID}}", &data.evidence_id)
        .replace("{{SOURCE_SIZE_GB}}", &format!("{:.2}", data.source_size as f64 / 1_000_000_000.0))
        .replace("{{SOURCE_SIZE_BYTES}}", &data.source_size.to_string())
        .replace("{{DURATION_SHORT}}", &short_duration_str)
        .replace("{{DURATION_FULL}}", &duration_str)
        .replace("{{BAD_SECTORS}}", &data.bad_sectors.to_string())
        .replace("{{SPEED_MB}}", &format!("{:.1}", speed_mb))
        .replace("{{NOTES}}", &data.notes)
        .replace("{{SOURCE_DEVICE}}", &data.source_device)
        .replace("{{SOURCE_MODEL}}", &data.source_model)
        .replace("{{SOURCE_SERIAL}}", &data.source_serial)
        .replace("{{DEST_FILE}}", &data.dest_file)
        .replace("{{START_TIME}}", &to_ist_rfc2822(&data.start_time))
        .replace("{{END_TIME}}", &to_ist_rfc2822(&data.end_time))
        .replace("{{HASHES_HTML}}", &hashes_html);

    file.write_all(html_content.as_bytes())?;
    Ok(())
}

pub fn generate_json_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    let mut hash_map = HashMap::new();
    for (k, v) in &data.hashes {
        hash_map.insert(k.to_string(), v.clone());
    }
    let data_json = serde_json::json!({
        "case_number": data.case_number,
        "examiner": data.examiner,
        "evidence_id": data.evidence_id,
        "notes": data.notes,
        "imaging_mode": data.imaging_mode,
        "format": data.format,
        "source_device": data.source_device,
        "source_size": data.source_size,
        "source_model": data.source_model,
        "source_serial": data.source_serial,
        "dest_file": data.dest_file,
        "start_time": to_ist_rfc2822(&data.start_time),
        "end_time": to_ist_rfc2822(&data.end_time),
        "bad_sectors": data.bad_sectors,
        "hashes": hash_map
    });
    let content = serde_json::to_string_pretty(&data_json)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub fn generate_csv_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "Timestamp,Event,Details")?;
    writeln!(file, "\"{}\",\"Acquisition Started\",\"Source: {}\"", to_ist_rfc2822(&data.start_time), data.source_device)?;
    writeln!(file, "\"{}\",\"Acquisition Finished\",\"Destination: {}\"", to_ist_rfc2822(&data.end_time), data.dest_file)?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "\"{}\",\"Hash Computed\",\"{}: {}\"", to_ist_rfc2822(&data.end_time), algo, hash_val)?;
    }
    Ok(())
}

