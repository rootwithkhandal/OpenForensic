use std::path::Path;
use yara_x::{Compiler, Rules};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub offset: u64,
    pub tags: Vec<String>,
}

pub fn load_rules_from_dir(dir: &Path) -> Result<Rules, String> {
    let mut compiler = Compiler::new();
    let mut rules_loaded = 0;

    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("Failed to read YARA directory: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        
        if path.is_file() {
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                let src = std::fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
                
                if let Err(e) = compiler.add_source(src.as_str()) {
                    println!("[WARNING] YARA compilation error in {}: {}", path.display(), e);
                    // We continue to try loading other rules even if one fails
                } else {
                    rules_loaded += 1;
                }
            }
        }
    }

    if rules_loaded == 0 {
        return Err("No valid YARA rules loaded from directory.".to_string());
    }

    Ok(compiler.build())
}

pub fn scan_chunk(rules: &Rules, data: &[u8], offset: u64) -> Vec<YaraMatch> {
    let mut scanner = yara_x::Scanner::new(rules);
    let mut matches = Vec::new();

    if let Ok(results) = scanner.scan(data) {
        for rule in results.matching_rules() {
            let tags = rule.tags().map(|t| t.identifier().to_string()).collect();
            matches.push(YaraMatch {
                rule_name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                offset,
                tags,
            });
        }
    }

    matches
}
