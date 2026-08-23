//! CLI diagnostics (`remoteclient2 doctor`), like PHP `doctor.php` / JS `doctor.js`.

use crate::config::Config;
use crate::grf::GrfArchive;
use crate::ini;
use serde_json::json;
use std::fs;

pub fn run(deep: bool, json_out: bool) -> i32 {
    let config = Config::from_env();
    let mut ok = true;
    let mut infos = Vec::new();
    let mut errors = Vec::new();

    infos.push(format!("Rust remoteclient2 {}", env!("CARGO_PKG_VERSION")));

    let ini_path = config.client_respath.join(&config.client_dataini);
    if ini_path.exists() {
        infos.push(format!("DATA.INI found: {}", ini_path.display()));
        if let Ok(text) = fs::read_to_string(&ini_path) {
            let names = ini::parse_data_ini(&text);
            if names.is_empty() {
                errors.push("DATA.INI has no [Data] GRF entries".into());
                ok = false;
            }
            for name in names {
                let p = config.client_respath.join(&name);
                match GrfArchive::open(&p) {
                    Ok(g) => {
                        infos.push(format!(
                            "Valid GRF: {} (version 0x{:x}, {} files)",
                            g.filename,
                            g.version,
                            g.entries.len()
                        ));
                        if deep {
                            let mut korean = 0usize;
                            for e in &g.entries {
                                if e.original_bytes.iter().any(|&b| b >= 0x80) {
                                    korean += 1;
                                }
                            }
                            infos.push(format!(
                                "  encoding scan: {korean} names with high bytes (likely CP949)"
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!("{}: {e}", p.display()));
                        ok = false;
                    }
                }
            }
        }
    } else {
        errors.push(format!("DATA.INI missing: {}", ini_path.display()));
        ok = false;
    }

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "success": ok,
                "info": infos,
                "errors": errors,
            }))
            .unwrap()
        );
    } else {
        println!("roBrowser Remote Client — Doctor (Rust)\n");
        for i in &infos {
            println!("  ✓ {i}");
        }
        for e in &errors {
            println!("  ✗ {e}");
        }
        println!(
            "\n{}",
            if ok {
                "Validation completed successfully."
            } else {
                "Validation failed."
            }
        );
    }
    if ok {
        0
    } else {
        1
    }
}

pub fn convert_encoding(output: &std::path::Path) -> i32 {
    let config = Config::from_env();
    let ini_path = config.client_respath.join(&config.client_dataini);
    let text = match fs::read_to_string(&ini_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Cannot read DATA.INI: {e}");
            return 1;
        }
    };
    let mut paths = serde_json::Map::new();
    let mut total = 0usize;
    for name in ini::parse_data_ini(&text) {
        let p = config.client_respath.join(&name);
        let Ok(g) = GrfArchive::open(&p) else {
            continue;
        };
        for e in &g.entries {
            total += 1;
            let unicode = crate::paths::decode_cp949(&e.original_bytes);
            let as_latin = String::from_utf8_lossy(&e.original_bytes);
            if unicode != as_latin {
                paths.insert(
                    unicode.replace('\\', "/"),
                    serde_json::Value::String(as_latin.replace('\\', "/")),
                );
            }
        }
    }
    let doc = json!({
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "paths": paths,
        "summary": { "totalFiles": total, "totalMapped": paths.len() }
    });
    if let Some(parent) = output.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(output, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    println!("Wrote {} mappings to {}", paths.len(), output.display());
    0
}
