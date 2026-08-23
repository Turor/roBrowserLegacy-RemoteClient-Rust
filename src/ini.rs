//! Minimal INI reader for Gravity `DATA.INI` (`[Data]` then `0=custom.grf`).

pub fn parse_data_ini(text: &str) -> Vec<String> {
    let mut section: Option<String> = None;
    let mut items: Vec<(u32, String)> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                section = Some(name.trim().to_string());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let in_data = section
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("data"))
            .unwrap_or(false);
        if !in_data {
            continue;
        }
        let Ok(idx) = k.trim().parse::<u32>() else {
            continue;
        };
        items.push((idx, v.trim().to_string()));
    }

    items.sort_by_key(|(i, _)| *i);
    items.into_iter().map(|(_, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_section_order() {
        let text = "[Data]\n2=data.grf\n0=custom.grf\n1=rdata.grf\n";
        assert_eq!(
            parse_data_ini(text),
            vec!["custom.grf", "rdata.grf", "data.grf"]
        );
    }
}
