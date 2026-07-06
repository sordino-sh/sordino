use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[derive(Clone, Debug)]
pub(crate) struct ScrubOptions {
    pub values: Vec<String>,
    pub replacement: String,
    pub drop_thinking: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ScrubReport {
    pub redactions: usize,
    pub removed_thinking_records: usize,
    pub relinked_records: usize,
    pub backup_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct Record {
    value: Value,
    uuid: Option<String>,
    parent_uuid: Option<String>,
}

pub(crate) fn scrub_file(path: &Path, opts: &ScrubOptions, dry_run: bool) -> Result<ScrubReport> {
    validate_options(opts)?;
    let original =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let (mut output, mut report) = scrub_jsonl(&original, opts)?;

    if dry_run {
        return Ok(report);
    }

    if output.is_empty() {
        bail!("scrub would produce an empty transcript; refusing to write");
    }
    if !output.ends_with('\n') {
        output.push('\n');
    }

    let backup = backup_path(path);
    std::fs::copy(path, &backup)
        .with_context(|| format!("creating backup {}", backup.display()))?;

    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("jsonl")
    ));
    std::fs::write(&tmp, output).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        format!(
            "replacing {} with scrubbed transcript from {}",
            path.display(),
            tmp.display()
        )
    })?;
    report.backup_path = Some(backup);
    Ok(report)
}

fn validate_options(opts: &ScrubOptions) -> Result<()> {
    if opts.values.iter().all(|v| v.is_empty()) {
        bail!("at least one non-empty --value is required");
    }
    if opts.replacement.is_empty() {
        bail!("replacement must not be empty");
    }
    Ok(())
}

fn scrub_jsonl(input: &str, opts: &ScrubOptions) -> Result<(String, ScrubReport)> {
    validate_options(opts)?;

    let mut records = parse_records(input)?;
    let values: Vec<&str> = opts
        .values
        .iter()
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .collect();
    let mut report = ScrubReport::default();
    let mut earliest_redacted = None;

    for (idx, record) in records.iter_mut().enumerate() {
        let count = redact_strings(&mut record.value, &values, &opts.replacement);
        if count > 0 {
            report.redactions += count;
            earliest_redacted.get_or_insert(idx);
        }
    }

    let remove = if opts.drop_thinking {
        let start = earliest_redacted.unwrap_or(records.len());
        records
            .iter()
            .enumerate()
            .filter_map(|(idx, record)| {
                (idx >= start && is_standalone_thinking_record(&record.value)).then_some(idx)
            })
            .collect::<HashSet<_>>()
    } else {
        HashSet::new()
    };
    report.removed_thinking_records = remove.len();

    if !remove.is_empty() {
        report.relinked_records = relink_parents(&mut records, &remove);
    }

    let mut out = String::new();
    for (idx, record) in records.into_iter().enumerate() {
        if remove.contains(&idx) {
            continue;
        }
        out.push_str(&serde_json::to_string(&record.value)?);
        out.push('\n');
    }

    Ok((out, report))
}

fn parse_records(input: &str) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    for (line_no, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("parsing JSONL line {}", line_no + 1))?;
        let uuid = value
            .get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let parent_uuid = value
            .get("parentUuid")
            .and_then(Value::as_str)
            .map(str::to_string);
        records.push(Record {
            value,
            uuid,
            parent_uuid,
        });
    }
    if records.is_empty() {
        bail!("transcript has no JSON records");
    }
    Ok(records)
}

fn redact_strings(value: &mut Value, needles: &[&str], replacement: &str) -> usize {
    match value {
        Value::String(s) => {
            let mut count = 0;
            for needle in needles {
                if needle.is_empty() {
                    continue;
                }
                let hits = s.matches(needle).count();
                if hits > 0 {
                    *s = s.replace(needle, replacement);
                    count += hits;
                }
            }
            count
        }
        Value::Array(items) => items
            .iter_mut()
            .map(|item| redact_strings(item, needles, replacement))
            .sum(),
        Value::Object(map) => map
            .values_mut()
            .map(|item| redact_strings(item, needles, replacement))
            .sum(),
        _ => 0,
    }
}

fn is_standalone_thinking_record(value: &Value) -> bool {
    let Some(message) = value.get("message") else {
        return false;
    };
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return false;
    }
    let Some(content) = message.get("content").and_then(Value::as_array) else {
        return false;
    };
    !content.is_empty()
        && content.iter().all(|block| {
            matches!(
                block.get("type").and_then(Value::as_str),
                Some("thinking" | "redacted_thinking")
            )
        })
}

fn relink_parents(records: &mut [Record], remove: &HashSet<usize>) -> usize {
    let uuid_to_idx = records
        .iter()
        .enumerate()
        .filter_map(|(idx, r)| r.uuid.as_ref().map(|uuid| (uuid.clone(), idx)))
        .collect::<HashMap<_, _>>();

    let mut changed = 0;
    for idx in 0..records.len() {
        if remove.contains(&idx) {
            continue;
        }
        let Some(parent) = records[idx].parent_uuid.clone() else {
            continue;
        };
        let Some(new_parent) = nearest_surviving_parent(&parent, records, &uuid_to_idx, remove)
        else {
            continue;
        };
        if new_parent != parent {
            records[idx].parent_uuid = Some(new_parent.clone());
            if let Value::Object(map) = &mut records[idx].value {
                map.insert("parentUuid".to_string(), Value::String(new_parent));
            }
            changed += 1;
        }
    }
    changed
}

fn nearest_surviving_parent(
    parent: &str,
    records: &[Record],
    uuid_to_idx: &HashMap<String, usize>,
    remove: &HashSet<usize>,
) -> Option<String> {
    let mut current = parent.to_string();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return None;
        }
        let Some(&idx) = uuid_to_idx.get(&current) else {
            return Some(current);
        };
        if !remove.contains(&idx) {
            return Some(current);
        }
        match &records[idx].parent_uuid {
            Some(next) => current = next.clone(),
            None => return None,
        }
    }
}

fn backup_path(path: &Path) -> PathBuf {
    for n in 0..1000 {
        let suffix = if n == 0 {
            "bak".to_string()
        } else {
            format!("bak.{n}")
        };
        let candidate = PathBuf::from(format!("{}.{}", path.display(), suffix));
        if !candidate.exists() {
            return candidate;
        }
    }
    path.with_extension("bak")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ScrubOptions {
        ScrubOptions {
            values: vec!["alice@example.com".to_string()],
            replacement: "[REDACTED]".to_string(),
            drop_thinking: true,
        }
    }

    #[test]
    fn redacts_strings_and_removes_later_standalone_thinking() {
        let input = r#"{"uuid":"u1","message":{"role":"user","content":[{"type":"text","text":"email alice@example.com"}]}}
{"uuid":"t1","parentUuid":"u1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"opaque"}]}}
{"uuid":"a1","parentUuid":"t1","message":{"role":"assistant","content":[{"type":"text","text":"sent to alice@example.com"}]}}
"#;

        let (out, report) = scrub_jsonl(input, &opts()).unwrap();

        assert_eq!(report.redactions, 2);
        assert_eq!(report.removed_thinking_records, 1);
        assert_eq!(report.relinked_records, 1);
        assert!(!out.contains("alice@example.com"));
        assert!(!out.contains(r#""type":"thinking""#));
        assert!(out.contains(r#""parentUuid":"u1""#));
    }

    #[test]
    fn keeps_thinking_before_earliest_redaction() {
        let input = r#"{"uuid":"t0","message":{"role":"assistant","content":[{"type":"thinking","thinking":"opaque"}]}}
{"uuid":"u1","parentUuid":"t0","message":{"role":"user","content":"alice@example.com"}}
"#;

        let (out, report) = scrub_jsonl(input, &opts()).unwrap();

        assert_eq!(report.removed_thinking_records, 0);
        assert!(out.contains(r#""type":"thinking""#));
    }

    #[test]
    fn walks_transitively_through_deleted_parent_chain() {
        let input = r#"{"uuid":"u1","message":{"role":"user","content":"alice@example.com"}}
{"uuid":"t1","parentUuid":"u1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"one"}]}}
{"uuid":"t2","parentUuid":"t1","message":{"role":"assistant","content":[{"type":"redacted_thinking","data":"two"}]}}
{"uuid":"a1","parentUuid":"t2","message":{"role":"assistant","content":[{"type":"text","text":"done"}]}}
"#;

        let (out, report) = scrub_jsonl(input, &opts()).unwrap();

        assert_eq!(report.removed_thinking_records, 2);
        assert_eq!(report.relinked_records, 1);
        assert!(out.contains(r#""parentUuid":"u1""#));
        assert!(!out.contains(r#""parentUuid":"t2""#));
    }
}
