//! Persistence for monitor-driven custom-mask edits.
//!
//! The monitor's "custom mask" affordance edits the LIVE engine config in memory.
//! Without persistence, the next `POST /zlauder/reload` (e.g. triggered by an
//! unrelated `/zlauder:privacy` file edit) re-reads the config files and DESTROYS
//! the in-memory addition. So we also write each addition to the project's
//! `zlauder.local.toml` (the gitignored Local scope the CLI uses), via the same
//! `toml_edit` document round-trip the hooks' `edit_scope_file` uses — comments and
//! formatting in the file are preserved.
//!
//! If the proxy cannot reach/write that path (no project root, or an I/O error),
//! the caller keeps the in-memory change and surfaces a `session_only` signal so the
//! UI can tell the operator the mask is live-but-not-persisted.

use std::path::{Path, PathBuf};

use zlauder_engine::CustomReplacement;

/// Where the proxy persists Local-scope edits: `<project_root>/zlauder.local.toml`.
/// `None` when there is no usable project root (so we fall back to session-only).
pub fn local_scope_path(project_root: &str) -> Option<PathBuf> {
    if project_root.is_empty() {
        return None;
    }
    Some(Path::new(project_root).join("zlauder.local.toml"))
}

/// Append one `[[engine.custom_replacements]]` entry to the project's
/// `zlauder.local.toml`, preserving any existing content/formatting. Returns the
/// written path on success.
///
/// Mirrors the hooks' `edit_scope_file`: parse the existing doc (or start fresh),
/// ensure `[engine]`, then push onto the `custom_replacements` array-of-tables.
pub fn persist_custom_replacement(
    project_root: &str,
    rule: &CustomReplacement,
) -> Result<PathBuf, String> {
    let path = local_scope_path(project_root)
        .ok_or_else(|| "no project root to persist to".to_string())?;

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;

    if !doc.contains_key("engine") {
        doc["engine"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Find or create the array-of-tables `engine.custom_replacements`.
    let engine = doc["engine"]
        .as_table_mut()
        .ok_or_else(|| "`engine` is not a table".to_string())?;
    if engine.get("custom_replacements").is_none() {
        engine.insert(
            "custom_replacements",
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
        );
    }
    let arr = engine
        .get_mut("custom_replacements")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| "`engine.custom_replacements` is not an array of tables".to_string())?;

    arr.push(custom_replacement_table(rule));

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, doc.to_string())
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Remove the FIRST persisted `[[engine.custom_replacements]]` entry matching
/// `pattern` (and `entity_type`) from `zlauder.local.toml`. Returns `true` if an
/// entry was removed and the file rewritten, `false` if no match was found (or the
/// file/array is absent). This is the persistence side of the UI's removal action;
/// the caller is responsible for the live-config removal.
pub fn remove_custom_replacement(
    project_root: &str,
    pattern: &str,
    entity_type: &str,
) -> Result<bool, String> {
    let Some(path) = local_scope_path(project_root) else {
        return Ok(false);
    };
    let Ok(existing) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;

    let Some(arr) = doc
        .get_mut("engine")
        .and_then(|e| e.get_mut("custom_replacements"))
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return Ok(false);
    };

    let mut removed = false;
    arr.retain(|t| {
        if removed {
            return true;
        }
        let p = t.get("pattern").and_then(|v| v.as_str());
        let e = t.get("entity_type").and_then(|v| v.as_str());
        if p == Some(pattern) && e == Some(entity_type) {
            removed = true;
            false
        } else {
            true
        }
    });

    if removed {
        std::fs::write(&path, doc.to_string())
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(removed)
}

/// Serialize one [`CustomReplacement`] as a `toml_edit::Table`, emitting only the
/// fields the monitor's custom-mask sets (so the persisted entry stays minimal and
/// readable). The remaining fields take their serde defaults on reload.
fn custom_replacement_table(rule: &CustomReplacement) -> toml_edit::Table {
    let mut t = toml_edit::Table::new();
    t.insert("pattern", toml_edit::value(rule.pattern.as_str()));
    t.insert("entity_type", toml_edit::value(rule.entity_type.as_str()));
    t.insert("is_regex", toml_edit::value(rule.is_regex));
    t.insert("case_sensitive", toml_edit::value(rule.case_sensitive));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, et: &str) -> CustomReplacement {
        CustomReplacement {
            pattern: pattern.to_string(),
            entity_type: et.to_string(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: false,
            token: None,
            apply_to_surfaces: None,
        }
    }

    #[test]
    fn persists_then_removes_roundtrip() {
        let dir = std::env::temp_dir().join(format!("zlauder-persist-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let root = dir.to_string_lossy().to_string();

        // Seed an existing file with a comment to prove formatting is preserved.
        let path = dir.join("zlauder.local.toml");
        std::fs::write(&path, "# keep me\n[engine]\nscore_threshold = 0.5\n").unwrap();

        let written = persist_custom_replacement(&root, &rule("ACME-123", "PROJECT_CODE")).unwrap();
        assert_eq!(written, path);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# keep me"), "comment preserved: {text}");
        assert!(text.contains("ACME-123"));
        assert!(text.contains("PROJECT_CODE"));
        assert!(text.contains("score_threshold"), "prior key preserved");

        // A second add appends rather than replaces.
        persist_custom_replacement(&root, &rule("BETA-9", "PROJECT_CODE")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("ACME-123") && text.contains("BETA-9"));

        // Remove the first; the second survives.
        let removed = remove_custom_replacement(&root, "ACME-123", "PROJECT_CODE").unwrap();
        assert!(removed);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("ACME-123"));
        assert!(text.contains("BETA-9"));

        // Removing a non-existent entry is a no-op `false`.
        assert!(!remove_custom_replacement(&root, "NOPE", "X").unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_project_root_is_session_only() {
        assert!(local_scope_path("").is_none());
        assert!(persist_custom_replacement("", &rule("X", "Y")).is_err());
        // Removal with no root is a clean false (nothing persisted to remove).
        assert!(!remove_custom_replacement("", "X", "Y").unwrap());
    }
}
