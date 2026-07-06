//! Persistence for monitor-driven custom-mask edits.
//!
//! The monitor's "custom mask" affordance edits the LIVE engine config in memory.
//! Without persistence, the next `POST /sordino/reload` (e.g. triggered by an
//! unrelated `/sordino:privacy` file edit) re-reads the config files and DESTROYS
//! the in-memory addition. So we also write each addition to the project's
//! `sordino.local.toml` (the gitignored Local scope the CLI uses), via the same
//! `toml_edit` document round-trip the hooks' `edit_scope_file` uses — comments and
//! formatting in the file are preserved.
//!
//! If the proxy cannot reach/write that path (no project root, or an I/O error),
//! the caller keeps the in-memory change and surfaces a `session_only` signal so the
//! UI can tell the operator the mask is live-but-not-persisted.

use std::path::{Path, PathBuf};

use sordino_engine::CustomReplacement;

/// Where the proxy persists Local-scope edits: `<project_root>/sordino.local.toml`.
/// `None` when there is no usable project root (so we fall back to session-only).
pub fn local_scope_path(project_root: &str) -> Option<PathBuf> {
    if project_root.is_empty() {
        return None;
    }
    Some(Path::new(project_root).join("sordino.local.toml"))
}

/// Append one `[[engine.custom_replacements]]` entry to the project's
/// `sordino.local.toml`, preserving any existing content/formatting. Returns the
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
/// `pattern` (and `entity_type`) from `sordino.local.toml`. Returns `true` if an
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

/// Write the project's `sordino.local.toml` `[engine.allow_list]` `exact` /
/// `exact_ci` arrays to the **full effective non-default sets** passed in, replacing
/// whatever was there. Returns the written path.
///
/// Why the *full* set, not an append: config layers merge **arrays wholesale**
/// (user < project < local), and `build_allow_list` reads only the final merged
/// `exact`/`exact_ci`. Appending one value to local would DROP project/user entries
/// on the next `/sordino/reload`, and a local-only removal couldn't durably re-mask a
/// value seeded by a lower layer. Making local authoritative (the complete effective
/// set) preserves lower-layer entries (they're already in the live set the caller
/// derives this from) AND lets re-mask durably drop any of them. `patterns` is left
/// untouched — reveal/remask never touch regex allow-patterns. Comments/formatting in
/// the file are preserved via the `toml_edit` round-trip.
pub fn persist_local_allow_lists(
    project_root: &str,
    exact: &[String],
    exact_ci: &[String],
) -> Result<PathBuf, String> {
    let path = local_scope_path(project_root)
        .ok_or_else(|| "no project root to persist to".to_string())?;

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;

    // Indexing auto-vivifies `[engine]` and `[engine.allow_list]` as tables without
    // clobbering existing sibling keys; assigning the arrays replaces them wholesale.
    doc["engine"]["allow_list"]["exact"] = toml_edit::value(str_array(exact));
    doc["engine"]["allow_list"]["exact_ci"] = toml_edit::value(str_array(exact_ci));

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

/// A TOML array of strings (sorted for stable diffs).
fn str_array(items: &[String]) -> toml_edit::Array {
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    let mut arr = toml_edit::Array::new();
    for s in sorted {
        arr.push(s.as_str());
    }
    arr
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
        let dir = std::env::temp_dir().join(format!("sordino-persist-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let root = dir.to_string_lossy().to_string();

        // Seed an existing file with a comment to prove formatting is preserved.
        let path = dir.join("sordino.local.toml");
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
        // Allow-list persistence likewise needs a root.
        assert!(persist_local_allow_lists("", &["R".into()], &[]).is_err());
    }

    // The audit #1/#2 regression: a reveal must persist the FULL effective set so a
    // lower-layer (project) entry survives the next reload, and a re-mask must durably
    // drop a value even when it was seeded by a lower layer (local is authoritative
    // because layered arrays replace wholesale).
    #[test]
    fn allow_list_persist_survives_reload_and_remask_is_durable() {
        use crate::config::{ConfigLayers, reload_engine};

        let dir = std::env::temp_dir().join(format!("sordino-al-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let root = dir.to_string_lossy().to_string();
        let project = dir.join("sordino.toml");
        let local = dir.join("sordino.local.toml");

        // A project-scope allow-list entry `P` (a pre-configured passthrough).
        std::fs::write(
            &project,
            "[engine.allow_list]\nexact = [\"projvalue\"]\n",
        )
        .unwrap();
        // Seed the local file with a comment to prove formatting is preserved.
        std::fs::write(&local, "# local scope\n").unwrap();

        let layers = ConfigLayers {
            user: std::path::PathBuf::from("/nonexistent/sordino/config.toml"),
            project: Some(project.clone()),
            local: Some(local.clone()),
        };

        // Reveal `R`: the caller derives the full effective non-default set (`P` is
        // already live + `R` the new reveal) and writes it to local, authoritative.
        persist_local_allow_lists(&root, &["projvalue".into(), "revealed".into()], &[]).unwrap();
        let text = std::fs::read_to_string(&local).unwrap();
        assert!(text.contains("# local scope"), "comment preserved: {text}");

        let cfg = reload_engine(&layers).unwrap();
        assert!(cfg.allow_list.is_allowed("projvalue"), "project entry survives reveal");
        assert!(cfg.allow_list.is_allowed("revealed"), "revealed entry is live");

        // Re-mask `P`: write the full effective set MINUS `projvalue`. Because local
        // replaces the merged array wholesale, the lower-layer value is durably gone.
        persist_local_allow_lists(&root, &["revealed".into()], &[]).unwrap();
        let cfg = reload_engine(&layers).unwrap();
        assert!(!cfg.allow_list.is_allowed("projvalue"), "remask durably drops the project value");
        assert!(cfg.allow_list.is_allowed("revealed"), "the other reveal stays");
        // The four common-word defaults are always re-seeded.
        assert!(cfg.allow_list.is_allowed("Anthropic"));
        assert!(cfg.allow_list.is_allowed("localhost"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
