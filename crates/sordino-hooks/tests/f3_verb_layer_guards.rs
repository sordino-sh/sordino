//! F3 verb-layer guard tests (committed, not one-shot greps).
//!
//! Two invariants the `/sordino:mask` refactor must hold forever:
//!
//! 1. **Frontmatter gate.** Every command file that can LOOSEN masking (`mask.md` and its
//!    deprecated aliases `disable.md` / `privacy.md`) carries `disable-model-invocation: true`,
//!    so a prompt-injection can never turn masking off via the SlashCommand tool. The honest,
//!    read-only `status.md` must NOT carry that flag (the model has to be able to read state).
//!
//! 2. **Banned false-restart copy.** No user-facing surface (plugin commands + scripts + both
//!    READMEs) or the BUILT `sordino-hooks --help` may claim a masking-off state "lifts / is
//!    lost / is cleared on restart", is "not persisted", or is "session-live". The truth (F2):
//!    an off stays off until you re-enable or it auto-re-arms; restarting Claude Code — which the
//!    daemon outlives — does NOT change that. Implemented as a proximity scan (`restart` within
//!    `N` chars of a banned anchor) so `\`-wrapped or variant-worded misleads are still caught.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The `sordino-plugin` dir, resolved from THIS crate's manifest dir
/// (`crates/sordino-hooks` -> `../../sordino-plugin`), so the guard travels with the repo.
fn plugin_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("sordino-plugin")
}

/// The repo root (`crates/sordino-hooks` -> `../..`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Extract the YAML-ish frontmatter block (between the first two `---` fences) of a command file.
fn frontmatter(md: &str) -> &str {
    let body = md.strip_prefix("---").unwrap_or(md);
    match body.find("\n---") {
        Some(end) => &body[..end],
        None => body,
    }
}

#[test]
fn command_frontmatter_gating_is_correct() {
    let cmds = plugin_dir().join("commands");

    // status.md is the model-readable honest read — it must stay UN-gated.
    let status = std::fs::read_to_string(cmds.join("status.md")).expect("read status.md");
    assert!(
        !frontmatter(&status).contains("disable-model-invocation"),
        "status.md MUST NOT carry disable-model-invocation — the model has to be able to read \
         masking state. Folding it under a gated file makes state unreadable."
    );

    // Every loosen surface MUST be gated true.
    for name in ["mask.md", "disable.md", "privacy.md"] {
        let text = std::fs::read_to_string(cmds.join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        let fm = frontmatter(&text);
        assert!(
            fm.contains("disable-model-invocation: true"),
            "{name} can LOOSEN masking but is missing `disable-model-invocation: true` — that is a \
             model-invocable disable-masking laundering path."
        );
    }
}

/// Banned anchors: a masking-off state that supposedly ends/vanishes because of a restart, or is
/// framed as ephemeral. Lower-cased comparison.
const BANNED_ANCHORS: [&str; 5] = ["lift", "lost", "cleared", "not persisted", "session-live"];
/// Proximity window (chars) around each `restart` occurrence.
const N: usize = 100;

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Return every "`restart` within N chars of a banned anchor" hit in `text`, as human-readable
/// context snippets for the failure message.
fn false_restart_hits(label: &str, text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let needle = "restart";
    let mut hits = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(needle) {
        let idx = from + rel;
        let ws = floor_boundary(&lower, idx.saturating_sub(N));
        let we = ceil_boundary(&lower, (idx + needle.len() + N).min(lower.len()));
        let window = &lower[ws..we];
        for anchor in BANNED_ANCHORS {
            if window.contains(anchor) {
                let cs = floor_boundary(&lower, idx.saturating_sub(50));
                let ce = ceil_boundary(&lower, (idx + needle.len() + 50).min(lower.len()));
                hits.push(format!("{label}: 'restart' near '{anchor}' -> …{}…", &lower[cs..ce]));
            }
        }
        from = idx + needle.len();
    }
    hits
}

#[test]
fn no_false_restart_copy_in_surfaces_or_help() {
    let mut files: Vec<PathBuf> = Vec::new();

    // Plugin command + script surfaces.
    for sub in ["commands", "scripts"] {
        let dir = plugin_dir().join(sub);
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {sub}: {e}")) {
            let path = entry.expect("dir entry").path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("md") | Some("sh") => files.push(path),
                _ => {}
            }
        }
    }
    // Both READMEs.
    files.push(plugin_dir().join("README.md"));
    files.push(repo_root().join("README.md"));

    let mut hits = Vec::new();
    for f in &files {
        if let Ok(text) = std::fs::read_to_string(f) {
            hits.extend(false_restart_hits(&f.display().to_string(), &text));
        }
    }

    // The BUILT `--help` output (doc-comments are baked into it). Scan the help pages that carry
    // the masking-off lifecycle copy.
    let bin = env!("CARGO_BIN_EXE_sordino-hooks");
    for args in [
        vec!["--help"],
        vec!["disable", "--help"],
        vec!["config", "--help"],
        vec!["config", "on", "--help"],
    ] {
        let out = Command::new(bin)
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("run {bin} {args:?}: {e}"));
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        hits.extend(false_restart_hits(&format!("--help {args:?}"), &combined));
    }

    assert!(
        hits.is_empty(),
        "false-restart / ephemeral-off copy must be ZERO; found {} hit(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}
