//! Bakes a per-build identity (`ZLAUDER_BUILD`) into the crate so both binaries
//! can tell whether a long-lived proxy was built from the same source. It's the
//! git short SHA (12), suffixed `-dirty` if the tree had uncommitted changes, or
//! `unknown` when git isn't available (e.g. an out-of-repo build). Released
//! binaries get the tag's commit SHA (CI builds from a clean checkout), so a
//! plugin update changes it and the SessionStart hook can recycle a stale proxy.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves (commit/checkout/reset). The reflog is appended on
    // every HEAD movement, so it's the reliable trigger; HEAD/index are best-effort.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    for rel in [".git/logs/HEAD", ".git/HEAD", ".git/index"] {
        let p = format!("{manifest}/../../{rel}");
        if std::path::Path::new(&p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let build = match sha {
        Some(s) if dirty => format!("{s}-dirty"),
        Some(s) => s,
        None => "unknown".to_string(),
    };
    println!("cargo:rustc-env=ZLAUDER_BUILD={build}");
}
