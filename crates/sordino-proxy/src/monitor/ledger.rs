//! Opt-in, append-only JSONL policy-event ledger.
//!
//! Every registered-secret wire-refusal (the 409 tripwire) appends ONE structured
//! line naming the offending entity *class* and the wire *channel* — NEVER a secret
//! value, matched byte content, a user-payload JSON key, or conversation content. This
//! converts the otherwise-silent 409 into a reportable policy signal an operator (or a
//! SIEM agent tailing the file) can act on. Sordino writes the receipt; it deliberately
//! builds no central reporting — the file is the integration seam.
//!
//! Durability over throughput: refusals are rare, so each event is flushed to disk
//! immediately. The writer owns its OWN [`Mutex`] — it never shares the monitor store's
//! lock — so a ledger append can never stall (or be stalled by) request-path masking.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One policy-event line.
///
/// HARD INVARIANT: every field is a class / name / enum string — NEVER a secret value,
/// matched bytes, a user-payload JSON key, or conversation text. This mirrors the
/// class-not-value discipline of the monitor capture scrub and the `entity_kind`
/// taxonomy: the ledger records THAT a class was refused on a channel, never the datum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// RFC3339 UTC, second granularity (e.g. `2026-07-07T18:42:05Z`).
    pub ts: String,
    /// Project-identity hash (`AppState::project_key()` hex) — not a path, not a name.
    pub project: String,
    /// The policy action. Always `"wire_refusal"` in v1.
    pub action: String,
    /// The refused entity CLASS (`"registered_secret"` for the byte/header tripwire) or,
    /// for a walker carve-out hit, the registered secret's NAME — a config-chosen label,
    /// never its value.
    pub entity_class: String,
    /// The wire channel the refusal fired on
    /// (`"body"` | `"path_query"` | `"header"` | `"carve_out"`).
    pub channel: String,
}

/// Append-only JSONL writer for policy events. Constructed only when the operator opts
/// in (`[proxy] ledger = true`); `AppState.ledger` is `None` otherwise, so the default
/// privacy-first path pays exactly zero cost.
pub struct Ledger {
    file: Mutex<File>,
    project: String,
}

impl Ledger {
    /// Open — creating parent dirs and the file if absent — an append-only ledger at
    /// `path`, stamping every event with `project` (the caller's
    /// `AppState::project_key()`). Never truncates an existing file, so events survive a
    /// proxy recycle.
    pub fn open(path: &Path, project: String) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            project,
        })
    }

    /// Append one `wire_refusal` event for `entity_class` on `channel`.
    ///
    /// BEST-EFFORT: a write failure is logged and swallowed — the 409 refusal is the
    /// enforcement, this line is only the receipt, so a ledger error must NEVER block,
    /// panic, or alter the response. Callers invoke this AFTER deciding to refuse.
    pub fn record_refusal(&self, entity_class: &str, channel: &str) {
        let event = LedgerEvent {
            ts: now_rfc3339(),
            project: self.project.clone(),
            action: "wire_refusal".to_string(),
            entity_class: entity_class.to_string(),
            channel: channel.to_string(),
        };
        if let Err(e) = self.append(&event) {
            tracing::warn!("sordino ledger: dropping a wire_refusal event (append failed): {e}");
        }
    }

    /// Serialize `event` as one JSON line and flush it. Returns the IO / serialization
    /// error to [`Self::record_refusal`], which applies the best-effort failure policy.
    fn append(&self, event: &LedgerEvent) -> io::Result<()> {
        let mut line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        // Recover from a poisoned lock rather than propagate a panic onto the request
        // path: the worst a poisoned writer costs is a possibly-interleaved line, which is
        // strictly better than aborting the refusal handler.
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        file.write_all(line.as_bytes())?;
        file.flush()
    }
}

/// Format `SystemTime::now()` as RFC3339 UTC at second granularity, std-only (no chrono
/// / time dependency, since neither is on the proxy's dependency graph). Uses Howard
/// Hinnant's civil-from-days algorithm, matching the engine's own date arithmetic.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch → (year, month, day),
/// proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sordino-ledger-{}-{}.jsonl",
            tag,
            std::process::id()
        ))
    }

    #[test]
    fn event_serializes_to_exact_shape() {
        let ev = LedgerEvent {
            ts: "2026-07-07T18:42:05Z".to_string(),
            project: "deadbeef".to_string(),
            action: "wire_refusal".to_string(),
            entity_class: "registered_secret".to_string(),
            channel: "body".to_string(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(v["ts"], "2026-07-07T18:42:05Z");
        assert_eq!(v["project"], "deadbeef");
        assert_eq!(v["action"], "wire_refusal");
        assert_eq!(v["entity_class"], "registered_secret");
        assert_eq!(v["channel"], "body");
        // Exactly these five keys — no leaked extras from the payload side.
        assert_eq!(v.as_object().unwrap().len(), 5);
    }

    #[test]
    fn append_and_read_back_multiple_lines() {
        let path = temp_path("multi");
        let _ = fs::remove_file(&path);
        let ledger = Ledger::open(&path, "proj-key-abc".to_string()).unwrap();
        ledger.record_refusal("registered_secret", "body");
        ledger.record_refusal("my_stripe_key", "carve_out");

        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one JSONL line per event");

        let e0: LedgerEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(e0.action, "wire_refusal");
        assert_eq!(e0.project, "proj-key-abc");
        assert_eq!(e0.entity_class, "registered_secret");
        assert_eq!(e0.channel, "body");
        assert!(
            e0.ts.ends_with('Z') && e0.ts.contains('T'),
            "RFC3339 UTC expected, got {}",
            e0.ts
        );

        let e1: LedgerEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e1.entity_class, "my_stripe_key");
        assert_eq!(e1.channel, "carve_out");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn disabled_ledger_is_a_no_op() {
        // The default privacy-first path: `AppState.ledger` is `None`. The guarded
        // call-site idiom (`if let Some(l) = &st.ledger { l.record_refusal(..) }`) must
        // write nothing at all.
        let path = temp_path("disabled");
        let _ = fs::remove_file(&path);
        let ledger: Option<Ledger> = None;
        if let Some(l) = &ledger {
            l.record_refusal("registered_secret", "body");
        }
        assert!(
            !path.exists(),
            "a None ledger must never create or write the file"
        );
    }

    #[test]
    fn reopen_appends_never_truncates() {
        let path = temp_path("append");
        let _ = fs::remove_file(&path);
        {
            let l = Ledger::open(&path, "p".to_string()).unwrap();
            l.record_refusal("registered_secret", "header");
        }
        {
            // Re-open the SAME path (a proxy recycle): the prior line must survive.
            let l = Ledger::open(&path, "p".to_string()).unwrap();
            l.record_refusal("registered_secret", "path_query");
        }
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(
            contents.lines().count(),
            2,
            "re-open must append, not truncate"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn now_rfc3339_has_expected_shape() {
        let ts = now_rfc3339();
        // `YYYY-MM-DDTHH:MM:SSZ` = 20 chars.
        assert_eq!(ts.len(), 20, "unexpected ts: {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
