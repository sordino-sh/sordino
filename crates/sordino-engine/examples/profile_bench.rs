//! Empirical per-profile detection benchmark.
//!
//! Builds an [`EngineConfig`] for each [`Profile`] via `EngineConfig::for_profile`
//! (the same threshold/categories/operator derivation `config.rs` uses), constructs
//! a real [`MaskEngine`] (so the wired `LemmaContextAwareEnhancer` IS exercised),
//! and runs a labeled corpus through `mask()`.
//!
//! For each POSITIVE sample we assert the expected entity actually got masked: a
//! manifest entry of the expected `entity_kind` whose `canonical_form` overlaps the
//! sensitive substring (or, for irreversible operators that leave no manifest entry,
//! the substring no longer appears verbatim in the masked text). For each HARD
//! NEGATIVE we assert NOTHING was masked (manifest empty AND text unchanged).
//!
//! ML is OFF (default) — PERSON/LOCATION samples are expected to MISS and are
//! recorded as such explicitly.
//!
//!   cargo run -p sordino-engine --example profile_bench

use std::collections::BTreeMap;

use sordino_engine::{EngineConfig, MaskEngine, Profile, Surface};

/// A positive sample: `text` should mask `needle` as entity `kind`.
struct Positive {
    kind: &'static str,
    needle: &'static str,
    text: &'static str,
    /// True when this is expected to MISS without the ML recognizer (PERSON/etc).
    needs_ml: bool,
}

impl Positive {
    const fn new(kind: &'static str, needle: &'static str, text: &'static str) -> Self {
        Self {
            kind,
            needle,
            text,
            needs_ml: false,
        }
    }
    const fn ml(kind: &'static str, needle: &'static str, text: &'static str) -> Self {
        Self {
            kind,
            needle,
            text,
            needs_ml: true,
        }
    }
}

fn positives() -> Vec<Positive> {
    use Positive as P;
    vec![
        // --- Emails: plain, plus-tagged, subaddressed -------------------------
        P::new(
            "EMAIL_ADDRESS",
            "alice@example.com",
            "contact alice@example.com please",
        ),
        P::new(
            "EMAIL_ADDRESS",
            "bob+newsletter@example.com",
            "subscribe bob+newsletter@example.com today",
        ),
        P::new(
            "EMAIL_ADDRESS",
            "carol.danvers+tag@sub.example.co.uk",
            "reply carol.danvers+tag@sub.example.co.uk soon",
        ),
        // --- Phones WITH context words (should mask once enhancer boosts) -----
        P::new(
            "PHONE_NUMBER",
            "+1 415 555 0132",
            "call me at +1 415 555 0132 tomorrow",
        ),
        P::new(
            "PHONE_NUMBER",
            "+1-415-555-0142",
            "my phone is +1-415-555-0142 ok",
        ),
        P::new(
            "PHONE_NUMBER",
            "(415) 555-0132",
            "reach me, number (415) 555-0132 anytime",
        ),
        P::new("PHONE_NUMBER", "415.555.0132", "phone 415.555.0132 is best"),
        P::new(
            "PHONE_NUMBER",
            "+44 20 7946 0958",
            "call the office at +44 20 7946 0958 now",
        ),
        // --- Phones WITHOUT context words (context-free) ----------------------
        // These are EXPECTED to miss on every profile: a phone with no nearby context
        // word stays at the 0.4 base, and the `PHONE_BASE_SCORE` tie-break drops the
        // at-base run even at the Strict 0.4 floor (so a phone-shaped order/id number is
        // never a false positive). Recorded here to document the tradeoff in the recall
        // numbers (the lever for context-free phones is ML or an explicit operator).
        P::new("PHONE_NUMBER", "+1 415 555 0132", "+1 415 555 0132"),
        P::new("PHONE_NUMBER", "(415) 555-0188", "(415) 555-0188"),
        // --- Identity ---------------------------------------------------------
        // A REAL SSN shape: a non-sample area number (not 123/000/666/9xx) that passes
        // presidio's `invalidate_result`, so the SSN5 pattern (score 0.5) actually fires.
        // (The textbook "123-45-6789" is a placeholder presidio deliberately rejects —
        // it only ever "masked" via a phone-recognizer coincidence, which the phone-FP
        // tie-break now correctly drops, so it is not a meaningful SSN-recall sample.)
        P::new("US_SSN", "536-90-4399", "ssn 536-90-4399 on file"),
        // --- Financial: credit cards (Luhn-valid), IBAN ----------------------
        P::new(
            "CREDIT_CARD",
            "4111111111111111",
            "visa 4111111111111111 charged",
        ),
        P::new(
            "CREDIT_CARD",
            "5555555555554444",
            "mastercard 5555555555554444 ok",
        ),
        P::new(
            "CREDIT_CARD",
            "378282246310005",
            "amex 378282246310005 declined",
        ),
        P::new(
            "IBAN_CODE",
            "GB82WEST12345698765432",
            "iban GB82WEST12345698765432 set",
        ),
        // --- Secrets ----------------------------------------------------------
        P::new(
            "AWS_ACCESS_KEY",
            "AKIAIOSFODNN7EXAMPLE",
            "key AKIAIOSFODNN7EXAMPLE here",
        ),
        P::new(
            "AWS_SECRET_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        P::new(
            "GCP_API_KEY",
            "AIzaSyC9x_8Kd2LmN4pQ6rS1tU3vW5yZ7aB0cEf",
            "gcp AIzaSyC9x_8Kd2LmN4pQ6rS1tU3vW5yZ7aB0cEf used",
        ),
        P::new(
            "JWT",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c works",
        ),
        P::new(
            "PRIVATE_KEY",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
        ),
        // --- Contact: IP addresses -------------------------------------------
        P::new("IP_ADDRESS", "203.0.113.42", "server at 203.0.113.42 down"),
        // --- Personal (expected MISS without ML) ------------------------------
        P::ml(
            "PERSON",
            "Alice Johnson",
            "please email Alice Johnson the report",
        ),
        P::ml(
            "PERSON",
            "Maria Gonzalez",
            "Maria Gonzalez approved the request",
        ),
    ]
}

/// Hard negatives: each MUST NOT mask. `label` is for the FP report.
fn hard_negatives() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "abs-path",
            "/home/user/Projects/sordino/crates/sordino-engine/src/detect.rs",
        ),
        (
            "kebab-ident",
            "this-is-a-rather-long-kebab-case-filename-indeed.md",
        ),
        (
            "snake-ident",
            "a_very_long_snake_case_module_identifier_name_here",
        ),
        (
            "camel-ident",
            "VeryLongCamelCaseComponentNameThatExceedsThirtyTwoChars",
        ),
        ("hex32-digest", "4f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c"),
        ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
        ("semver", "version 12.4.108-rc.2+build.5678"),
        ("order-num", "Order #4021558 shipped"),
        ("isbn-run", "ISBN 978-0-13-468599-1 in stock"),
        ("git-sha", "commit deadbeefcafebabe0123456789abcdef01234567"),
    ]
}

/// Did `out` mask the positive sample's expected entity?
///
/// Two acceptance modes, since profiles use different operators (Token leaves a
/// reversible manifest entry; Strict's Redact does not):
///   1. A manifest entry of the expected kind whose `canonical_form` overlaps the
///      needle (the precise, reversible-operator path).
///   2. The needle no longer appears verbatim in the masked text (catches
///      Redact/Mask/Hash, which leave no manifest entry).
fn masked_expected(out: &sordino_engine::MaskOutcome, p: &Positive, original: &str) -> bool {
    let by_manifest = out.manifest.entries.iter().any(|e| {
        e.entity_kind == p.kind
            && (e.canonical_form.contains(p.needle) || p.needle.contains(&e.canonical_form))
    });
    if by_manifest {
        return true;
    }
    // Irreversible operators: the needle must have been altered in the masked text.
    // Guard against trivially-true (needle absent from original) — never the case here.
    original.contains(p.needle) && !out.masked_text.contains(p.needle)
}

struct ProfileResult {
    profile: Profile,
    threshold: f32,
    // recall over positives that DON'T need ML (the actionable recall).
    detectable_total: usize,
    detectable_hit: usize,
    // per-entity: kind -> (hit, total) over detectable (non-ML) positives.
    per_entity: BTreeMap<&'static str, (usize, usize)>,
    // ML-needed positives and how many masked anyway (expected 0 without ML).
    ml_total: usize,
    ml_hit: usize,
    // false positives over hard negatives: list of (label, what-fired).
    fps: Vec<(String, String)>,
}

fn run_profile(profile: Profile, pos: &[Positive], neg: &[(&str, &str)]) -> ProfileResult {
    let cfg = EngineConfig::for_profile(profile);
    let threshold = cfg.score_threshold;
    let engine = MaskEngine::new(cfg).expect("build engine");

    let mut detectable_total = 0;
    let mut detectable_hit = 0;
    let mut per_entity: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    let mut ml_total = 0;
    let mut ml_hit = 0;

    for p in pos {
        let out = engine.mask(p.text, Surface::UserMessage).expect("mask");
        let hit = masked_expected(&out, p, p.text);
        if p.needs_ml {
            ml_total += 1;
            if hit {
                ml_hit += 1;
            }
            continue;
        }
        detectable_total += 1;
        let e = per_entity.entry(p.kind).or_insert((0, 0));
        e.1 += 1;
        if hit {
            detectable_hit += 1;
            e.0 += 1;
        }
    }

    let mut fps = Vec::new();
    for (label, text) in neg {
        let out = engine.mask(text, Surface::UserMessage).expect("mask");
        let masked = !out.manifest.is_empty() || out.masked_text != *text;
        if masked {
            let what = if out.manifest.is_empty() {
                format!("text changed -> {:?}", out.masked_text)
            } else {
                out.manifest
                    .entries
                    .iter()
                    .map(|e| format!("{}={:?}", e.entity_kind, e.canonical_form))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            fps.push((label.to_string(), what));
        }
    }

    ProfileResult {
        profile,
        threshold,
        detectable_total,
        detectable_hit,
        per_entity,
        ml_total,
        ml_hit,
        fps,
    }
}

fn main() {
    let pos = positives();
    let neg = hard_negatives();
    let profiles = Profile::ALL;

    let results: Vec<ProfileResult> = profiles
        .iter()
        .map(|p| run_profile(*p, &pos, &neg))
        .collect();

    println!("== sordino profile detection benchmark (ML OFF) ==");
    println!(
        "corpus: {} positives ({} detectable w/o ML, {} need ML), {} hard negatives\n",
        pos.len(),
        pos.iter().filter(|p| !p.needs_ml).count(),
        pos.iter().filter(|p| p.needs_ml).count(),
        neg.len()
    );

    // --- Summary table ----------------------------------------------------
    println!(
        "{:<16} {:>6}  {:>16}  {:>14}  {:>10}",
        "PROFILE", "thresh", "recall (non-ML)", "ml-recall", "FP/negs"
    );
    println!("{}", "-".repeat(72));
    for r in &results {
        let recall = pct(r.detectable_hit, r.detectable_total);
        println!(
            "{:<16} {:>6.2}  {:>9}/{:<3} {:>3.0}%  {:>4}/{:<3} {:>3.0}%  {:>5}/{:<3}",
            format!("{:?}", r.profile),
            r.threshold,
            r.detectable_hit,
            r.detectable_total,
            recall,
            r.ml_hit,
            r.ml_total,
            pct(r.ml_hit, r.ml_total),
            r.fps.len(),
            neg.len(),
        );
    }

    // --- Per-entity recall per profile ------------------------------------
    let all_kinds: Vec<&'static str> = {
        let mut v: Vec<&'static str> = pos.iter().filter(|p| !p.needs_ml).map(|p| p.kind).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    println!("\n== per-entity recall (non-ML positives), hit/total ==");
    print!("{:<18}", "ENTITY");
    for r in &results {
        print!("{:>14}", format!("{:?}", r.profile));
    }
    println!();
    println!("{}", "-".repeat(18 + 14 * results.len()));
    for kind in &all_kinds {
        print!("{:<18}", kind);
        for r in &results {
            match r.per_entity.get(kind) {
                Some((h, t)) => print!("{:>14}", format!("{h}/{t}")),
                None => print!("{:>14}", "-"),
            }
        }
        println!();
    }
    // PERSON row (ML-needed) shown explicitly as an expected miss.
    print!("{:<18}", "PERSON (needs ML)");
    for r in &results {
        print!("{:>14}", format!("{}/{}", r.ml_hit, r.ml_total));
    }
    println!("   <- expected 0/N without ML");

    // --- False positives over hard negatives ------------------------------
    println!("\n== hard-negative false positives (must be empty) ==");
    let mut any = false;
    for r in &results {
        if r.fps.is_empty() {
            println!("{:<16} clean (0 FPs)", format!("{:?}", r.profile));
        } else {
            any = true;
            println!("{:<16} {} FP(s):", format!("{:?}", r.profile), r.fps.len());
            for (label, what) in &r.fps {
                println!("    [{label}] {what}");
            }
        }
    }
    if !any {
        println!("(no profile produced a false positive over the hard-negative set)");
    }
}

fn pct(hit: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * hit as f64 / total as f64
    }
}
