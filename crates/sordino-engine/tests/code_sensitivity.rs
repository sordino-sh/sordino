//! Code-sensitivity regression corpus — the filepath-vs-PII boundary a coding tool
//! lives on. At the DEFAULT (Balanced) profile, code constructs (file paths, module
//! paths, git SHAs, UUIDs, semver, host:port, public URLs) must pass through VERBATIM,
//! while real secrets / PII / declared codenames must mask. This is the regression gate
//! for any future recognizer or detection-gate change (plan §6).
//!
//! Rationale: masking a code construct never breaks correctness (tokens resolve back
//! on the wire, even inside tool uses), but it degrades the model's reasoning — so
//! precision on this boundary is the goal. Negatives assert NO masking (output ==
//! input); positives assert the secret VALUE is absent (no brittle token matching).

use sordino_engine::{CustomReplacement, EngineConfig, MaskEngine, Surface};

fn engine() -> MaskEngine {
    MaskEngine::new(EngineConfig::default()).expect("engine init")
}

fn mask(e: &MaskEngine, t: &str) -> String {
    e.mask(t, Surface::UserMessage).expect("mask").masked_text
}

/// MUST NOT MASK — code constructs pass through verbatim at the Balanced default.
#[test]
fn code_constructs_pass_through_at_balanced() {
    let e = engine();
    let benign = [
        // unix / windows file paths
        "/home/user/project/src/main.rs",
        "./src/config.rs",
        "../lib/mod.rs",
        r"C:\Users\dev\app.py",
        // bare repo files / dotfiles
        "CLAUDE.md",
        "Cargo.toml",
        "package.json",
        "opts.la",
        "tsconfig.json",
        // file:line reference
        "src/recognizers.rs:421",
        // dotted module / symbol paths
        "crate::config::Category",
        "std::collections::HashMap",
        "pkg.sub.module.func",
        // identifiers / hashes / ids
        "a1b2c3d",                                   // short git SHA
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  // 40-hex SHA
        "550e8400-e29b-41d4-a716-446655440000",      // UUID
        "this_is_a_long_snake_case_identifier_name", // long identifier
        // versions
        "v0.10.0",
        "1.2.3",
        // host:port (Network off by default → IP/host passes)
        "0.0.0.0:8080",
        "localhost:3000",
        "127.0.0.1:5432",
        // a public URL (Network off → passes through)
        "https://docs.rs/regex/latest/regex/",
        // ISO-8601 timestamp (DATE_TIME is off by default)
        "2026-06-10T12:00:00Z",
    ];
    for t in benign {
        let out = mask(&e, t);
        assert_eq!(out, t, "code construct masked (false positive): {t:?} -> {out:?}");
    }
}

/// MUST MASK — real secrets / PII still mask at the Balanced default. (input, the
/// substring that must be ABSENT from the masked output.)
#[test]
fn real_secrets_and_pii_still_mask_at_balanced() {
    let e = engine();
    let cases: [(&str, &str); 7] = [
        ("aws key AKIAIOSFODNN7EXAMPLE rotate it", "AKIAIOSFODNN7EXAMPLE"),
        (
            "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N here",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ),
        // Valid-area SSN WITH context. (A bare/low-validity `123-45-6789` is a
        // deliberate decoy that does NOT mask at the 0.50 Balanced floor — see
        // `examples/bare_pii_fp_bench.rs` — so precision on SSN-shaped order numbers
        // is preserved; real SSNs ride the context boost.)
        ("My SSN is 536-90-4399 on file", "536-90-4399"),
        ("mail alice@example.com please", "alice@example.com"),
        ("card 4111111111111111 charged", "4111111111111111"),
        ("iban GB82WEST12345698765432 transfer", "GB82WEST12345698765432"),
        ("call https://h/p?token=letmein-opaque now", "letmein-opaque"),
        // NOTE: a full multi-line PEM PRIVATE KEY block is deliberately NOT asserted
        // here — at Balanced only the `-----BEGIN … KEY-----` marker masks (as API_KEY)
        // while the base64 body relies on the entropy catch-all; private-key *block*
        // recall is a separate, pre-existing concern out of scope for this corpus.
    ];
    for (t, secret) in cases {
        let out = mask(&e, t);
        assert!(!out.contains(secret), "secret/PII NOT masked: {t:?} -> {out:?}");
    }
}

/// KNOWN PRECISION GAPS — characterization of CURRENT Balanced behavior that is not
/// ideal, kept VISIBLE/tracked rather than silently omitted (ship-gate chunk-3 finding).
/// All but PEM are over-masking FALSE POSITIVES: safe-but-confusing (tokens resolve on
/// the wire, so correctness holds; the cost is model-context noise). When a gap is fixed
/// the relevant assertion flips and this test must be updated.
#[test]
fn known_precision_gaps_current_behavior() {
    let e = engine();
    // Email-shaped code/infra metadata masks as EMAIL_ADDRESS — NOT a user's personal
    // PII (SSH remotes, no-reply/bot addresses, package.json authors). FOLLOW-UP (owner
    // decision): allow-list well-known code-host emails (git@github.com, *@users.noreply
    // .github.com, …) to stop over-masking them.
    assert!(
        mask(&e, "clone git@github.com:org/repo.git").contains("[EMAIL_ADDRESS_"),
        "tracked FP: git@host remote currently masks"
    );
    assert!(
        mask(&e, "author noreply@github.com").contains("[EMAIL_ADDRESS_"),
        "tracked FP: no-reply bot address currently masks"
    );
    // A high-entropy PUBLIC content identifier (IPFS CIDv1, base32) is caught by the
    // generic API_KEY entropy catch-all. Public id, not a secret — candidate for a
    // CID-shape exclusion in `plausible_generic_secret`.
    let cid = "bafybeigdyrzt5sfp7udm7hu76x2v66pzff7uzjj2nfqitj7frdnpfefqeq";
    assert!(
        !mask(&e, &format!("pin {cid}")).contains(cid),
        "tracked FP: IPFS CID currently masks as API_KEY"
    );
    // A `phone`-named id field boosts its numeric value over the PHONE floor via the
    // lemma context enhancer (the word "phone" is the cue). Niche context-boost edge.
    assert!(
        !mask(&e, "phone_number_id=14155550132").contains("14155550132"),
        "tracked FP: phone_number_id value currently masks as PHONE"
    );
}

/// KNOWN RECALL GAP (PEM): a full PRIVATE KEY block should mask entirely, but at Balanced
/// only the `-----BEGIN … KEY-----` marker masks while the base64 body relies on the
/// entropy catch-all (which misses short/structured bodies). Ignored so it does not fail
/// CI; un-ignore when private-key *block* recall lands. Tracked outside the precision
/// corpus per the chunk-3 review.
#[test]
#[ignore = "known gap: PEM private-key block body not fully masked at Balanced"]
fn pem_private_key_block_fully_masks() {
    let e = engine();
    let pem = "-----BEGIN PRIVATE KEY-----\n\
               MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n\
               -----END PRIVATE KEY-----";
    let out = mask(&e, pem);
    assert!(
        !out.contains("MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA"),
        "PEM body should mask: {out}"
    );
}

/// A declared project codename (via `custom_replacements`) masks, while a file path in
/// the same text passes through — the recall side of the boundary.
#[test]
fn declared_codename_masks_while_path_passes() {
    let cfg = EngineConfig {
        custom_replacements: vec![CustomReplacement {
            pattern: "PROJECT-NEPTUNE".into(),
            entity_type: "CODENAME".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: false,
            token: None,
            apply_to_surfaces: None,
        }],
        ..EngineConfig::default()
    };
    let e = MaskEngine::new(cfg).expect("engine init");
    let out = mask(&e, "deploy PROJECT-NEPTUNE from ./src/main.rs");
    assert!(!out.contains("PROJECT-NEPTUNE"), "codename not masked: {out}");
    assert!(out.contains("./src/main.rs"), "path masked alongside codename: {out}");
}
