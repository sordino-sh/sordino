//! Detection probe: mask each CLI arg on a MASK surface and print what the engine
//! detected (entity kind + the exact plaintext span). Used to verify recognizer
//! precision (e.g. that ordinary filenames/paths do NOT trip the API_KEY recognizer).
//!
//!   cargo run -q -p sordino-engine --example probe -- "finance-notes.md" "AKIAIOSFODNN7EXAMPLE"

use sordino_engine::MaskEngine;
use sordino_engine::{EngineConfig, MaskOutcome, Surface}; // re-exported at crate root? if not, fall back below

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let inputs: Vec<String> = if args.is_empty() {
        default_battery()
    } else {
        args
    };

    let engine = MaskEngine::new(EngineConfig::default()).expect("build engine");
    let mut flagged = 0usize;
    for input in &inputs {
        let out: MaskOutcome = engine.mask(input, Surface::ToolResult).expect("mask");
        if out.manifest.is_empty() {
            println!("clean   | {input:?}");
        } else {
            flagged += 1;
            let hits: Vec<String> = out
                .manifest
                .entries
                .iter()
                .map(|e| format!("{}={:?}", e.entity_kind, e.canonical_form))
                .collect();
            println!(
                "FLAGGED | {input:?}\n        -> masked: {:?}\n        -> {}",
                out.masked_text,
                hits.join(", ")
            );
        }
    }
    eprintln!("\n{flagged}/{} inputs flagged", inputs.len());
}

fn default_battery() -> Vec<String> {
    [
        // Ordinary filenames / paths — should ALL be clean.
        "finance-notes.md",
        "/home/user/Projects/sordino-testbed/finance-notes.md",
        "employees.csv",
        "package-lock.json",
        "Cargo.toml",
        "README.md",
        "src/components/Button.tsx",
        "docs/IMPLEMENTATION-NOTES.md",
        // Hashed / fingerprinted asset names (real-world FP magnets for entropy rules).
        "app.4f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c.js",
        "main.a1b2c3d4.chunk.js",
        "vendor.0123456789abcdef0123456789abcdef.css",
        "deadbeefdeadbeefdeadbeefdeadbeef.patch",
        "550e8400-e29b-41d4-a716-446655440000.json",
        // Long-but-wordy identifiers.
        "VeryLongCamelCaseComponentNameThatExceedsThirtyTwoChars.tsx",
        "this-is-a-rather-long-kebab-case-filename-indeed.md",
        // Real secrets — SHOULD be flagged (true positives must survive any fix).
        "AKIAIOSFODNN7EXAMPLE",
        "AWS_ACCESS_KEY_ID=AKIALALEMEL33243OLIB",
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "AIzaSyC9x_8Kd2LmN4pQ6rS1tU3vW5yZ7aB0cEf", // GCP: AIza + exactly 35 random
        // Bare high-entropy token caught ONLY by the generic pattern — recall check.
        "k7Lm2Nq9Rp4StUvWxYzAbCdEfGhIjKlMnOp",
        // Real keys that legitimately CONTAIN '/' — must still fire (the slash concern).
        "https://hooks.slack.com/services/T00000000/B00000000/abcdEFGH1234ijklMNOP5678",
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
