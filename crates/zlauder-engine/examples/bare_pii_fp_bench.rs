//! False-positive cost of lowering the detection floor so BARE (context-free)
//! US_SSN / PHONE_NUMBER numbers mask.
//!
//! THE QUESTION (owner: "measure first"): the context-aware enhancer masks a phone
//! only when a context word ("call", "phone", ...) sits nearby (see
//! `detect::bare_phone_without_context_stays_below_threshold`). Closing that gap —
//! masking a *bare* `+1 415 555 0132` or `123-45-6789` with no surrounding cue —
//! means lowering the score floor for those two entities. presidio's
//! PhoneRecognizer / UsSsnRecognizer emit those candidates at a score BELOW the
//! Balanced 0.5 gate; a per-entity floor of ~0.4/0.35 would let them through. The
//! cost is everything ELSE that looks phone/SSN-ish: order numbers, tracking
//! numbers, build versions, epochs, ISBNs, dimensions, raw 9-11 digit runs in logs.
//!
//! WHAT THIS MEASURES: a corpus of DECOYS (look phone/SSN-ish, are NOT PII) is run
//! through a real `MaskEngine` at three engine-wide score floors:
//!   * 0.50  — the live Balanced default (BASELINE, expected ~0 PHONE/SSN masks)
//!   * 0.40  — hypothetical per-entity floor for SSN
//!   * 0.35  — hypothetical per-entity floor for PHONE
//!
//! For each floor we count how many decoys gain a PHONE_NUMBER or US_SSN manifest
//! entry — i.e. the FALSE MASKS the owner would be buying by closing the gap. We
//! also confirm the gap is real by running the bare positives at each floor.
//!
//! Lowering the engine-wide `score_threshold` is a faithful SIMULATION of a
//! per-entity floor BECAUSE we attribute false masks only to PHONE/SSN manifest
//! kinds — entries of any other kind are not charged to this decision. (A genuine
//! per-entity floor would lower the gate for ONLY those two recognizers; counting
//! only their manifest entries yields the same FP set.)
//!
//! This example changes NO config defaults and asserts nothing — it prints a table.
//!
//!   cargo run -p zlauder-engine --example bare_pii_fp_bench

use zlauder_engine::{EngineConfig, MaskEngine, Profile, Surface};

/// The two entity kinds whose floor the owner is considering lowering. A false mask
/// is only charged to this decision when one of these manifest kinds fires.
const TARGET_KINDS: [&str; 2] = ["US_SSN", "PHONE_NUMBER"];

/// Floors to evaluate. 0.50 is the live Balanced baseline; the others are the
/// hypothetical lowered per-entity floors named in the brief.
const FLOORS: [f32; 3] = [0.50, 0.40, 0.35];

/// A decoy: a string that LOOKS phone/SSN-ish (digit runs, dashes, parens, dots)
/// but is NOT PII. `label` groups it in the report.
struct Decoy {
    label: &'static str,
    text: &'static str,
}

const fn d(label: &'static str, text: &'static str) -> Decoy {
    Decoy { label, text }
}

/// Decoys that resemble phone numbers or SSNs but carry no personal information.
/// Spread across the shapes the brief calls out: order/ticket/invoice numbers,
/// tracking numbers, long IDs, build/version numbers, timestamps/epochs, ISBNs,
/// dimensions, and raw 9-11 digit runs in code/log lines.
fn decoys() -> Vec<Decoy> {
    vec![
        // --- order / ticket / invoice numbers -------------------------------
        d("order", "Order #4021558 has shipped"),
        d("order", "Your order 415-555-0132 confirmation"), // phone-shaped order id
        d("ticket", "Ticket INC0012345 assigned to ops"),
        d("ticket", "Support case 800-273-8255 escalated"), // phone-shaped case id
        d("invoice", "Invoice 2024-00-3917 due on receipt"),
        d("invoice", "INV-415-998 total $1,204.00"),
        // --- tracking numbers -----------------------------------------------
        d("tracking", "Tracking 1Z999AA10123456784 in transit"),
        d("tracking", "USPS 9400 1000 0000 0000 0000 00 delivered"),
        d("tracking", "FedEx 7712 3456 7890 picked up"),
        // --- long ids / account-ish runs ------------------------------------
        d("long-id", "customer_id=100200300 in record"),
        d("long-id", "device serial 5559876543 returned"),
        d("long-id", "node id 4155550132 in cluster"), // bare 10-digit, phone-shaped
        d("long-id", "row 123456789 updated"),         // bare 9-digit, SSN-length
        // --- build / version numbers ----------------------------------------
        d("version", "release v12.4.108-rc.2+build.5678"),
        d("version", "kernel 6.18.9-zen1-2-zen booted"),
        d("version", "schema 415.555.0001 migrated"), // dotted, phone-shaped
        d("build", "build 20240617.3 succeeded"),
        // --- timestamps / epochs --------------------------------------------
        d("epoch", "ts=1718559600 event logged"),
        d("epoch", "expires 1893456000 seconds"),
        d("timestamp", "at 2024-06-17 14:55:01.320 done"),
        d("timestamp", "elapsed 415.5550132 ms"), // float, phone-shaped digits
        // --- ISBN -----------------------------------------------------------
        d("isbn", "ISBN 978-0-13-468599-1 in stock"),
        d("isbn", "ISBN-10 0-13-468599-7 reprint"),
        // --- dimensions / measurements --------------------------------------
        d("dimension", "panel 415 x 555 x 0132 mm"),
        d("dimension", "torque 123-45-6789 Nm spec"), // SSN-shaped measurement
        d("dimension", "range 800.555.0100 to 0200 Hz"),
        // --- raw digit runs in code / log lines -----------------------------
        d("log-run", "GET /api/v1/users/123456789 200"),
        d("log-run", "errno 4155550132 from syscall"),
        d("log-run", "[pid 555012] worker stalled"),
        d("log-run", "checksum 800273825 mismatch"), // 9-digit
        d("log-run", "offset 41555501320 bytes"),    // 11-digit
        d("log-run", "0x415555 0x0132 register dump"), // hex, phone-shaped
        d("code", "const PORT = 4155550132;"),
        d("code", "retry_after 800-273-8255 ms"), // dashed, phone-shaped
        // --- formatted runs that mimic SSN/phone punctuation ----------------
        d("ssn-shape", "part no 123-45-6789 in bin"),
        d("ssn-shape", "lot 987-65-4321 quarantined"),
        d("phone-shape", "ext (415) 555-0132 unused desk"), // no context cue word
        d("phone-shape", "+1 800 555 0100"),                // bare toll-free-ish
    ]
}

/// Bare positives: REAL phone/SSN values with NO context cue. These document the
/// gap — at the baseline floor they should MISS (stay unmasked); the whole point of
/// lowering the floor is to mask them. We report at each floor so the owner sees the
/// recall side of the trade alongside the FP side.
struct BarePositive {
    kind: &'static str,
    needle: &'static str,
    text: &'static str,
}

const fn bp(kind: &'static str, needle: &'static str, text: &'static str) -> BarePositive {
    BarePositive { kind, needle, text }
}

fn bare_positives() -> Vec<BarePositive> {
    vec![
        bp("PHONE_NUMBER", "+1 415 555 0132", "+1 415 555 0132"),
        bp("PHONE_NUMBER", "(415) 555-0188", "(415) 555-0188"),
        bp("PHONE_NUMBER", "+44 20 7946 0958", "+44 20 7946 0958"),
        bp("US_SSN", "123-45-6789", "123-45-6789"),
        bp("US_SSN", "078-05-1120", "078-05-1120"),
    ]
}

/// Build a Balanced engine with the engine-wide floor overridden to `floor`.
/// Balanced already enables Contact (PHONE_NUMBER) and Identity (US_SSN), so no
/// category change is needed — only the gate moves.
fn engine_at(floor: f32) -> MaskEngine {
    let mut cfg = EngineConfig::for_profile(Profile::Balanced);
    cfg.score_threshold = floor;
    MaskEngine::new(cfg).expect("build engine")
}

// ---------------------------------------------------------------------------
// Hard-context recognizer FP corpus (DATE_OF_BIRTH / CREDIT_CARD_EXPIRATION / CVV)
//
// These three recognizers are a SEPARATE FP class from the PHONE/SSN floor decision
// above: they carry their context IN the regex and fire at a flat 0.85 (above every
// profile floor), so the floor table never charges them. The hazard instead is
// code/log shapes whose VALUE looks like a date/expiry/CVV — `port 8080`,
// `status 200`, `ratio 01/12`, `the cache expires 12/24`. The card-context gate +
// month whitelist + dropped `cid/cvn/csc` labels are what keep these at zero.
//
// This section prints the count of DATE_OF_BIRTH/CREDIT_CARD_EXPIRATION/CVV masks the
// live Balanced default charges over the plan's revised C2 corpus — the expectation is
// ZERO. (The unit test `detect::cvv_plan_detect_tests::c2_fp_corpus_zero_masks_under_balanced`
// asserts it; this surfaces the same corpus in the bench for eyeballing.)
// ---------------------------------------------------------------------------

/// Hard-context entity kinds whose FP-safety this section measures. EXPIRATION_DATE
/// (the neutral, weak-evidence expiry label, FIX 1b) is included so the FP corpus
/// charges it too — a word-boundary FP like `discard exp` or `the discovery expires`
/// must mask ZERO of all four kinds, not silently leak as the neutral label.
const HARD_CONTEXT_KINDS: [&str; 4] = [
    "DATE_OF_BIRTH",
    "CREDIT_CARD_EXPIRATION",
    "EXPIRATION_DATE",
    "CVV",
];

/// The plan's revised C2 FP corpus + FIX 6 adversarial NO-MASK rows: code/log lines
/// whose values look like a date, expiry, or CVV but carry no real PII. Every one must
/// mask ZERO of the four. The FIX 6 additions exercise the word-boundary keyword scan
/// (`discard`≁`card`, `discovery`≁`discover`, `scorecard`≁`card`), the PAN
/// plausibility guard (`0000000000000`), the restricted CVV `is`-connector
/// (`the security code is 200 lines`), and the standalone-expiry FP class.
fn hard_context_fp_corpus() -> Vec<Decoy> {
    vec![
        d("port", "port 8080"),
        d("ratio", "ratio 01/12"),
        d("build", "build 20240115"),
        d("status", "status 200"),
        d("cid", "cid=4096"),
        d("export", "export 03/27"),
        d("json-csc", r#"{"csc": 4096}"#),
        d("expires", "the cache expires 12/24"),
        d("cert", "certificate expires Jan 2026"),
        d("cvv-multiline", "CVV:\n\n\n\n123"),
        // --- FIX 6 NO-MASK (word-boundary, PAN-plausibility, CVV-`is`-scope) ---
        d("discard", "discard exp 03/27"),
        d("discovery", "the discovery expires 03/27"),
        d("scorecard", "scorecard 1234 03/27"),
        d("zero-pan", "0000000000000 exp 03/27"),
        d("security-prose", "the security code is 200 lines long"),
        d("cache", "the cache expires 12/24"),
        d("cert-jan", "certificate expires Jan 2026"),
    ]
}

/// Count DOB/expiry/CVV masks a Balanced engine charges for `text`.
fn hard_context_hits(engine: &MaskEngine, text: &str) -> Vec<(String, String)> {
    let out = engine.mask(text, Surface::UserMessage).expect("mask");
    out.manifest
        .entries
        .iter()
        .filter(|e| HARD_CONTEXT_KINDS.contains(&e.entity_kind.as_str()))
        .map(|e| (e.entity_kind.clone(), e.canonical_form.clone()))
        .collect()
}

/// Run the C2 corpus through the live Balanced default and print the (expected-zero)
/// DOB/expiry/CVV false-mask tally.
fn report_hard_context_fp() {
    let engine = MaskEngine::new(EngineConfig::for_profile(Profile::Balanced)).expect("engine");
    let corpus = hard_context_fp_corpus();
    let mut false_masks: Vec<(&'static str, String, String)> = Vec::new();
    for dc in &corpus {
        for (kind, val) in hard_context_hits(&engine, dc.text) {
            false_masks.push((dc.label, kind, val));
        }
    }

    println!("\n== hard-context FP corpus (DOB / expiry / CVV) — live Balanced default ==");
    println!(
        "kinds: {} | corpus: {} code/log shapes | expected false masks: 0",
        HARD_CONTEXT_KINDS.join(", "),
        corpus.len(),
    );
    if false_masks.is_empty() {
        println!(
            "result: clean (0 DOB/expiry/CVV false masks over {} inputs)",
            corpus.len()
        );
    } else {
        println!("result: {} false mask(s):", false_masks.len());
        for (label, kind, val) in &false_masks {
            println!("    [{label}] {kind} = {val:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// LABEL-CORRECTNESS corpus (FIX 1b confidence-tiered expiry relabel)
//
// A masked token is visible to the upstream LLM, so a travel-visa / gift-card expiry
// masked as CREDIT_CARD_EXPIRATION would corrupt the model's reasoning. This section
// asserts each row masks under the EXPECTED label: ambiguous context → EXPIRATION_DATE;
// PAN / unambiguous payment term → CREDIT_CARD_EXPIRATION.
// ---------------------------------------------------------------------------

/// A label-correctness expectation: `text` must mask `value` under `expect_kind`.
struct LabelCase {
    text: &'static str,
    value: &'static str,
    expect_kind: &'static str,
}

const fn lc(text: &'static str, value: &'static str, expect_kind: &'static str) -> LabelCase {
    LabelCase {
        text,
        value,
        expect_kind,
    }
}

fn label_corpus() -> Vec<LabelCase> {
    vec![
        // Ambiguous context (bare visa / gift card / subscription) → neutral label.
        lc("my travel visa expires 03/26", "03/26", "EXPIRATION_DATE"),
        lc("my gift card expires 03/26", "03/26", "EXPIRATION_DATE"),
        lc("subscription valid thru 12/25", "12/25", "EXPIRATION_DATE"),
        // Strong payment evidence (PAN / unambiguous term) → specific label.
        lc(
            "4111 1111 1111 1111 exp 03/27",
            "03/27",
            "CREDIT_CARD_EXPIRATION",
        ),
        lc(
            "credit card on file, exp 03/27",
            "03/27",
            "CREDIT_CARD_EXPIRATION",
        ),
    ]
}

/// Report the FIX-1b label-correctness corpus through the live Balanced default.
fn report_label_correctness() {
    let engine = MaskEngine::new(EngineConfig::for_profile(Profile::Balanced)).expect("engine");
    let corpus = label_corpus();
    println!("\n== expiry label-correctness corpus (FIX 1b confidence-tiered relabel) ==");
    println!(
        "rows: {} | ambiguous → EXPIRATION_DATE, PAN/unambiguous-term → CREDIT_CARD_EXPIRATION",
        corpus.len()
    );
    let mut wrong = 0usize;
    for c in &corpus {
        let hits = hard_context_hits(&engine, c.text);
        let ok = hits
            .iter()
            .any(|(kind, val)| kind == c.expect_kind && val == c.value);
        if ok {
            println!("    OK   {:?} → {} {:?}", c.text, c.expect_kind, c.value);
        } else {
            wrong += 1;
            println!(
                "    WRONG {:?} → expected {} {:?}, got {:?}",
                c.text, c.expect_kind, c.value, hits
            );
        }
    }
    println!(
        "result: {}",
        if wrong == 0 {
            format!("all {} rows labeled correctly", corpus.len())
        } else {
            format!("{wrong} row(s) mislabeled")
        }
    );
}

/// Manifest entries of the target (PHONE/SSN) kinds produced for `text`.
fn target_hits(engine: &MaskEngine, text: &str) -> Vec<(String, String)> {
    let out = engine.mask(text, Surface::UserMessage).expect("mask");
    out.manifest
        .entries
        .iter()
        .filter(|e| TARGET_KINDS.contains(&e.entity_kind.as_str()))
        .map(|e| (e.entity_kind.clone(), e.canonical_form.clone()))
        .collect()
}

struct FloorResult {
    floor: f32,
    /// (decoy label, fired kind, fired value) for every PHONE/SSN false mask.
    false_masks: Vec<(&'static str, String, String)>,
    decoys_total: usize,
    /// bare positives recovered (masked) at this floor / total bare positives.
    bare_hit: usize,
    bare_total: usize,
}

fn run_floor(floor: f32, decoys: &[Decoy], bares: &[BarePositive]) -> FloorResult {
    let engine = engine_at(floor);

    let mut false_masks = Vec::new();
    for dc in decoys {
        for (kind, val) in target_hits(&engine, dc.text) {
            false_masks.push((dc.label, kind, val));
        }
    }

    let mut bare_hit = 0;
    for b in bares {
        let hits = target_hits(&engine, b.text);
        let recovered = hits.iter().any(|(kind, val)| {
            kind == b.kind && (val.contains(b.needle) || b.needle.contains(val.as_str()))
        });
        if recovered {
            bare_hit += 1;
        }
    }

    FloorResult {
        floor,
        false_masks,
        decoys_total: decoys.len(),
        bare_hit,
        bare_total: bares.len(),
    }
}

fn main() {
    let decoys = decoys();
    let bares = bare_positives();
    let results: Vec<FloorResult> = FLOORS
        .iter()
        .map(|f| run_floor(*f, &decoys, &bares))
        .collect();

    println!("== zlauder bare-PII false-positive cost benchmark (ML OFF) ==");
    println!(
        "profile: Balanced (Contact+Identity on) | targets: {} | decoys: {} | bare positives: {}",
        TARGET_KINDS.join(", "),
        decoys.len(),
        bares.len(),
    );
    println!(
        "method: override engine score floor; count only PHONE/SSN manifest entries\n        (simulates a per-entity floor for those two recognizers)\n"
    );

    // --- Headline table ---------------------------------------------------
    println!(
        "{:<10} {:>21}  {:>18}  note",
        "FLOOR", "false PHONE/SSN masks", "bare-PII recovered"
    );
    println!("{}", "-".repeat(74));
    for r in &results {
        let note = if (r.floor - 0.50).abs() < f32::EPSILON {
            "BASELINE (live Balanced)"
        } else {
            "hypothetical lowered floor"
        };
        println!(
            "{:<10.2} {:>13}/{:<3}  {:>13}/{:<3}  {}",
            r.floor,
            r.false_masks.len(),
            r.decoys_total,
            r.bare_hit,
            r.bare_total,
            note,
        );
    }

    // --- Delta vs baseline ------------------------------------------------
    let baseline = &results[0];
    println!(
        "\n== cost of closing the gap (delta vs {:.2} baseline) ==",
        baseline.floor
    );
    for r in results.iter().skip(1) {
        let extra_fp = r.false_masks.len() as i64 - baseline.false_masks.len() as i64;
        let extra_recall = r.bare_hit as i64 - baseline.bare_hit as i64;
        println!(
            "floor {:.2}: +{} false mask(s), +{} bare PII recovered",
            r.floor, extra_fp, extra_recall
        );
    }

    // --- Itemized false masks per floor -----------------------------------
    println!("\n== itemized false masks (decoys masked as PHONE/SSN) ==");
    for r in &results {
        if r.false_masks.is_empty() {
            println!("floor {:.2}: clean (0 PHONE/SSN false masks)", r.floor);
        } else {
            println!(
                "floor {:.2}: {} false mask(s):",
                r.floor,
                r.false_masks.len()
            );
            for (label, kind, val) in &r.false_masks {
                println!("    [{label}] {kind} = {val:?}");
            }
        }
    }

    // --- Bottom line ------------------------------------------------------
    println!("\n== read ==");
    println!(
        "Baseline (0.50) charges {} PHONE/SSN false mask(s) over {} decoys and recovers {}/{} bare PII.",
        baseline.false_masks.len(),
        baseline.decoys_total,
        baseline.bare_hit,
        baseline.bare_total,
    );
    println!(
        "Each lowered floor's FP count above is the price of the recall it buys on the same line."
    );

    // --- hard-context recognizer FP corpus (separate decision) ------------
    report_hard_context_fp();

    // --- expiry label-correctness corpus (FIX 1b) -------------------------
    report_label_correctness();
}
