//! Hard-context, value-only-capture regex recognizers for the three PII misses
//! whose value shape is indistinguishable from ordinary code/log content: date of
//! birth, credit-card expiration, and CVV. (See `cvv-plan.md` Part 1 — "value
//! ambiguity" is the property that forces context gating.)
//!
//! Each recognizer impls [`presidio_core::Recognizer`] DIRECTLY over a raw
//! [`regex::Regex`] (the [`crate::detect`] Pass-2b path drives it just like the ML
//! recognizer), mirroring `IbanRecognizer`'s idiom of emitting a span NARROWER than
//! the regex match: the full regex matches `label + gap + value`, but the emitted
//! [`RecognizerResult`] start/end come from CAPTURE GROUP 1 (the value only). The
//! label is context, never masked; under [`crate::Operator::Redact`] a CVV reads
//! `CVV: [REDACTED]`, never leaking the SAD value while keeping the human-readable
//! key.
//!
//! We impl the trait over a bare `Regex` (not the analyzer's `PatternRecognizer`)
//! for two reasons (feasibility audit V5): (a) `PatternRecognizer` emits the WHOLE
//! match as the span, but we need the value-only sub-span; (b) the
//! `presidio_analyzer::pattern` module is not a top-level re-export, so importing it
//! is awkward — a raw `Regex` sidesteps both.
//!
//! All three emit `EntityType::Custom(<config const>)` at base score `0.85`, using
//! the shared entity-string consts from [`crate::config`] so the recognizer's
//! emitted label can never drift from the category-gate string (a desync silently
//! no-ops the gate).

use presidio_core::{EntityType, NlpArtifacts, Recognizer, RecognizerResult};
use regex::Regex;
use std::sync::OnceLock;

use crate::config::{
    ENTITY_CREDIT_CARD_EXPIRATION, ENTITY_CVV, ENTITY_DATE_OF_BIRTH, ENTITY_EXPIRATION_DATE,
};

/// High base score for a hard-context match. Above every profile floor (Strict 0.4
/// .. SecretsOnly 0.6), so a gated value always clears the threshold on its own —
/// these recognizers carry their context IN the regex, so they do not rely on the
/// lemma enhancer's boost the way the soft (phone) recognizers do.
const BASE_SCORE: f32 = 0.85;

/// Separator-only, no-letter, no-digit, no-newline bounded gap between a label and
/// its value. Separators only ⇒ kills the gap-skip (`born to run, ETA 12/25`) and
/// the newline-leak FP; widened to `{0,6}` for `exp.-:.`; the `" is "` connector
/// admits `CVV is 123` and — with a trailing optional `[:=]` + spaces — `CVV is: 123`
/// (audit cvv-is-colon-secondary-gap). The connector stays whitespace-anchored on the
/// left (`[ \t]+is`) so it never fires inside `this`/`his`.
const GAP: &str = r"(?:[ \t:=#.\-]{0,6}|[ \t]+is[ \t]*[:=]?[ \t]*)";

/// Newline-tolerant gap: [`GAP`] plus ONE tolerated colon-newline (`DOB:\n<date>`,
/// `CVV:\n123`), which a privacy proxy must not leak when a label sits on the line
/// above its value. Shared by DOB and CVV (the SAD value is strictly higher-sensitivity
/// than DOB, so it gets the same single-newline tolerance — audit cvv-newline-gap-sad-leak).
/// Multi-newline is still rejected (the FP-safety boundary), so `CVV:\n\n\n\n123` does
/// not match here.
const GAP_NL: &str = r"(?:[ \t:=#.\-]{0,6}|[ \t]+is[ \t]*[:=]?[ \t]*|[ \t]*:[ \t]*\r?\n[ \t]{0,8})";

/// CVV-specific gap WITH the `is` connector — used ONLY behind the UNAMBIGUOUS CVV
/// abbreviations (`cvv`/`cvv2`/`cvc2`/`cav2`). Like [`GAP_NL`] (whitespace/`:`/`=`/`#`
/// separators, the `is` connector, ONE colon-newline so `CVV:\n123` masks — audit
/// cvv-newline-gap-sad-leak) but with `.` and `-` DROPPED from the separator class
/// (audit cvv-cvc-bare-label-codelog-fp): dotted/dashed code identifiers (`cvc2-500`,
/// `obj.cvc.200`, `response.cvc=404`) must not bind a 3-4-digit status/port to a CVV
/// label. The recall paths (`CVV: 123`, `cvc2=4567`, `CVV is 123`) all use
/// whitespace/`:`/`=`/`is`, so none regress.
const GAP_CVV: &str = r"(?:[ \t:=#]{0,6}|[ \t]+is[ \t]*[:=]?[ \t]*|[ \t]*:[ \t]*\r?\n[ \t]{0,8})";

/// CVV gap WITHOUT the `is` connector — used behind the PROSE-CAPABLE multi-word
/// labels (`security code`, `card verification*`, `card identification number`).
/// FIX 4: the `is` connector lets `the security code is 200 lines` bind the non-date
/// integer `200` (a generic prose FP). The multi-word labels therefore require TIGHT
/// adjacency (separators or a single colon-newline only — NO `is`), so `security
/// code: 123` / `security code 4821` mask while `the security code is 200 lines`
/// does NOT. The unambiguous abbreviations keep the `is` connector (`cvv is 123`).
const GAP_CVV_TIGHT: &str = r"(?:[ \t:=#]{0,6}|[ \t]*:[ \t]*\r?\n[ \t]{0,8})";

/// Build the `EntityType::Custom(<label>)` for one of our config consts. None of the
/// four consts is a canonical presidio Display name, so `from_label` preserves them
/// verbatim as `Custom` — its `Display`/`to_string()` then equals the const, which is
/// exactly the string `detect::ingest_results` keys the category gate on.
fn custom(label: &str) -> EntityType {
    EntityType::from_label(label)
}

/// Run one label+gap+value regex over `text`, emitting a value-only span (group 1)
/// per match. `extra_ok` is a per-match acceptance predicate
/// `(text, whole_match, value_match) -> bool` (the card-context gate and the
/// third-date-field guard both read it); it returns `true` to emit. The
/// recognizer-name is recorded on each result so overlap/audit can trace the source.
fn gated_capture<F>(
    re: &Regex,
    entity: &EntityType,
    recognizer_name: &str,
    text: &str,
    mut extra_ok: F,
) -> Vec<RecognizerResult>
where
    F: FnMut(&str, &regex::Match<'_>, &regex::Match<'_>) -> bool,
{
    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).expect("group 0 always present");
        // Group 1 is the VALUE — the only span we emit/mask.
        let Some(value) = caps.get(1) else {
            continue;
        };
        if value.start() >= value.end() {
            continue;
        }
        // The gate sees the whole match (label class) AND the value sub-match (so it
        // can inspect the text immediately after the value — e.g. the expiry
        // third-date-field guard).
        if !extra_ok(text, &whole, &value) {
            continue;
        }
        out.push(
            RecognizerResult::new(entity.clone(), value.start(), value.end(), BASE_SCORE)
                .with_recognizer(recognizer_name.to_string()),
        );
    }
    out
}

// ---------------------------------------------------------------------------
// DATE_OF_BIRTH
// ---------------------------------------------------------------------------

/// The date-value alternation, group 1 = the whole date. Inner branches use
/// NON-capturing groups so group 1 is always the date. Shared by the forward
/// (`label + GAP_NL + value`) and reverse (`value + connector + label`) DOB regexes
/// so both readings honour the identical, audit-hardened date grammar (longest-first
/// day alts, shared trailing terminal).
///
/// TERMINAL (appended AFTER the group-1 close so it is never captured): every branch's
/// right edge is a word boundary OR — for an ISO-8601 timestamp — a consumed `T<time>`
/// suffix. The `regex` crate has no look-around, so the ISO time is matched (outside
/// group 1) rather than asserted; this terminates the date cleanly on
/// `1990-01-02T00:00` (audit dob-iso-datetime-leak) while the trailing `\b` still forces
/// whole-run consumption (an over-long contiguous DIGIT run like `199012251` fails
/// because the next char is a digit, satisfying neither `\b` nor the `[Tt]`-led branch).
const DOB_VALUE: &str = concat!(
    r"(",
    // Y-M-D: year, month 01-12, day — day alt LONGEST-FIRST (audit V2).
    // Ordered FIRST so a 4-digit lead binds here, never as a stray D/M/Y day.
    // Optional spaces around the separator (`1985 - 03 - 27`) mirror the expiry
    // `\s?` (audit dob-spaced-separator-fn); FP-safe because the numeric branches
    // only ever run behind the hard DOB label gate.
    r"\d{4}\s?[/\-.]\s?(?:0?[1-9]|1[0-2])\s?[/\-.]\s?(?:3[01]|[12]\d|0?[1-9])",
    // M/D/Y or M-D-Y (US-majority, audit dob-us-mdy-leak): month 01-12, then
    // day LONGEST-FIRST (audit V2 truncation guard), then 2-4y. FP-safe — the
    // hard DOB label gate (label+GAP_NL, or reverse connector+label) brackets this; a
    // bare ratio/date never reaches it. Ordered BEFORE D/M/Y so a day>12 in field 2
    // (US `03/27/1985`) resolves; ambiguous both-≤12 dates still fall to the D/M/Y below.
    // Optional spaces around separators (`03 / 27 / 1985`) mirror the expiry pattern.
    r"|(?:0?[1-9]|1[0-2])\s?[/\-.]\s?(?:3[01]|[12]\d|0?[1-9])\s?[/\-.]\s?\d{2,4}",
    // D/M/Y or D-M-Y (slash/dash/dot): day, then month 01-12, then 2-4y. Optional
    // spaces around separators mirror the expiry pattern (audit dob-spaced-separator-fn).
    r"|\d{1,2}\s?[/\-.]\s?(?:0?[1-9]|1[0-2])\s?[/\-.]\s?\d{2,4}",
    // Month-name D, Y (month whitelist). The shared terminal `\b` mirrors the numeric
    // branches: an over-long year run (`January 15, 20235`) fails the whole match
    // rather than capturing `January 15, 2023` and leaking the trailing `5`
    // (audit dob-monthname-trailing-digit-leak).
    r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2},?\s+\d{4}",
    // Compact YYYYMMDD (fixed-width ⇒ no reorder needed); the shared terminal `\b` so
    // an over-long run (e.g. `199012251`) fails rather than masking a prefix.
    r"|(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])",
    r")",
    // Shared right-edge terminal, OUTSIDE group 1 so neither the `\b` nor a consumed ISO
    // time enters the emitted span. Either a word boundary (the over-long-digit-run guard
    // — a following digit satisfies neither alternative) OR a consumed ISO-8601 time
    // (`T00:00`, `T23:59:59`) so a timestamped DOB terminates the date cleanly without
    // leaking (audit dob-iso-datetime-leak). The `regex` crate has no look-around, so the
    // ISO time is MATCHED (then discarded by being outside group 1), not asserted.
    r"(?:[Tt]\d{1,2}:\d{2}(?::\d{2})?\b|\b)",
);

/// Date-of-birth recognizer. Forward: label (`date of birth`/`d.o.b.`/`birth date`/
/// `born`) + [`GAP_NL`] + a date value; reverse: a date value then a HARD-GATED label
/// (parenthesised abbrev `(DOB)`/`(date of birth)` OR an explicit `is (my) DOB`
/// connector). Both emit the VALUE only.
///
/// The reverse form (audit dob-value-then-label-leak) mirrors the CVV reverse
/// `123 (CVV)` so a date written BEFORE its label — `1990-01-02 (DOB)`,
/// `12/25/1990 is my DOB`, common in form dumps / EHR exports / chat — no longer
/// escapes a privacy proxy verbatim. It stays HARD-gated (parenthesised abbrev OR
/// explicit `is (my) DOB`/`date of birth` only, NEVER a bare trailing word) to preserve
/// FP-safety: a bare `1990-01-02 dob-related` or stray date never matches.
///
/// The day alternation in the year-first branch is ordered LONGEST-FIRST
/// (`3[01]|[12]\d|0?[1-9]`): `regex`'s leftmost-first alternation would otherwise let
/// `0?[1-9]` eat only the `1` of `15` and stop, truncating `2023-11-15` → `2023-11-1`
/// (audit V2). Month is a hard whitelist (kills `Maybe`/`Junket`/`Marvelous`).
pub struct DateOfBirthRecognizer {
    entities: Vec<EntityType>,
    /// label + GAP_NL + value  (`DOB: 1990-01-02`, `born January 2, 1990`).
    forward: Regex,
    /// value + hard-gated label  (`1990-01-02 (DOB)`, `12/25/1990 is my DOB`).
    reverse: Regex,
}

impl DateOfBirthRecognizer {
    pub fn new() -> Self {
        let label = r"(?i)\b(?:date\s+of\s+birth|d\.?o\.?b\.?|birth\s*date|born(?:\s+on)?)\b";
        let forward = format!("{label}{GAP_NL}{DOB_VALUE}");
        // Reverse: value (group 1) then a HARD-gated DOB label — a parenthesised abbrev
        // or an explicit `is (my) (dob|date of birth)` connector. No bare trailing word
        // (FP-safety). `\.?` after the abbrev tolerates `(D.O.B.)`.
        let reverse = format!(
            r"{DOB_VALUE}{}",
            r"(?:[ \t]{0,2}\((?i:d\.?o\.?b\.?|date\s+of\s+birth)\)|[ \t]+is[ \t]+(?:my[ \t]+)?(?i:d\.?o\.?b\.?|date\s+of\s+birth)\b)"
        );
        Self {
            entities: vec![custom(ENTITY_DATE_OF_BIRTH)],
            forward: Regex::new(&forward).expect("DOB forward recognizer regex must compile"),
            reverse: Regex::new(&reverse).expect("DOB reverse recognizer regex must compile"),
        }
    }
}

impl Default for DateOfBirthRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for DateOfBirthRecognizer {
    fn name(&self) -> &str {
        "DateOfBirthRecognizer"
    }
    fn supported_entities(&self) -> &[EntityType] {
        &self.entities
    }
    fn supported_languages(&self) -> &[&str] {
        &["en"]
    }
    fn analyze(
        &self,
        text: &str,
        _entities: Option<&[EntityType]>,
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        // Third-date-field guard (audit expiry-slashdate-third-field-leak, DOB dash
        // form): the year-first/D-M-Y branches end on a `\b` that a trailing `-`/`/`
        // separator satisfies, so `DOB: 1985-03-27-99` would mask `1985-03-27` and leak
        // `-99`. A value immediately followed by a date separator + digit is a malformed
        // over-long date, not a clean DOB — drop it rather than partial-mask.
        let guard = |full: &str, _: &regex::Match<'_>, value: &regex::Match<'_>| {
            !is_three_field_date_tail(full, value.end())
        };
        let mut out = gated_capture(&self.forward, &self.entities[0], self.name(), text, guard);
        out.extend(gated_capture(
            &self.reverse,
            &self.entities[0],
            self.name(),
            text,
            guard,
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// CREDIT_CARD_EXPIRATION
// ---------------------------------------------------------------------------

/// Window (chars, each side of the match) the card-context gate scans for a card
/// keyword or a Luhn-valid PAN. Mirrors the Purview/Google PAN-anchoring discipline.
const CARD_CONTEXT_WINDOW: usize = 40;

/// Credit-card expiration recognizer. Label (`exp`/`expiry`/`expiration`/`expires`/
/// `exp date`/`valid thru`/`valid through`/`good thru`) + [`GAP`] + a MM/YY-style
/// value; emits the VALUE only.
///
/// CARD-CONTEXT GATE (audit V3): a match whose label is an `exp*`/`expir*`/`expires`
/// form (the ubiquitous non-card log word — "cache expires 12/24", "cert expires Jan
/// 2026") EMITS ONLY IF a card keyword or a Luhn-valid 13-19-digit PAN appears within
/// ±[`CARD_CONTEXT_WINDOW`] chars. The card-exclusive `valid thru`/`valid through`/
/// `good thru` forms emit STANDALONE (no gate). Single-digit month `exp 1/27` is
/// admitted, safe ONLY behind this gate.
///
/// CONFIDENCE-TIERED LABEL (FIX 1b): the EMIT gate above is unchanged, but the EMITTED
/// LABEL is chosen per-match by SIGNAL STRENGTH within the ±[`CARD_CONTEXT_WINDOW`]:
///   - STRONG → [`ENTITY_CREDIT_CARD_EXPIRATION`]: a PLAUSIBLE Luhn-valid PAN (FIX 3)
///     in-window, OR an UNAMBIGUOUS payment term (word-boundary matched, FIX 2):
///     `credit card`/`debit card`/`mastercard`/`amex`/`american express`/`maestro`/
///     `jcb`/`diners`/`discover card`/`visa card`.
///   - ELSE → [`ENTITY_EXPIRATION_DATE`]: only an AMBIGUOUS keyword fired
///     (`card`/`visa`/`discover`) or a standalone `valid thru`/`valid through`/
///     `good thru`.
///
/// Bare `visa` is ALWAYS ambiguous → EXPIRATION_DATE unless a Visa-range Luhn PAN
/// confirms it. Masked tokens are visible to the upstream LLM, so a travel-visa /
/// gift-card expiry must NOT be mislabeled `CREDIT_CARD_EXPIRATION` (it would corrupt
/// the model's reasoning — "my visa runs out on [EXPIRATION_DATE]" reads true,
/// "[CREDIT_CARD_EXPIRATION]" does not). The mask is NEVER suppressed — only relabeled.
pub struct CardExpiryRecognizer {
    /// `[CREDIT_CARD_EXPIRATION, EXPIRATION_DATE]` — both possible emitted labels.
    entities: Vec<EntityType>,
    /// Strong (specific) label — emitted on STRONG payment evidence.
    strong_entity: EntityType,
    /// Neutral (weak-evidence) label — emitted when only ambiguous context fired.
    neutral_entity: EntityType,
    re: Regex,
}

impl CardExpiryRecognizer {
    pub fn new() -> Self {
        // The label is group 1 so the gate can read which form matched; the VALUE is
        // group 2 — but `gated_capture` emits group 1, so we instead build a regex
        // whose group 1 IS the value, and re-derive the label form from the match
        // text inside the gate predicate. Simpler & robust: keep value as group 1,
        // and let the gate inspect `whole.as_str()` for the label class.
        let label = r"(?i)\b(?:exp(?:iry|iration|ires?)?|exp\s+date|valid\s+thru|valid\s+through|good\s+thru)\b(?:\s+date)?";
        let value = concat!(
            r"(",
            // MM/YY or MM/YYYY (single-digit month admitted; safe behind the gate),
            // optional spaces around the separator (`03 / 27`). Year alt is 4-digit-FIRST
            // so MM/YYYY is preferred, and a trailing `\b` forces the whole adjacent
            // digit run to be consumed — an over-long run (`03/271`) fails the `\b`
            // mid-run rather than masking `03/27` and leaking the `1` (audit truncation).
            r"(?:0?[1-9]|1[0-2])\s?[/\-]\s?(?:\d{4}|\d{2})\b",
            // Month-name YYYY/YY (`Jan 2026`, `December 27`). Trailing `\b` mirrors the
            // numeric branch: an over-long run (`Jan 20265`) fails the whole match
            // rather than capturing `Jan 2026` and leaking the trailing `5` (audit
            // monthname-trailing-digit-leak). `valid thru`/`good thru` are standalone
            // (no card-context gate), so this branch leaks readily without the guard.
            r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)[\s\-]\d{2,4}\b",
            r")",
        );
        let pattern = format!("{label}{GAP}{value}");
        Self {
            entities: vec![
                custom(ENTITY_CREDIT_CARD_EXPIRATION),
                custom(ENTITY_EXPIRATION_DATE),
            ],
            strong_entity: custom(ENTITY_CREDIT_CARD_EXPIRATION),
            neutral_entity: custom(ENTITY_EXPIRATION_DATE),
            re: Regex::new(&pattern).expect("card-expiry recognizer regex must compile"),
        }
    }
}

impl Default for CardExpiryRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Card keywords whose presence (within the window) admits an `exp*` expiry match.
/// These gate EMISSION only (FIX 2 word-boundary matched) — the EMITTED LABEL is
/// chosen separately by [`STRONG_PAYMENT_TERMS`] vs ambiguous context (FIX 1b). The
/// AMBIGUOUS singletons here (`card`/`visa`/`discover`) admit the match but, alone,
/// yield the NEUTRAL `EXPIRATION_DATE` label (a travel visa / gift card / loyalty card
/// expiry); only a PAN or an unambiguous payment term promotes to CREDIT_CARD.
const CARD_KEYWORDS: &[&str] = &[
    "card",
    "credit",
    "debit",
    "visa",
    "mastercard",
    "amex",
    "discover",
    "jcb",
    "diners",
    "maestro",
];

/// UNAMBIGUOUS payment terms (FIX 1b STRONG signal): each, matched by WORD-BOUNDARY
/// token sequence (FIX 2), promotes the emitted label to [`ENTITY_CREDIT_CARD_EXPIRATION`].
/// These are payment-card-exclusive (a `credit card`/`mastercard`/`amex` cannot be a
/// travel visa). Bare `visa`/`discover`/`card` are DELIBERATELY ABSENT — they are
/// ambiguous (travel visa, loyalty/gift card, software discovery) and yield the neutral
/// label unless a Luhn PAN confirms payment. Multi-word terms match as
/// whitespace-separated token sequences (so `visa card` matches `... visa card ...`
/// token-wise but `Visalia` / `discard` / `scorecard` never do).
const STRONG_PAYMENT_TERMS: &[&str] = &[
    "credit card",
    "debit card",
    "mastercard",
    "amex",
    "american express",
    "maestro",
    "jcb",
    "diners",
    "discover card",
    "visa card",
];

/// True if `tokens` (the in-window text split on non-alphanumeric runs, lowercased)
/// contains every word of `term` as a CONTIGUOUS, whole-token subsequence — the
/// word-boundary discipline of FIX 2. A single-word `term` matches one token; a
/// multi-word `term` (`credit card`) matches consecutive tokens. So `discard`!~`card`,
/// `discovery`!~`discover`, `scorecard`/`wildcard`!~`card`, `Visalia`!~`visa`, while
/// `credit card`/`visa card` match their real token sequences.
fn tokens_contain_term(tokens: &[&str], term: &str) -> bool {
    let want: Vec<&str> = term.split_whitespace().collect();
    if want.is_empty() {
        return false;
    }
    tokens
        .windows(want.len())
        .any(|w| w.iter().zip(&want).all(|(t, k)| t == k))
}

/// Split `text` into lowercased alphanumeric tokens (non-alphanumeric is a boundary).
/// The token stream is what FIX-2 word-boundary keyword matching compares against, so
/// `discard exp` → `["discard", "exp"]` (no `card` token) and `discover card` →
/// `["discover", "card"]`.
fn alnum_tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Lazily-compiled detector for "is this label an `exp*`/`expir*`/`expires` form"
/// (gated) vs a card-exclusive `valid thru`/`good thru` (standalone). Anchored at the
/// match start so it classifies the label, not anything in the value.
fn exp_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*(?:exp\b|expir|expires)").expect("exp-label regex"))
}

/// True if `whole` (an expiry match) is the gated `exp*` family (vs the standalone
/// `valid thru`/`good thru` family).
fn is_gated_expiry_label(whole: &str) -> bool {
    exp_label_re().is_match(whole)
}

/// True if the text immediately after `value_end` (skipping optional spaces, since the
/// expiry value tolerates `12 / 25`) is a date separator (`/`, `-`, `.`) followed by an
/// ASCII digit — i.e. the captured value is the first two fields of a three-field date
/// (`MM/DD/YYYY`), not a two-field card expiry. Audit expiry-slashdate-third-field-leak.
fn is_three_field_date_tail(text: &str, value_end: usize) -> bool {
    let bytes = text.as_bytes();
    let mut i = value_end;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    let Some(&sep) = bytes.get(i) else {
        return false;
    };
    if sep != b'/' && sep != b'-' && sep != b'.' {
        return false;
    }
    let mut j = i + 1;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    matches!(bytes.get(j), Some(b) if b.is_ascii_digit())
}

/// Compute the ±[`CARD_CONTEXT_WINDOW`] char window (byte-window snapped to char
/// boundaries so a multibyte slice never panics) around `[m.start, m.end)`.
fn context_window<'a>(text: &'a str, m: &regex::Match<'_>) -> &'a str {
    let lo = m.start().saturating_sub(CARD_CONTEXT_WINDOW);
    let hi = (m.end() + CARD_CONTEXT_WINDOW).min(text.len());
    let lo = floor_char_boundary(text, lo);
    let hi = ceil_char_boundary(text, hi);
    &text[lo..hi]
}

/// True if a card keyword (FIX 2: WORD-BOUNDARY token-matched, so `discard`!~`card`,
/// `discovery`!~`discover`, `scorecard`!~`card`, `Visalia`!~`visa`) OR a plausible
/// Luhn-valid 13-19-digit PAN (FIX 3) appears within [`CARD_CONTEXT_WINDOW`] chars of
/// the match. This gates EMISSION; the label tier is chosen by
/// [`payment_signal_strength`].
fn has_card_context(text: &str, m: &regex::Match<'_>) -> bool {
    let window = context_window(text, m);
    let lower = window.to_ascii_lowercase();
    let tokens = alnum_tokens(&lower);
    if CARD_KEYWORDS.iter().any(|kw| tokens_contain_term(&tokens, kw)) {
        return true;
    }
    window_has_luhn_pan(window)
}

/// The signal strength of the payment context around an expiry match (FIX 1b). STRONG
/// (→ `CREDIT_CARD_EXPIRATION`) iff a plausible Luhn-valid PAN (FIX 3) is in-window OR
/// an UNAMBIGUOUS payment term ([`STRONG_PAYMENT_TERMS`], FIX-2 word-boundary matched)
/// fires; otherwise NEUTRAL (→ `EXPIRATION_DATE`). Bare `visa`/`discover`/`card` are
/// ambiguous and do NOT promote on their own — only a PAN or an unambiguous term does.
fn payment_signal_is_strong(text: &str, m: &regex::Match<'_>) -> bool {
    let window = context_window(text, m);
    let lower = window.to_ascii_lowercase();
    let tokens = alnum_tokens(&lower);
    if STRONG_PAYMENT_TERMS
        .iter()
        .any(|term| tokens_contain_term(&tokens, term))
    {
        return true;
    }
    // A plausible Luhn-valid PAN is STRONG evidence regardless of keywords — this is
    // also what confirms a bare `visa` (a Visa-range Luhn PAN in-window).
    window_has_luhn_pan(window)
}

fn floor_char_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Scan `window` for a Luhn-valid 13-19-digit PAN, tolerating space/dash grouping
/// (`4111 1111 1111 1111`).
///
/// A naive single-pass "merge any separator-joined run" mis-anchors when an unrelated
/// short number abuts the PAN with a space (`99 4111111111111111`): the merged 18-digit
/// run is not Luhn-valid, so the real PAN inside it is never tested and the expiry leaks
/// (audit luhn-pan-merge-fn). The fix tests 13-19-digit candidates anchored to
/// SEPARATOR-GROUP boundaries: the full separator-joined run, and — if that fails — each
/// suffix that begins at a later group start. This finds the embedded PAN behind a
/// `99 `/`5 ` decoy WITHOUT re-opening the arbitrary-interior FP (a single contiguous
/// non-PAN run like `1234567890123456`, whose only Luhn-valid sub-window starts at an
/// interior offset, still does not anchor).
fn window_has_luhn_pan(window: &str) -> bool {
    let bytes = window.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            // Collect the separator-joined run, recording the digit-stream index at
            // which each separator-delimited group begins (group starts = valid PAN
            // anchor points). A single space/dash between digits is a grouping separator
            // and is dropped from the stream.
            let mut digits: Vec<u8> = Vec::new();
            let mut group_starts: Vec<usize> = vec![0];
            let mut j = i;
            while j < bytes.len() {
                let b = bytes[j];
                if b.is_ascii_digit() {
                    digits.push(b - b'0');
                    j += 1;
                } else if (b == b' ' || b == b'-')
                    && j + 1 < bytes.len()
                    && bytes[j + 1].is_ascii_digit()
                {
                    j += 1;
                    group_starts.push(digits.len());
                } else {
                    break;
                }
            }
            if run_has_luhn_pan(&digits, &group_starts) {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

/// True if a 13-19-digit slice of `digits` that BEGINS at one of `group_starts` passes
/// Luhn. Group-boundary anchoring (vs arbitrary interior offsets) finds a PAN behind a
/// decoy short group while keeping a single contiguous non-PAN run from matching on a
/// stray interior Luhn-valid window (audit luhn-pan-merge-fn).
fn run_has_luhn_pan(digits: &[u8], group_starts: &[usize]) -> bool {
    for &start in group_starts {
        let avail = digits.len() - start;
        let max_len = avail.min(19);
        for len in 13..=max_len {
            let cand = &digits[start..start + len];
            // FIX 3 — PAN plausibility guard (Codex MINOR, "0000000000000 exp 03/27"):
            // a digit run that is ALL IDENTICAL (`0000…`, `1111…`) or has NO nonzero
            // digit is not a plausible PAN even when it happens to pass Luhn (an
            // all-zero run sums to 0 ≡ 0 mod 10). Reject before accepting the anchor.
            if !is_plausible_pan(cand) {
                continue;
            }
            if luhn_ok(cand) {
                return true;
            }
        }
    }
    false
}

/// FIX 3 PAN plausibility guard: reject candidates whose digits are ALL IDENTICAL
/// (`0000…`, `4444…`) or that contain NO nonzero digit (`000…`). A real PAN is never
/// a single repeated digit; an all-zero run also passes Luhn trivially (sum 0).
fn is_plausible_pan(digits: &[u8]) -> bool {
    let Some(&first) = digits.first() else {
        return false;
    };
    if digits.iter().all(|&d| d == first) {
        return false;
    }
    digits.iter().any(|&d| d != 0)
}

/// Luhn checksum over a slice of single decimal digits.
fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

impl Recognizer for CardExpiryRecognizer {
    fn name(&self) -> &str {
        "CardExpiryRecognizer"
    }
    fn supported_entities(&self) -> &[EntityType] {
        &self.entities
    }
    fn supported_languages(&self) -> &[&str] {
        &["en"]
    }
    fn analyze(
        &self,
        text: &str,
        _entities: Option<&[EntityType]>,
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        // Iterate captures directly (not via `gated_capture`) so the EMITTED LABEL can
        // be chosen per-match by signal strength (FIX 1b) — the EMIT decision and the
        // LABEL decision are distinct.
        let mut out = Vec::new();
        for caps in self.re.captures_iter(text) {
            let whole = caps.get(0).expect("group 0 always present");
            let Some(value) = caps.get(1) else {
                continue;
            };
            if value.start() >= value.end() {
                continue;
            }
            // --- EMIT gate (UNCHANGED — FIX 1b leaves the gate intact) ---
            // Third-date-field guard (audit expiry-slashdate-third-field-leak): a
            // captured value immediately followed by a date separator + digit is a
            // three-field US date (MM/DD/YYYY, MM/DD/YY, MM-DD-YYYY), NOT a card expiry.
            // The recognizer would otherwise mask only MM/DD and leak the trailing year
            // — a partial leak, worse than not masking. Drop it entirely.
            if is_three_field_date_tail(text, value.end()) {
                continue;
            }
            // `exp*` family needs in-window card context; `valid thru`/`good thru` are
            // card-exclusive ⇒ emit standalone.
            if is_gated_expiry_label(whole.as_str()) && !has_card_context(text, &whole) {
                continue;
            }
            // --- LABEL tier (FIX 1b): STRONG payment evidence → specific label;
            // ambiguous keyword / standalone `valid thru` → neutral label. ---
            let entity = if payment_signal_is_strong(text, &whole) {
                &self.strong_entity
            } else {
                &self.neutral_entity
            };
            out.push(
                RecognizerResult::new(entity.clone(), value.start(), value.end(), BASE_SCORE)
                    .with_recognizer(self.name().to_string()),
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// CVV
// ---------------------------------------------------------------------------

/// CVV recognizer. Label (`cvv`/`cvv2`/`cvc2`/`cav2`/`security code`/`card
/// verification value|code|number`/`card identification number`) + [`GAP_CVV`] + a 3-4
/// digit value; emits the VALUE only. Also matches the reverse forms `123 (CVV)` and
/// `123 is my CVV`.
///
/// Bare `cid`/`cvn`/`csc` are deliberately NOT labels: they collide catastrophically
/// with ids/ports/status codes in code traffic (audit V6). Bare `cvc` is likewise
/// dropped (only `cvc2` kept) for the same FP class (audit cvv-cvc-bare-label-codelog-fp).
/// The unambiguous multi-word `card identification number` IS kept.
pub struct CvvRecognizer {
    entities: Vec<EntityType>,
    /// label + gap + value. The UNAMBIGUOUS abbreviations use the `is`-connector gap
    /// (`CVV is 123`); the prose-capable multi-word labels use the TIGHT gap
    /// (`security code: 123`, NOT `security code is 200 lines`) — FIX 4.
    forward: Regex,
    /// value + hard-gated label  (`123 (CVV)`, `123 is my CVV`).
    reverse: Regex,
}

impl CvvRecognizer {
    pub fn new() -> Self {
        // Bare `cvc` is DROPPED (only `cvc2` kept): bare `cvc` + a `.`/`-`/space gap
        // false-positives on code/log identifiers and HTTP statuses (`the cvc 100`,
        // `response.cvc=404`) — the same FP class that retired `cid`/`cvn`/`csc`
        // (audit cvv-cvc-bare-label-codelog-fp). `cvc2` is unambiguous and kept. `cvv`
        // stays as the canonical, far-less-FP-prone synonym.
        //
        // FIX 4 — connector scope split. The `is` connector ([`GAP_CVV`]) is restricted
        // to the UNAMBIGUOUS abbreviations (`cvv`/`cvv2`/`cvc2`/`cav2`): for them `cvv
        // is 123` is unambiguously a CVV. The PROSE-CAPABLE multi-word labels (`security
        // code`/`card verification*`/`card identification number`) read like English
        // sentences, so the `is` connector would let `the security code is 200 lines`
        // bind the non-date integer `200`; they therefore require TIGHT adjacency
        // ([`GAP_CVV_TIGHT`], no `is`). Recall is preserved: `cvv is 123` still masks
        // (abbrev path); `security code: 123` / `security code 4821` still mask (tight
        // path); `the security code is 200 lines` does NOT.
        let abbr_label = r"(?i)\b(?:cvv2?|cvc2|cav2)\b";
        let prose_label = r"(?i)\b(?:security\s+code|card\s+verification(?:\s+(?:value|code|number))?|card\s+identification\s+number)\b";
        // Value group is kept OUTSIDE the label/gap alternation so it is ALWAYS group 1
        // (the single value capture `gated_capture` emits) regardless of which label
        // branch fired. abbrev+GAP_CVV(with `is`) | prose-label+GAP_CVV_TIGHT(no `is`).
        let forward = format!(
            r"(?:{abbr_label}{GAP_CVV}|{prose_label}{GAP_CVV_TIGHT})\b(\d{{3,4}})\b"
        );
        // Reverse: `123 (CVV)`/`123 is my CVV` — value (group 1) then a HARD-gated CVV
        // label: a parenthesised abbrev OR an explicit `is (my)` connector (mirrors the
        // DOB reverse form, audit cvv-reverse-is-my-connector-asymmetry). Never a bare
        // trailing word (preserves the C2 FP discipline). `security code` is admitted
        // only in the `is my` form (the parenthesised `(security code)` is unusual).
        let reverse = concat!(
            r"\b(\d{3,4})\b",
            r"(?:[ \t]{0,2}\((?i:cvv2?|cvc2|cav2)\)",
            r"|[ \t]+is[ \t]+(?:my[ \t]+)?(?i:cvv2?|cvc2|cav2|security\s+code))",
        );
        Self {
            entities: vec![custom(ENTITY_CVV)],
            forward: Regex::new(&forward).expect("CVV forward recognizer regex must compile"),
            reverse: Regex::new(reverse).expect("CVV reverse recognizer regex must compile"),
        }
    }
}

impl Default for CvvRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for CvvRecognizer {
    fn name(&self) -> &str {
        "CvvRecognizer"
    }
    fn supported_entities(&self) -> &[EntityType] {
        &self.entities
    }
    fn supported_languages(&self) -> &[&str] {
        &["en"]
    }
    fn analyze(
        &self,
        text: &str,
        _entities: Option<&[EntityType]>,
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        let mut out = gated_capture(
            &self.forward,
            &self.entities[0],
            self.name(),
            text,
            |_, _, _| true,
        );
        out.extend(gated_capture(
            &self.reverse,
            &self.entities[0],
            self.name(),
            text,
            |_, _, _| true,
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Profile;
    use crate::config::EngineConfig;
    use crate::detect::run_detection;
    use crate::surface::Surface;

    fn analyzer() -> presidio_analyzer::AnalyzerEngine {
        presidio_analyzer::default_analyzer("en")
            .with_context_enhancer(presidio_analyzer::LemmaContextAwareEnhancer::new())
    }

    // ---- direct-recognizer span checks (value-only) -----------------------

    fn dob_spans(text: &str) -> Vec<&str> {
        DateOfBirthRecognizer::new()
            .analyze(text, None, None)
            .iter()
            .filter_map(|r| r.text(text))
            .collect()
    }
    fn cvv_spans(text: &str) -> Vec<&str> {
        CvvRecognizer::new()
            .analyze(text, None, None)
            .iter()
            .filter_map(|r| r.text(text))
            .collect()
    }
    fn expiry_spans(text: &str) -> Vec<&str> {
        CardExpiryRecognizer::new()
            .analyze(text, None, None)
            .iter()
            .filter_map(|r| r.text(text))
            .collect()
    }
    /// `(emitted entity label, value slice)` for each expiry match — exercises the
    /// FIX-1b confidence-tiered relabel (CREDIT_CARD_EXPIRATION vs EXPIRATION_DATE).
    fn expiry_labeled(text: &str) -> Vec<(String, String)> {
        CardExpiryRecognizer::new()
            .analyze(text, None, None)
            .iter()
            .filter_map(|r| Some((r.entity_type.to_string(), r.text(text)?.to_string())))
            .collect()
    }

    /// Drive the real `has_card_context` gate by anchoring its `Match` on the literal
    /// `exp` token in `text` (the gate scans ±40 chars around the match either way).
    fn has_card_context_str(text: &str) -> bool {
        let probe = Regex::new(r"exp").expect("probe regex");
        let m = probe.find(text).expect("text must contain an `exp` token");
        has_card_context(text, &m)
    }

    #[test]
    fn dob_emits_value_only_span_not_label() {
        // The emitted slice is the date, NEVER the "DOB:" label.
        assert_eq!(dob_spans("DOB: 1990-01-02"), vec!["1990-01-02"]);
        assert_eq!(dob_spans("born January 2, 1990"), vec!["January 2, 1990"]);
        // Slash-date D/M/Y still matches (day first, then 01-12 month).
        assert_eq!(dob_spans("date of birth 27/03/1985"), vec!["27/03/1985"]);
        // US-format M/D/Y now ALSO matches (audit dob-us-mdy-leak): the month-first
        // branch fires only behind the hard DOB label, so it stays FP-safe.
        assert_eq!(dob_spans("date of birth 03/27/1985"), vec!["03/27/1985"]);
    }

    #[test]
    fn dob_us_mdy_slash_date_matches() {
        // Audit dob-us-mdy-leak / dob-mdy-fn: the US-majority M/D/Y form (day>12 in the
        // 2nd field) must mask. Previously a hard recall hole on confirmed PII.
        assert_eq!(dob_spans("DOB: 03/27/1985"), vec!["03/27/1985"]);
        assert_eq!(dob_spans("born 12/25/1990"), vec!["12/25/1990"]);
        assert_eq!(dob_spans("date of birth 3/27/85"), vec!["3/27/85"]);
        assert_eq!(dob_spans("DOB: 12/25/1990"), vec!["12/25/1990"]);
        // D/M/Y, Y-M-D, month-name, and 2-digit-year still resolve (no regression).
        assert_eq!(dob_spans("DOB: 27/03/1985"), vec!["27/03/1985"]);
        assert_eq!(dob_spans("DOB: 1985-03-27"), vec!["1985-03-27"]);
        assert_eq!(dob_spans("DOB: 2023-11-15"), vec!["2023-11-15"]);
        assert_eq!(dob_spans("born January 2, 1990"), vec!["January 2, 1990"]);
        // 13 is not a valid month ⇒ M/D/Y misses; 13 IS a valid day ⇒ D/M/Y catches it
        // (month 27>12 fails, so the whole value falls through to no-match here).
        assert!(dob_spans("DOB: 13/27/1985").is_empty());
    }

    #[test]
    fn dob_mdy_is_hard_label_gated_fp_safe() {
        // The M/D/Y branch only fires behind a hard DOB label. A bare US date with no
        // label (or a non-DOB label) must NOT mask — preserves the C2 FP corpus.
        assert!(dob_spans("03/27/1985").is_empty());
        assert!(dob_spans("export 03/27/1985").is_empty());
        assert!(dob_spans("ratio 01/12 today").is_empty());
        assert!(dob_spans("port 8080 03/27/1985").is_empty());
    }

    #[test]
    fn dob_year_first_full_capture_regression() {
        // Audit V2: the year-first day alternation must capture the FULL day; the
        // longest-first reorder fixes the `2023-11-15` → `2023-11-1` truncation.
        assert_eq!(dob_spans("DOB: 2023-11-15"), vec!["2023-11-15"]);
        assert_eq!(dob_spans("d.o.b. 1999-12-31"), vec!["1999-12-31"]);
    }

    #[test]
    fn dob_overlong_digit_run_no_truncated_leak() {
        // Audit expiry-dob-right-unbounded-truncation: a trailing `\b` forces the whole
        // adjacent digit run to be consumed, so an over-long run fails entirely instead
        // of masking a plausible prefix and leaking the suffix.
        assert!(
            dob_spans("DOB: 27/03/198567").is_empty(),
            "over-long D/M/Y run must not mask a truncated `27/03/1985` and leak `67`"
        );
        assert!(
            dob_spans("DOB: 27/03/85123").is_empty(),
            "over-long 2y-then-extra run must not mask a truncated prefix"
        );
        assert!(
            dob_spans("DOB: 199012251").is_empty(),
            "over-long compact run must not mask `19901225` and leak the trailing `1`"
        );
        // Month-name branch (audit dob-monthname-trailing-digit-leak): the trailing `\b`
        // must also force whole-run consumption here. Previously this branch lacked the
        // guard, so `January 15, 20235` masked `January 15, 2023` and leaked `5`.
        assert!(
            dob_spans("DOB: January 15, 20235").is_empty(),
            "over-long month-name year run must not mask `January 15, 2023` and leak `5`"
        );
        assert!(
            dob_spans("born March 5 19905").is_empty(),
            "over-long month-name year run must not mask `March 5 1990` and leak `5`"
        );
        // Well-formed month-name DOBs still match with the full correct span.
        assert_eq!(dob_spans("born January 2, 1990"), vec!["January 2, 1990"]);
        assert_eq!(dob_spans("born March 5, 1991"), vec!["March 5, 1991"]);
    }

    #[test]
    fn dob_colon_newline_tolerated_single_only() {
        // GAP_NL tolerates ONE colon-newline (privacy proxy must not leak it).
        assert_eq!(dob_spans("DOB:\n2023-11-15"), vec!["2023-11-15"]);
        // Multi-newline is beyond GAP_NL ⇒ not a DOB match.
        assert!(dob_spans("DOB:\n\n\n\n1990-01-02").is_empty());
    }

    #[test]
    fn dob_value_then_label_reverse_masks() {
        // Audit dob-value-then-label-leak: a date written BEFORE its label now masks
        // (value-only span), closing the asymmetry with the CVV reverse form. Both the
        // parenthesised abbrev and the explicit `is (my) DOB` connector are accepted.
        assert_eq!(dob_spans("1990-01-02 (DOB)"), vec!["1990-01-02"]);
        assert_eq!(
            dob_spans("Patient: 03/27/1985 (date of birth)"),
            vec!["03/27/1985"]
        );
        assert_eq!(dob_spans("12/25/1990 is my DOB"), vec!["12/25/1990"]);
        assert_eq!(
            dob_spans("March 5, 1991 is my date of birth"),
            vec!["March 5, 1991"]
        );
        // (D.O.B.) abbrev with dots tolerated.
        assert_eq!(dob_spans("1985-03-27 (D.O.B.)"), vec!["1985-03-27"]);
        // Forward form still works (no regression).
        assert_eq!(dob_spans("DOB 03/27/1985"), vec!["03/27/1985"]);
    }

    #[test]
    fn dob_value_then_label_reverse_is_hard_gated_fp_safe() {
        // The reverse form is HARD-gated: a bare trailing word (no parens, no `is (my)`
        // connector) must NOT match — preserves the C2 FP discipline.
        assert!(dob_spans("1990-01-02 dob-related ticket").is_empty());
        assert!(dob_spans("config 03/27/1985 born to run").is_empty());
        // A stray date with no DOB label at all stays unmatched.
        assert!(dob_spans("ratio 01/12 today").is_empty());
        assert!(dob_spans("port 8080 03/27/1985").is_empty());
        // `is` connector requires the DOB abbrev/phrase, not an arbitrary word.
        assert!(dob_spans("12/25/1990 is a holiday").is_empty());
    }

    #[test]
    fn dob_month_whitelist_rejects_lookalike_words() {
        // "Maybe"/"Junket"/"Marvelous" must NOT satisfy the month-name branch.
        assert!(dob_spans("born Maybe 2 2020").is_empty());
        assert!(dob_spans("born Junket 2 2020").is_empty());
    }

    #[test]
    fn dob_spaced_separator_numeric_dates_match() {
        // Audit dob-spaced-separator-fn: human-entered DOBs with spaces around the
        // separator (forms / EHR / chat) must mask, mirroring the expiry `\s?`. FP-safe
        // because the numeric branches only fire behind the hard DOB label gate.
        assert_eq!(dob_spans("DOB: 03 / 27 / 1985"), vec!["03 / 27 / 1985"]);
        assert_eq!(dob_spans("DOB: 1985 - 03 - 27"), vec!["1985 - 03 - 27"]);
        assert_eq!(
            dob_spans("date of birth 27 / 03 / 1985"),
            vec!["27 / 03 / 1985"]
        );
        // Contrast with the sibling expiry, which already tolerated spaces.
        assert_eq!(
            expiry_spans("card 4111111111111111 exp 03 / 27"),
            vec!["03 / 27"]
        );
        // Still hard-gated: a bare spaced date with no DOB label must NOT mask.
        assert!(dob_spans("03 / 27 / 1985").is_empty());
        assert!(dob_spans("export 03 / 27 / 1985").is_empty());
    }

    #[test]
    fn dob_iso_datetime_year_first_masks_date_portion() {
        // Audit dob-iso-datetime-leak: a DOB written as a full ISO timestamp must still
        // mask its date portion — the trailing `T<digit>` boundary terminates the date
        // cleanly without re-opening the over-long-digit-run truncation guard.
        assert_eq!(dob_spans("DOB: 1990-01-02T00:00"), vec!["1990-01-02"]);
        assert_eq!(dob_spans("d.o.b. 1999-12-31T23:59:59"), vec!["1999-12-31"]);
        // The over-long contiguous-DIGIT runs must still fail (the `T`-boundary relax
        // only admits a `T`/space after the day, never more digits).
        assert!(dob_spans("DOB: 199012251").is_empty());
        assert!(dob_spans("DOB: 27/03/198567").is_empty());
    }

    #[test]
    fn dob_dash_third_field_date_dropped() {
        // Audit expiry-slashdate-third-field-leak (DOB dash form): a malformed over-long
        // dash date (`1985-03-27-99`) must NOT mask `1985-03-27` and leak `-99`. The
        // third-field guard drops it entirely.
        assert!(dob_spans("DOB: 1985-03-27-99").is_empty());
        // Well-formed Y-M-D still masks (no spurious third field).
        assert_eq!(dob_spans("DOB: 1985-03-27"), vec!["1985-03-27"]);
        // A trailing separator that is NOT followed by a digit (prose) does not trip it.
        assert_eq!(dob_spans("DOB: 1985-03-27. Patient ok"), vec!["1985-03-27"]);
    }

    #[test]
    fn cvv_value_only_span_forward_and_reverse() {
        assert_eq!(cvv_spans("CVV: 123"), vec!["123"]);
        assert_eq!(cvv_spans("security code 4821"), vec!["4821"]);
        assert_eq!(cvv_spans("cvc2=4567"), vec!["4567"]);
        assert_eq!(cvv_spans("CVV is 123"), vec!["123"]);
        // Reverse form.
        assert_eq!(cvv_spans("123 (CVV)"), vec!["123"]);
    }

    #[test]
    fn cvv_is_connector_with_separator() {
        // Audit cvv-is-colon-secondary-gap: the `is` connector now admits a trailing
        // separator, so `CVV is: 123` masks (was leaking). Plain `is`, `is =`, etc. too.
        assert_eq!(cvv_spans("CVV is: 123"), vec!["123"]);
        assert_eq!(cvv_spans("CVV is = 123"), vec!["123"]);
        assert_eq!(cvv_spans("CVV is 123"), vec!["123"]);
        // The connector stays left-anchored on whitespace ⇒ never fires inside `this`.
        assert!(cvv_spans("this123").is_empty());
        assert!(cvv_spans("dish is fine, 123 customers").is_empty());
    }

    #[test]
    fn cvv_bare_cid_cvn_csc_are_not_labels() {
        // These FP magnets must NOT mask (audit V6).
        assert!(cvv_spans("cid=4096").is_empty());
        assert!(cvv_spans("cvn 123").is_empty());
        assert!(cvv_spans(r#"{"csc": 200}"#).is_empty());
        // But the unambiguous multi-word form IS kept.
        assert_eq!(cvv_spans("card identification number 321"), vec!["321"]);
    }

    // ---- FIX 4: `is`-connector scope restricted to unambiguous abbreviations ----

    #[test]
    fn fix4_is_connector_scope() {
        // FIX 4: the `is` connector is restricted to the UNAMBIGUOUS abbreviations.
        // RECALL — `cvv is 123` (abbrev) still masks via the `is` connector.
        assert_eq!(cvv_spans("cvv is 123"), vec!["123"]);
        assert_eq!(cvv_spans("cvc2 is 456"), vec!["456"]);
        // RECALL — tight-adjacency multi-word labels still mask.
        assert_eq!(cvv_spans("security code: 123"), vec!["123"]);
        assert_eq!(cvv_spans("security code 4821"), vec!["4821"]);
        // FP — the prose-capable `security code` must NOT use the `is` connector, so
        // "the security code is 200 lines long" no longer binds the non-date `200`.
        assert!(
            cvv_spans("the security code is 200 lines long").is_empty(),
            "prose `security code is N` must not bind a non-CVV integer"
        );
        // The other prose labels are likewise tight-only.
        assert!(cvv_spans("the card verification value is 200 lines").is_empty());
        assert!(cvv_spans("the card identification number is 200 lines").is_empty());
        // But the abbreviation `is` form remains (cvv/cvv2/cvc2/cav2).
        assert_eq!(cvv_spans("cav2 is 789"), vec!["789"]);
    }

    #[test]
    fn cvv_bare_cvc_label_is_dropped_fp_safe() {
        // Audit cvv-cvc-bare-label-codelog-fp: bare `cvc` is dropped (FP magnet on
        // code/log identifiers and HTTP statuses); only `cvc2` is kept.
        assert!(cvv_spans("the cvc 100 times").is_empty());
        assert!(cvv_spans("metric cvc 200 ok").is_empty());
        assert!(cvv_spans("response.cvc=404").is_empty());
        assert!(cvv_spans("obj.cvc.200").is_empty());
        // Dotted/dashed code paths no longer bind even the kept `cvc2` (GAP_CVV drops
        // `.`/`-` separators).
        assert!(cvv_spans("cvc2-500").is_empty());
        assert!(cvv_spans("obj.cvc2.200").is_empty());
        // `cvc2` with a whitespace/`:`/`=` separator IS still a valid CVV label.
        assert_eq!(cvv_spans("cvc2=4567"), vec!["4567"]);
        assert_eq!(cvv_spans("cvc2: 123"), vec!["123"]);
        // `cvv` (the canonical, less-FP-prone synonym) is untouched.
        assert_eq!(cvv_spans("CVV: 123"), vec!["123"]);
    }

    #[test]
    fn cvv_colon_newline_tolerated_single_only() {
        // Audit cvv-newline-gap-sad-leak: a CVV on the line after its label must mask —
        // SAD is strictly higher-sensitivity than DOB, which already tolerated this.
        assert_eq!(cvv_spans("CVV:\n123"), vec!["123"]);
        // Multi-newline beyond GAP_CVV stays unmatched (FP-safety boundary preserved).
        assert!(cvv_spans("CVV:\n\n\n\n123").is_empty());
    }

    #[test]
    fn cvv_value_then_label_is_my_connector_masks() {
        // Audit cvv-reverse-is-my-connector-asymmetry: value-first natural language
        // (`123 is my CVV`) must mask, mirroring the DOB reverse `is (my)` connector.
        assert_eq!(cvv_spans("123 is my CVV"), vec!["123"]);
        assert_eq!(cvv_spans("4567 is my cvc2"), vec!["4567"]);
        assert_eq!(cvv_spans("123 is my security code"), vec!["123"]);
        // Parenthesised reverse form still works (no regression).
        assert_eq!(cvv_spans("123 (CVV)"), vec!["123"]);
        // HARD-gated: a bare trailing word (no parens, no `is (my) <cvv-label>`) does
        // NOT match — preserves the C2 FP discipline.
        assert!(cvv_spans("100 is my goal").is_empty());
        assert!(cvv_spans("200 customers").is_empty());
    }

    #[test]
    fn expiry_card_context_gate() {
        // `exp*` family WITH card context emits; bare/non-card does not (audit V3).
        assert_eq!(
            expiry_spans("card 4111111111111111 exp 03/27"),
            vec!["03/27"]
        );
        assert_eq!(
            expiry_spans("expiration date 11/2028 on the visa"),
            vec!["11/2028"]
        );
        // Single-digit month, safe behind the gate.
        assert_eq!(expiry_spans("visa exp 1/27"), vec!["1/27"]);
        // No card context ⇒ the ubiquitous-log FP is killed.
        assert!(expiry_spans("the cache expires 12/24").is_empty());
        assert!(expiry_spans("certificate expires Jan 2026").is_empty());
        assert!(expiry_spans("retry ratio exp 12/24").is_empty());
    }

    #[test]
    fn expiry_valid_thru_is_card_exclusive_standalone() {
        // `valid thru`/`good thru` are card-exclusive ⇒ emit with NO card context.
        assert_eq!(expiry_spans("valid thru 03/27"), vec!["03/27"]);
        assert_eq!(expiry_spans("good thru 12/2030"), vec!["12/2030"]);
        assert_eq!(expiry_spans("valid through 06/29"), vec!["06/29"]);
    }

    // ---- FIX 1b: confidence-tiered expiry relabel -------------------------

    #[test]
    fn expiry_strong_evidence_labels_credit_card() {
        // FIX 1b STRONG: a plausible Luhn-valid PAN in-window OR an unambiguous payment
        // term (word-boundary matched) → CREDIT_CARD_EXPIRATION.
        assert_eq!(
            expiry_labeled("4111 1111 1111 1111 exp 03/27"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "03/27".into())],
            "Luhn PAN in-window ⇒ strong label"
        );
        assert_eq!(
            expiry_labeled("credit card on file, exp 03/27"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "03/27".into())],
            "`credit card` unambiguous payment term ⇒ strong label"
        );
        assert_eq!(
            expiry_labeled("mastercard exp 12/28"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "12/28".into())],
        );
        assert_eq!(
            expiry_labeled("american express card exp 12/28"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "12/28".into())],
        );
        // `visa card` (two-token unambiguous term) is strong even without a PAN.
        assert_eq!(
            expiry_labeled("visa card exp 06/29"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "06/29".into())],
        );
    }

    #[test]
    fn expiry_ambiguous_context_labels_neutral_expiration_date() {
        // FIX 1b ELSE: only an AMBIGUOUS keyword (bare `card`/`visa`/`discover`) or a
        // standalone `valid thru`/`good thru` fired ⇒ neutral EXPIRATION_DATE. A masked
        // CREDIT_CARD label would corrupt the upstream LLM's reasoning about a travel
        // visa / gift card.
        assert_eq!(
            expiry_labeled("my travel visa expires 03/26"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "03/26".into())],
            "bare `visa` is ALWAYS ambiguous ⇒ neutral label"
        );
        assert_eq!(
            expiry_labeled("my gift card expires 03/26"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "03/26".into())],
            "bare `card` ambiguous ⇒ neutral label"
        );
        assert_eq!(
            expiry_labeled("subscription valid thru 12/25"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "12/25".into())],
            "standalone `valid thru` ⇒ neutral label"
        );
        assert_eq!(
            expiry_labeled("good thru 12/2030"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "12/2030".into())],
        );
        // Bare `discover` (software discovery / discovery call) is ambiguous → neutral.
        assert_eq!(
            expiry_labeled("discover exp 06/29"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "06/29".into())],
        );
    }

    #[test]
    fn expiry_bare_visa_promoted_only_by_visa_range_pan() {
        // Bare `visa` alone is neutral; a Visa-range (4-leading) Luhn PAN in-window
        // confirms payment ⇒ promotes to the specific label.
        assert_eq!(
            expiry_labeled("visa 4111111111111111 exp 03/27"),
            vec![(ENTITY_CREDIT_CARD_EXPIRATION.into(), "03/27".into())],
        );
        // Without the PAN, the same bare `visa` stays neutral.
        assert_eq!(
            expiry_labeled("visa exp 03/27"),
            vec![(ENTITY_EXPIRATION_DATE.into(), "03/27".into())],
        );
    }

    #[test]
    fn supported_entities_lists_both_expiry_labels() {
        // FIX 1b: the recognizer declares BOTH labels it can emit.
        let rec = CardExpiryRecognizer::new();
        let labels: Vec<String> = rec
            .supported_entities()
            .iter()
            .map(|e| e.to_string())
            .collect();
        assert!(labels.contains(&ENTITY_CREDIT_CARD_EXPIRATION.to_string()));
        assert!(labels.contains(&ENTITY_EXPIRATION_DATE.to_string()));
    }

    // ---- FIX 2: word-boundary keyword matching ----------------------------

    #[test]
    fn fix2_word_boundary_keyword_no_substring_fp() {
        // Codex MAJOR reproduced: "discard exp 03/27" must NOT mask — `card` ⊂ `discard`
        // is a substring, but the word-boundary scan compares whole tokens.
        assert!(expiry_spans("discard exp 03/27").is_empty(), "discard ≁ card");
        assert!(
            expiry_spans("the discovery expires 03/27").is_empty(),
            "discovery ≁ discover"
        );
        assert!(
            expiry_spans("scorecard 1234 03/27").is_empty(),
            "scorecard ≁ card (and 1234 is no PAN)"
        );
        assert!(
            expiry_spans("wildcard exp 03/27").is_empty(),
            "wildcard ≁ card"
        );
        // `Visalia` (a city) must not satisfy the bare-`visa` keyword either.
        assert!(
            expiry_labeled("Visalia exp 03/27").is_empty(),
            "Visalia ≁ visa (and no PAN) ⇒ exp gate has no card context"
        );
        // Sanity: the real whole-token keyword DOES still admit the match.
        assert!(!expiry_spans("credit card exp 03/27").is_empty());
    }

    #[test]
    fn fix2_tokens_contain_term_unit() {
        // The token-sequence matcher: single tokens, multi-word sequences, and the
        // substring non-matches the gate relies on.
        let toks = alnum_tokens("the credit card on file exp 03 27");
        assert!(tokens_contain_term(&toks, "card"));
        assert!(tokens_contain_term(&toks, "credit card")); // contiguous tokens
        let discard = alnum_tokens("discard exp 03 27");
        assert!(!tokens_contain_term(&discard, "card")); // `discard` is one token
        let disco = alnum_tokens("the discovery expires");
        assert!(!tokens_contain_term(&disco, "discover"));
    }

    // ---- FIX 3: PAN plausibility guard ------------------------------------

    #[test]
    fn fix3_pan_plausibility_guard() {
        // Codex MINOR reproduced: "0000000000000 exp 03/27" — an all-zero run passes
        // Luhn (sum 0 ≡ 0 mod 10) but is not a plausible PAN. The guard rejects it, so
        // with no other card context the exp match is dropped.
        assert!(
            expiry_spans("0000000000000 exp 03/27").is_empty(),
            "all-zero run is not a plausible PAN anchor"
        );
        assert!(
            !has_card_context_str("0000000000000 exp 03/27"),
            "all-zero run does not anchor card context"
        );
        // All-identical nonzero run (a Luhn coincidence) is also rejected.
        assert!(!is_plausible_pan(&[4; 16]));
        assert!(!is_plausible_pan(&[0; 13]));
        // A genuine mixed-digit PAN is plausible.
        assert!(is_plausible_pan(&[4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
        // And the real PAN still anchors.
        assert!(has_card_context_str("4111111111111111 exp 03/27"));
    }

    #[test]
    fn exp_does_not_fire_inside_export() {
        // `\bexp` must not match inside "export" (word-boundary check).
        assert!(expiry_spans("export 03/27").is_empty());
    }

    #[test]
    fn luhn_pan_anchors_expiry_without_keyword() {
        // A Luhn-valid PAN within ±40 chars anchors the expiry even with no keyword.
        // 4111111111111111 is the canonical Luhn-valid test PAN.
        assert_eq!(expiry_spans("4111111111111111 exp 03/27"), vec!["03/27"]);
        // A non-Luhn 16-digit run does NOT anchor (and no keyword) ⇒ dropped.
        assert!(expiry_spans("1234567890123456 exp 03/27").is_empty());
    }

    #[test]
    fn luhn_pan_anchor_survives_decoy_prefix() {
        // Audit luhn-pan-merge-fn: a real PAN preceded by a short number + space used to
        // merge into one over-long non-Luhn run, dropping the anchor. The sliding-window
        // scan now finds the embedded 16-digit PAN regardless of the decoy.
        assert!(has_card_context_str("acct 99 4111111111111111 exp 03/27"));
        assert!(has_card_context_str("qty 5 4111111111111111 exp 03/27"));
        // The grouped form and the baseline still anchor.
        assert!(has_card_context_str("4111 1111 1111 1111 exp 03/27"));
        assert!(has_card_context_str("4111111111111111 exp 03/27"));
        // A run with no Luhn-valid 13-19-digit sub-window still does NOT anchor.
        assert!(!has_card_context_str("99 1234567890123456 exp 03/27"));
        // End-to-end: the decoy-prefixed expiry now masks (was leaking).
        assert_eq!(
            expiry_spans("acct 99 4111111111111111 exp 03/27"),
            vec!["03/27"]
        );
    }

    #[test]
    fn expiry_overlong_digit_run_no_truncated_leak() {
        // Audit expiry-dob-right-unbounded-truncation: the trailing `\b` forces the whole
        // adjacent digit run to be consumed, so `03/271` masks nothing (was masking
        // `03/27` and leaking the `1`). MM/YYYY is still preferred over MM/YY.
        assert!(
            expiry_spans("card 4111111111111111 exp 03/271").is_empty(),
            "over-long MM/YY run must not mask `03/27` and leak the trailing `1`"
        );
        assert!(
            expiry_spans("card 4111111111111111 exp 3/202712345").is_empty(),
            "over-long MM/YYYY run must not mask `3/2027` and leak the suffix"
        );
        // The well-formed cases still mask, and MM/YYYY binds the full 4-digit year.
        assert_eq!(
            expiry_spans("card 4111111111111111 exp 03/27"),
            vec!["03/27"]
        );
        assert_eq!(
            expiry_spans("card 4111111111111111 exp 3/2027"),
            vec!["3/2027"]
        );
        // Month-name branch (audit monthname-trailing-digit-leak): the trailing `\b`
        // must also force whole-run consumption. `valid thru`/`good thru` are standalone
        // (no card-context gate), so this is the readiest leak path. Previously
        // `valid thru Jan 20265` masked `Jan 2026` and leaked the trailing `5`.
        assert!(
            expiry_spans("valid thru Jan 20265").is_empty(),
            "over-long month-name year run must not mask `Jan 2026` and leak `5`"
        );
        assert!(
            expiry_spans("card 4111111111111111 exp December 12345").is_empty(),
            "over-long month-name year run must not mask `December 1234` and leak `5`"
        );
        // Well-formed month-name expiries still mask with the full correct span.
        assert_eq!(expiry_spans("valid thru Jan 2026"), vec!["Jan 2026"]);
        assert_eq!(expiry_spans("valid thru December 27"), vec!["December 27"]);
        assert_eq!(expiry_spans("valid thru Sep 99"), vec!["Sep 99"]);
    }

    #[test]
    fn expiry_three_field_slash_date_dropped_not_partial_leak() {
        // Audit expiry-slashdate-third-field-leak: a three-field US date (MM/DD/YYYY,
        // MM/DD/YY, MM-DD-YYYY) is NOT a card expiry. The recognizer must DROP it
        // entirely rather than mask MM/DD and leak the trailing year field.
        assert!(expiry_spans("valid thru 12/25/26").is_empty()); // was masking `12/25`, leaking `/26`
        assert!(expiry_spans("valid thru 03/27/2025").is_empty()); // was leaking `/2025`
        assert!(expiry_spans("card 4111111111111111 exp 03/27/2025").is_empty());
        assert!(expiry_spans("valid thru 03-27-2025").is_empty()); // dash form, was leaking `-2025`
        // Spaced three-field date also dropped (the value tolerates `03 / 27`).
        assert!(expiry_spans("valid thru 03 / 27 / 2025").is_empty());
        // Genuine two-field expiries still mask (no spurious third field). `exp` is
        // card-gated, so use a card-context line; `valid thru` is standalone.
        assert_eq!(
            expiry_spans("card 4111111111111111 exp 03/27"),
            vec!["03/27"]
        );
        assert_eq!(expiry_spans("valid thru 3/2027"), vec!["3/2027"]);
        assert_eq!(expiry_spans("valid thru Jan 2026"), vec!["Jan 2026"]);
        // A trailing separator NOT followed by a digit (sentence end) does not trip it.
        assert_eq!(expiry_spans("valid thru 03/27. Done."), vec!["03/27"]);
    }

    // ---- end-to-end through run_detection (category gate + score floor) ---
    //
    // `run_detection` runs a recognizer passed in the `ml` slot through Pass 2b — the
    // IDENTICAL category-gate / allow-list / score-floor / overlap path the registered
    // recognizers take in `from_parts`. So feeding one of our recognizers as `ml` is a
    // faithful end-to-end test of the gate + value-only span (the registration wiring
    // itself is proven in lib.rs).

    fn detect_via_slot(
        cfg: &EngineConfig,
        rec: &dyn Recognizer,
        text: &str,
    ) -> Vec<(String, String)> {
        run_detection(&analyzer(), cfg, &[], &[], Some(rec), text, Surface::UserMessage)
            .unwrap()
            .into_iter()
            .filter_map(|d| {
                let slice = text.get(d.start..d.end)?;
                Some((d.entity_type, slice.to_string()))
            })
            .collect()
    }

    #[test]
    fn recall_corpus_masks_under_balanced() {
        // The plan's revised C1 RECALL corpus, end-to-end through the gate under
        // Balanced (Identity + Financial on). Each row must yield its entity, spanning
        // ONLY the value.
        let cfg = EngineConfig::default(); // Balanced
        let dob = DateOfBirthRecognizer::new();
        let exp = CardExpiryRecognizer::new();
        let cvv = CvvRecognizer::new();

        for (rec, text, ent, value) in [
            (
                &dob as &dyn Recognizer,
                "DOB: 1990-01-02",
                ENTITY_DATE_OF_BIRTH,
                "1990-01-02",
            ),
            (&dob, "DOB:\n2023-11-15", ENTITY_DATE_OF_BIRTH, "2023-11-15"),
            (
                &dob,
                "born January 2, 1990",
                ENTITY_DATE_OF_BIRTH,
                "January 2, 1990",
            ),
            (
                &exp,
                "card 4111111111111111 exp 03/27",
                ENTITY_CREDIT_CARD_EXPIRATION,
                "03/27",
            ),
            (
                // Bare "visa" is AMBIGUOUS (travel visa) → the neutral label (FIX 1b);
                // the EMIT gate still fires (bare `card`/`visa` admits the match), only
                // the LABEL is neutral absent a PAN / unambiguous payment term.
                &exp,
                "expiration date 11/2028 on the visa",
                ENTITY_EXPIRATION_DATE,
                "11/2028",
            ),
            (&cvv, "CVV: 123", ENTITY_CVV, "123"),
            (&cvv, "cvv2=4567", ENTITY_CVV, "4567"),
            (&cvv, "123 (CVV)", ENTITY_CVV, "123"),
            (&cvv, "security code 4821", ENTITY_CVV, "4821"),
        ] {
            let got = detect_via_slot(&cfg, rec, text);
            assert!(
                got.iter().any(|(e, v)| e == ent && v == value),
                "recall miss for {text:?}: expected ({ent}, {value:?}), got {got:?}"
            );
        }
    }

    #[test]
    fn fp_corpus_zero_masks_under_balanced() {
        // The plan's revised C2 FP-safety corpus — 0 masks under Balanced.
        let cfg = EngineConfig::default();
        let dob = DateOfBirthRecognizer::new();
        let exp = CardExpiryRecognizer::new();
        let cvv = CvvRecognizer::new();

        for (rec, text) in [
            (&exp as &dyn Recognizer, "export 03/27"),
            (&exp, "the cache expires 12/24"),
            (&exp, "certificate expires Jan 2026"),
            (&cvv, "cid=4096"),
            (&cvv, r#"{"csc": 200}"#),
            (&dob, "DOB:\n\n\n\n123"),
            // FIX 6 adversarial NO-MASK corpus.
            (&exp, "discard exp 03/27"),                 // FIX 2 word-boundary
            (&exp, "the discovery expires 03/27"),       // FIX 2 word-boundary
            (&exp, "scorecard 1234 03/27"),              // FIX 2 + no PAN
            (&exp, "0000000000000 exp 03/27"),           // FIX 3 PAN plausibility
            (&cvv, "the security code is 200 lines long"), // FIX 4 `is`-scope
            (&exp, "the cache expires 12/24"),
            (&exp, "certificate expires Jan 2026"),
        ] {
            let got = detect_via_slot(&cfg, rec, text);
            assert!(
                got.is_empty(),
                "FP for {text:?}: expected 0 masks, got {got:?}"
            );
        }
    }

    #[test]
    fn fix6_label_correct_corpus_under_balanced() {
        // FIX 6 LABEL-CORRECT, end-to-end through the gate under Balanced: ambiguous
        // context → EXPIRATION_DATE; PAN / unambiguous payment term → CREDIT_CARD_EXPIRATION.
        let cfg = EngineConfig::default(); // Balanced
        let exp = CardExpiryRecognizer::new();
        for (text, ent, value) in [
            ("my travel visa expires 03/26", ENTITY_EXPIRATION_DATE, "03/26"),
            ("my gift card expires 03/26", ENTITY_EXPIRATION_DATE, "03/26"),
            (
                "subscription valid thru 12/25",
                ENTITY_EXPIRATION_DATE,
                "12/25",
            ),
            (
                "4111 1111 1111 1111 exp 03/27",
                ENTITY_CREDIT_CARD_EXPIRATION,
                "03/27",
            ),
            (
                "credit card on file, exp 03/27",
                ENTITY_CREDIT_CARD_EXPIRATION,
                "03/27",
            ),
        ] {
            let got = detect_via_slot(&cfg, &exp, text);
            assert!(
                got.iter().any(|(e, v)| e == ent && v == value),
                "label-correct miss for {text:?}: expected ({ent}, {value:?}), got {got:?}"
            );
            // And the WRONG strong/neutral sibling must NOT also be emitted.
            let wrong = if ent == ENTITY_EXPIRATION_DATE {
                ENTITY_CREDIT_CARD_EXPIRATION
            } else {
                ENTITY_EXPIRATION_DATE
            };
            assert!(
                !got.iter().any(|(e, _)| e == wrong),
                "{text:?} must NOT also emit the {wrong} sibling label, got {got:?}"
            );
        }
    }

    #[test]
    fn fix6_recall_corpus_under_balanced() {
        // FIX 6 RECALL: CVV / DOB recall paths still mask under Balanced.
        let cfg = EngineConfig::default();
        let dob = DateOfBirthRecognizer::new();
        let cvv = CvvRecognizer::new();
        for (rec, text, ent, value) in [
            (&cvv as &dyn Recognizer, "cvv is 123", ENTITY_CVV, "123"),
            (&cvv, "CVV: 123", ENTITY_CVV, "123"),
            (&cvv, "security code 4821", ENTITY_CVV, "4821"),
            (&dob, "DOB: 1990-01-02", ENTITY_DATE_OF_BIRTH, "1990-01-02"),
        ] {
            let got = detect_via_slot(&cfg, rec, text);
            assert!(
                got.iter().any(|(e, v)| e == ent && v == value),
                "recall miss for {text:?}: expected ({ent}, {value:?}), got {got:?}"
            );
        }
    }

    #[test]
    fn fix6_expiration_date_masks_under_identity_only_profile() {
        // FIX 6 + FIX 1a OR-semantics lock: the neutral EXPIRATION_DATE label masks
        // when ONLY Identity is enabled (Financial OFF) — proving dual category
        // membership + the `.any()` OR in `entity_enabled`. A travel-visa expiry is an
        // identity-document expiry, so an Identity-only deployment must still mask it.
        let cfg = EngineConfig {
            enabled_categories: [crate::config::Category::Identity].into_iter().collect(),
            ..EngineConfig::default()
        };
        let exp = CardExpiryRecognizer::new();
        let got = detect_via_slot(&cfg, &exp, "my travel visa expires 03/26");
        assert!(
            got.iter()
                .any(|(e, v)| e == ENTITY_EXPIRATION_DATE && v == "03/26"),
            "EXPIRATION_DATE must mask under Identity-only (Financial off): got {got:?}"
        );
        // Contrast: the STRONG credit-card label is Financial-only, so it is gated OFF
        // under Identity-only — a PAN-anchored expiry is dropped here.
        let got_cc = detect_via_slot(&cfg, &exp, "4111 1111 1111 1111 exp 03/27");
        assert!(
            !got_cc
                .iter()
                .any(|(e, _)| e == ENTITY_CREDIT_CARD_EXPIRATION),
            "CREDIT_CARD_EXPIRATION (Financial-only) must be gated off under Identity-only: {got_cc:?}"
        );
    }

    #[test]
    fn category_gate_keys_on_emitted_label_string() {
        // The recognizer's emitted Display string must equal the config const that the
        // gate matches on — else every detection is silently dropped.
        assert_eq!(
            custom(ENTITY_DATE_OF_BIRTH).to_string(),
            ENTITY_DATE_OF_BIRTH
        );
        assert_eq!(
            custom(ENTITY_CREDIT_CARD_EXPIRATION).to_string(),
            ENTITY_CREDIT_CARD_EXPIRATION
        );
        assert_eq!(custom(ENTITY_CVV).to_string(), ENTITY_CVV);
        // And these are NOT enabled under SecretsOnly.
        let secrets = EngineConfig::for_profile(Profile::SecretsOnly);
        assert!(!secrets.entity_enabled(ENTITY_CVV));
        assert!(!secrets.entity_enabled(ENTITY_DATE_OF_BIRTH));
    }

    // ---- C5 LabelMap remap (ML) — exercised WITHOUT loading a model -------

    /// The ML `private_date` label must remap to `Custom("PRIVATE_DATE")` (audit V4 —
    /// NOT `DATE_OF_BIRTH`, which would mislabel generic private dates as births). This
    /// exercises the `LabelMap` builder directly; no model/backend is loaded.
    #[cfg(feature = "ml")]
    #[test]
    fn ml_private_date_remaps_to_private_date_custom() {
        use crate::config::ENTITY_PRIVATE_DATE;
        use presidio_classifier::{LabelMap, OPENAI_PRIVACY_FILTER};

        // The tuple element type is fixed at `(SmolStr, EntityType)` by
        // `with_overrides`, so `.into()` infers `SmolStr` — no direct `smol_str` dep.
        let map = LabelMap::from_spec(&OPENAI_PRIVACY_FILTER).with_overrides([(
            "private_date".into(),
            EntityType::from_label(ENTITY_PRIVATE_DATE),
        )]);
        assert_eq!(
            map.translate("private_date"),
            Some(EntityType::from_label(ENTITY_PRIVATE_DATE)),
        );
        // And its Display equals the config const the Identity gate keys on.
        assert_eq!(
            map.translate("private_date").unwrap().to_string(),
            ENTITY_PRIVATE_DATE
        );
    }
}
