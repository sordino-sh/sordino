//! Detection: presidio analyzer + custom rules, filtered and overlap-resolved
//! into a sorted, non-overlapping span list with a resolved operator each.

use presidio_analyzer::{AnalyzeRequest, AnalyzerEngine};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;

use crate::config::{CustomReplacement, EngineConfig, Operator};
use crate::error::EngineError;
use crate::surface::Surface;

/// A custom rule compiled to a regex (literal rules are escaped). Matching via
/// regex on the original text gives correct byte offsets for any case folding.
pub struct CompiledCustom {
    re: Regex,
    pub entity_type: String,
    pub literal_token: bool,
    pub token: Option<String>,
    pub priority: u32,
    pub surfaces: Option<HashSet<Surface>>,
}

pub fn compile_customs(rules: &[CustomReplacement]) -> Result<Vec<CompiledCustom>, EngineError> {
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let raw = if r.is_regex {
            r.pattern.clone()
        } else {
            regex::escape(&r.pattern)
        };
        let re = RegexBuilder::new(&raw)
            .case_insensitive(!r.case_sensitive)
            .build()
            .map_err(|source| EngineError::BadCustomRegex {
                pattern: r.pattern.clone(),
                source,
            })?;
        out.push(CompiledCustom {
            re,
            entity_type: r.entity_type.clone(),
            literal_token: r.literal_token,
            token: r.token.clone(),
            priority: r.priority,
            surfaces: r.apply_to_surfaces.clone(),
        });
    }
    // Lower `priority` value = higher precedence; apply those first.
    out.sort_by_key(|c| c.priority);
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Detection {
    pub start: usize,
    pub end: usize,
    pub entity_type: String,
    pub score: f32,
    pub operator: Operator,
    /// Fixed token for `literal_token` custom rules.
    pub fixed_token: Option<String>,
    pub is_custom: bool,
}

pub fn run_detection(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    text: &str,
    surface: Surface,
) -> Result<Vec<Detection>, EngineError> {
    let mut dets: Vec<Detection> = Vec::new();
    // Spans of allow-listed values; any detection fully contained in one of these
    // is also suppressed (allow-listing "admin@example.com" covers its
    // "example.com" sub-domain too).
    let mut allowed_spans: Vec<(usize, usize)> = Vec::new();

    // Pass 1: custom rules (already priority-sorted).
    for c in customs {
        if let Some(surfs) = &c.surfaces
            && !surfs.contains(&surface)
        {
            continue;
        }
        for m in c.re.find_iter(text) {
            let slice = &text[m.start()..m.end()];
            if cfg.allow_list.is_allowed(slice) {
                allowed_spans.push((m.start(), m.end()));
                continue;
            }
            let operator = if c.literal_token {
                Operator::Token
            } else {
                cfg.operator_for(&c.entity_type)
            };
            dets.push(Detection {
                start: m.start(),
                end: m.end(),
                entity_type: c.entity_type.clone(),
                score: 1.0,
                operator,
                fixed_token: if c.literal_token {
                    c.token.clone()
                } else {
                    None
                },
                is_custom: true,
            });
        }
    }

    // Pass 2: presidio analyzer.
    let results = analyzer
        .analyze(AnalyzeRequest::new(text, &cfg.language).score_threshold(cfg.score_threshold));
    for r in results {
        let entity_type = r.entity_type.to_string();
        if !cfg.entity_enabled(&entity_type) {
            continue;
        }
        let Some(slice) = r.text(text) else {
            continue;
        };
        if slice.is_empty() {
            continue;
        }
        if cfg.allow_list.is_allowed(slice) {
            allowed_spans.push((r.start, r.end));
            continue;
        }
        let operator = cfg.operator_for(&entity_type);
        dets.push(Detection {
            start: r.start,
            end: r.end,
            entity_type,
            score: r.score,
            operator,
            fixed_token: None,
            is_custom: false,
        });
    }

    // Suppress detections fully contained within an allow-listed span.
    if !allowed_spans.is_empty() {
        dets.retain(|d| {
            !allowed_spans
                .iter()
                .any(|(s, e)| *s <= d.start && d.end <= *e)
        });
    }

    Ok(resolve_overlaps(dets))
}

/// Keep the best detection on overlap: custom > presidio, then higher score, then
/// longer span. Returns the survivors sorted by `start`.
fn resolve_overlaps(mut dets: Vec<Detection>) -> Vec<Detection> {
    // Best first.
    dets.sort_by(|a, b| {
        b.is_custom
            .cmp(&a.is_custom)
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut kept: Vec<Detection> = Vec::new();
    for d in dets {
        let overlaps = kept.iter().any(|k| d.start < k.end && k.start < d.end);
        if !overlaps {
            kept.push(d);
        }
    }
    kept.sort_by_key(|d| d.start);
    kept
}
