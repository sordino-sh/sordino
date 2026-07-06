//! Compile-time assembly of the monitor UI from split asset files.
//!
//! The HTML in `ui/monitor.html` carries two placeholder tokens:
//!   * `/* MONITOR_CSS */` inside a `<style>` element
//!   * `/* MONITOR_JS */`  inside a `<script>` element
//!
//! At compile time we `include_str!` the three assets and substitute the CSS
//! and JS at those placeholders, producing a single self-contained document.
//! The Frontend phase may replace the contents of the three asset files freely;
//! it must keep both placeholder tokens intact so this wiring still works.

use axum::body::Body;
use axum::response::Response;
use http::header::CONTENT_TYPE;

const HTML: &str = include_str!("ui/monitor.html");
const CSS: &str = include_str!("ui/monitor.css");
const JS: &str = include_str!("ui/monitor.js");

/// The placeholder tokens the HTML asset must contain exactly once each.
const CSS_PLACEHOLDER: &str = "/* MONITOR_CSS */";
const JS_PLACEHOLDER: &str = "/* MONITOR_JS */";

/// Assemble the full HTML document by injecting the CSS and JS assets.
fn assemble() -> String {
    HTML.replacen(CSS_PLACEHOLDER, CSS, 1)
        .replacen(JS_PLACEHOLDER, JS, 1)
}

pub async fn ui() -> Response {
    let mut r = Response::new(Body::from(assemble()));
    r.headers_mut()
        .insert(CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_present_and_substituted() {
        // The raw HTML must carry both placeholders for the wiring to work.
        assert!(HTML.contains(CSS_PLACEHOLDER));
        assert!(HTML.contains(JS_PLACEHOLDER));
        // After assembly the placeholders are gone and the assets are inlined.
        let doc = assemble();
        assert!(!doc.contains(CSS_PLACEHOLDER));
        assert!(!doc.contains(JS_PLACEHOLDER));
        assert!(doc.contains("<!doctype html>"));
    }
}
