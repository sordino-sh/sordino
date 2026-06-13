//! zlauder-proxy library surface: request masking, response unmasking, routing.
//! The binary (`main.rs`) is a thin wrapper around these modules.

// The proxy's ML lifecycle (`ml.rs`, `--download-model`) calls into
// `zlauder_engine::ml`, which only exists when at least one backend is compiled
// in. A backend-less proxy would be a regex-only build that silently can't
// honor `[engine.ml] enabled = true` — refuse at compile time instead. Lives in
// the lib root (not `main.rs`) so the clear message fires before `ml.rs`'s
// unresolved-`zlauder_engine::ml` errors would drown it.
#[cfg(not(any(feature = "ml", feature = "ml-http")))]
compile_error!(
    "zlauder-proxy needs at least one ML backend feature: build with `--features ml` \
     (local Candle), `--features ml-http` (remote endpoint), or the default (both)."
);

pub mod admin;
pub mod bind;
pub mod config;
pub mod headers;
pub mod ml;
pub mod monitor;
pub mod openai_chat;
pub mod openai_responses;
pub mod routes;
pub mod secrets;
pub mod sse;
pub mod state;
pub mod walk;

pub use routes::router;
pub use state::AppState;

#[cfg(test)]
mod test_support;
