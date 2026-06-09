//! zlauder-proxy library surface: request masking, response unmasking, routing.
//! The binary (`main.rs`) is a thin wrapper around these modules.

pub mod admin;
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
