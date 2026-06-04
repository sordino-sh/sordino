//! The four-arrow surface model (ported from orchestr8-privacy `lib.rs` arrows).
//!
//! ```text
//! Arrow 1: user   -> LLM          = MASK
//! Arrow 1: system -> LLM          = MASK
//! Arrow 4: tool output -> LLM     = MASK
//! Arrow 2: LLM -> display         = UNMASK
//! Arrow 3: LLM -> tool input      = UNMASK  (NEVER re-mask)
//! ```

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Arrow 1: user message text -> LLM. MASK.
    UserMessage,
    /// Arrow 1: system prompt / tool descriptions -> LLM. MASK.
    SystemPrompt,
    /// Arrow 4: tool output fed back to the LLM. MASK.
    ToolResult,
    /// Arrow 2: LLM-authored text -> display. UNMASK.
    AssistantText,
    /// Arrow 3: LLM-authored tool input -> tool. UNMASK (never re-mask).
    ToolUseInput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Mask,
    Unmask,
}

impl Surface {
    pub fn direction(self) -> Direction {
        match self {
            Surface::UserMessage | Surface::SystemPrompt | Surface::ToolResult => Direction::Mask,
            Surface::AssistantText | Surface::ToolUseInput => Direction::Unmask,
        }
    }
}
