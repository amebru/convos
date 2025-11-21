//! Convos - A library for loading and parsing exported gen-AI conversations
//!
//! This library provides functionality for loading conversations from ChatGPT and Claude
//! export archives. It can be used as a standalone library or through the C FFI for
//! integration with other programming languages like Swift, Python, C++, etc.
//!
//! # Examples
//!
//! ## Loading conversations
//!
//! ```no_run
//! use convos::{load_conversations, build_summaries};
//! use std::path::Path;
//!
//! let export_path = Path::new("/path/to/export");
//! let conversations = load_conversations(export_path).unwrap();
//! let summaries = build_summaries(&conversations);
//!
//! for summary in summaries {
//!     println!("{}: {}", summary.id, summary.title);
//! }
//! ```
//!
//! ## Filtering conversations
//!
//! ```no_run
//! use convos::{load_conversations, build_summaries, filter_conversations};
//! use std::path::Path;
//!
//! let export_path = Path::new("/path/to/export");
//! let conversations = load_conversations(export_path).unwrap();
//! let summaries = build_summaries(&conversations);
//!
//! let filtered = filter_conversations(&summaries, "search query");
//! for summary in filtered {
//!     println!("{}: {}", summary.id, summary.title);
//! }
//! ```

pub mod types;
pub mod parser;
pub mod loader;
pub mod render;
pub mod ffi;

// Re-export commonly used types and functions for convenience
pub use types::{
    Conversation, Message, Artifact, ConversationSummary, ExportKind,
};
pub use loader::{
    load_conversations, build_summaries, filter_conversations,
    resolve_conversation_id, find_artifact_file, artifact_exists,
};
pub use parser::{
    detect_export_kind, parse_chatgpt_conversations, parse_claude_conversations,
};
pub use render::render_markdown;

/// Format a byte size into a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", value, UNITS[unit_index])
    }
}

/// Format a timestamp into a readable string.
pub fn format_timestamp(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
