//! FFI module for exposing Rust functionality to Swift via swift-bridge
//!
//! This module provides a Swift-compatible interface to the convos library,
//! allowing the macOS app to load and display conversations.

use std::path::PathBuf;

#[swift_bridge::bridge]
mod ffi {
    #[swift_bridge(swift_repr = "struct")]
    pub struct FfiMessage {
        pub role: String,
        pub content: String,
    }

    #[swift_bridge(swift_repr = "struct")]
    pub struct FfiArtifact {
        pub role: String,
        pub name: String,
        pub kind: String,
        pub size_bytes: u64,
        pub url: String,
        pub description: String,
        pub created_at: String,
    }

    #[swift_bridge(swift_repr = "struct")]
    pub struct FfiConversationSummary {
        pub index: usize,
        pub id: String,
        pub title: String,
        pub created_at: String,
    }

    #[swift_bridge(swift_repr = "struct")]
    pub struct FfiConversation {
        pub id: String,
        pub title: String,
        pub created_at: String,
        pub messages: Vec<FfiMessage>,
        pub artifacts: Vec<FfiArtifact>,
    }

    extern "Rust" {
        fn load_conversation_summaries(export_path: String) -> Result<Vec<FfiConversationSummary>, String>;
        fn load_conversation_by_id(export_path: String, conversation_id: String) -> Result<FfiConversation, String>;
        fn filter_conversations_by_query(
            summaries: Vec<FfiConversationSummary>,
            query: String
        ) -> Vec<FfiConversationSummary>;
        fn render_markdown_to_plain(markdown: String) -> String;
    }
}

// Implementation of the FFI functions

/// Load all conversations from an export directory
pub fn load_conversation_summaries(export_path: String) -> Result<Vec<ffi::FfiConversationSummary>, String> {
    let path = PathBuf::from(export_path);

    let conversations = crate::load_conversations(&path)
        .map_err(|e| format!("Failed to load conversations: {}", e))?;

    let summaries = crate::build_summaries(&conversations);

    let ffi_summaries = summaries
        .into_iter()
        .map(|s| ffi::FfiConversationSummary {
            index: s.index,
            id: s.id,
            title: s.title,
            created_at: s.created_at
                .map(crate::format_timestamp)
                .unwrap_or_else(|| "Unknown".to_string()),
        })
        .collect();

    Ok(ffi_summaries)
}

/// Load a specific conversation by ID
pub fn load_conversation_by_id(
    export_path: String,
    conversation_id: String
) -> Result<ffi::FfiConversation, String> {
    let path = PathBuf::from(export_path);

    let conversations = crate::load_conversations(&path)
        .map_err(|e| format!("Failed to load conversations: {}", e))?;

    let summaries = crate::build_summaries(&conversations);

    let resolved_index = crate::resolve_conversation_id(&conversation_id, &summaries)
        .map_err(|e| format!("Conversation '{}' not found: {}", conversation_id, e))?;

    let conversation = conversations
        .get(resolved_index)
        .ok_or_else(|| format!("Conversation index {} out of range", resolved_index))?
        .clone();

    let ffi_messages = conversation
        .messages
        .into_iter()
        .map(|m| ffi::FfiMessage {
            role: m.role,
            content: m.content,
        })
        .collect();

    let ffi_artifacts = conversation
        .artifacts
        .into_iter()
        .map(|a| ffi::FfiArtifact {
            role: a.role,
            name: a.name,
            kind: a.kind,
            size_bytes: a.size_bytes.unwrap_or(0),
            url: a.url.unwrap_or_default(),
            description: a.description.unwrap_or_default(),
            created_at: a.created_at
                .map(crate::format_timestamp)
                .unwrap_or_else(|| "Unknown".to_string()),
        })
        .collect();

    Ok(ffi::FfiConversation {
        id: conversation.id,
        title: conversation.title,
        created_at: conversation.created_at
            .map(crate::format_timestamp)
            .unwrap_or_else(|| "Unknown".to_string()),
        messages: ffi_messages,
        artifacts: ffi_artifacts,
    })
}

/// Filter conversations by search query
pub fn filter_conversations_by_query(
    summaries: Vec<ffi::FfiConversationSummary>,
    query: String
) -> Vec<ffi::FfiConversationSummary> {
    let native_summaries: Vec<crate::ConversationSummary> = summaries
        .iter()
        .map(|s| crate::ConversationSummary {
            index: s.index,
            id: s.id.clone(),
            title: s.title.clone(),
            created_at: None, // Not used for filtering
        })
        .collect();

    let filtered = crate::filter_conversations(&native_summaries, &query);

    // Convert back to FFI types
    summaries
        .into_iter()
        .filter(|s| filtered.iter().any(|f| f.id == s.id))
        .collect()
}

/// Render markdown content to plain text (strips formatting for now)
pub fn render_markdown_to_plain(markdown: String) -> String {
    // For now, just return the markdown as-is
    // The Swift side can handle rendering, or we can enhance this later
    markdown
}
