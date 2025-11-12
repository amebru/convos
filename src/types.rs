//! Core data types for conversations and messages.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// A conversation containing messages and artifacts.
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub created_at: Option<DateTime<Utc>>,
    pub messages: Vec<Message>,
    pub artifacts: Vec<Artifact>,
}

/// A message within a conversation.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// An artifact (file attachment) associated with a conversation.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub role: String,
    pub name: String,
    pub kind: String,
    pub size_bytes: Option<u64>,
    pub url: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

/// A lightweight summary of a conversation for listing and filtering.
#[derive(Debug, Clone)]
pub struct ConversationSummary {
    pub index: usize,
    pub id: String,
    pub title: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// The type of export format detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    ChatGpt,
    Claude,
}

// ChatGPT format types
#[derive(Debug, Deserialize)]
pub struct ChatGptConversationRecord {
    pub id: String,
    pub title: Option<String>,
    pub create_time: Option<f64>,
    pub current_node: Option<String>,
    pub mapping: HashMap<String, ChatGptConversationNode>,
}

#[derive(Debug, Deserialize)]
pub struct ChatGptConversationNode {
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub message: Option<ChatGptMessageRecord>,
}

#[derive(Debug, Deserialize)]
pub struct ChatGptMessageRecord {
    #[serde(default)]
    pub author: Option<ChatGptMessageAuthor>,
    #[serde(default)]
    pub create_time: Option<f64>,
    #[serde(default)]
    pub content: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ChatGptMessageAuthor {
    #[serde(default)]
    pub role: Option<String>,
}

// Claude format types
#[derive(Debug, Deserialize)]
pub struct ClaudeConversationRecord {
    pub uuid: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub chat_messages: Vec<ClaudeChatMessage>,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeChatMessage {
    pub sender: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub content: Vec<ClaudeContent>,
    #[serde(default)]
    pub attachments: Vec<Value>,
    #[serde(default)]
    pub files: Vec<Value>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeContent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
}
