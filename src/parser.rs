//! Parsing logic for ChatGPT and Claude conversation exports.

use crate::types::*;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashSet;

/// Detect the export format kind from a sample of conversation objects.
pub fn detect_export_kind(items: &[Value]) -> Result<ExportKind> {
    let Some(sample) = items.iter().find_map(|value| value.as_object()) else {
        return Err(anyhow!(
            "could not detect export format: no conversation objects found"
        ));
    };

    if sample.contains_key("mapping") {
        Ok(ExportKind::ChatGpt)
    } else if sample.contains_key("chat_messages") {
        Ok(ExportKind::Claude)
    } else {
        Err(anyhow!("unrecognised conversation schema"))
    }
}

/// Parse ChatGPT format conversations from raw JSON string.
pub fn parse_chatgpt_conversations(raw: &str) -> Result<Vec<Conversation>> {
    let records: Vec<ChatGptConversationRecord> =
        serde_json::from_str(raw).with_context(|| "decoding ChatGPT conversation schema")?;

    let mut conversations = Vec::with_capacity(records.len());
    for record in records {
        let created_at = record.create_time.and_then(timestamp_from_f64);
        let id = record.id.clone();
        let title = record
            .title
            .as_deref()
            .filter(|title| !title.trim().is_empty())
            .unwrap_or("(untitled conversation)")
            .to_string();
        let (messages, artifacts) = extract_chatgpt_messages(&record);
        conversations.push(Conversation {
            id,
            title,
            created_at,
            messages,
            artifacts,
        });
    }

    Ok(conversations)
}

/// Parse Claude format conversations from raw JSON string.
pub fn parse_claude_conversations(raw: &str) -> Result<Vec<Conversation>> {
    let records: Vec<ClaudeConversationRecord> =
        serde_json::from_str(raw).with_context(|| "decoding Claude conversation schema")?;

    let mut conversations = Vec::with_capacity(records.len());
    for record in records {
        let created_at = record.created_at.as_deref().and_then(parse_rfc3339);
        let title = record
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .or_else(|| record.summary.as_deref())
            .unwrap_or("(untitled conversation)")
            .to_string();

        let (messages, artifacts) = extract_claude_messages(record.chat_messages);

        conversations.push(Conversation {
            id: record.uuid,
            title,
            created_at,
            messages,
            artifacts,
        });
    }

    Ok(conversations)
}

fn extract_chatgpt_messages(convo: &ChatGptConversationRecord) -> (Vec<Message>, Vec<Artifact>) {
    let mut ordered_ids = Vec::new();
    let mut visited = HashSet::new();

    if let Some(current) = convo.current_node.as_deref() {
        let mut cursor = Some(current);
        while let Some(node_id) = cursor {
            if !visited.insert(node_id) {
                break;
            }
            ordered_ids.push(node_id.to_string());
            cursor = convo
                .mapping
                .get(node_id)
                .and_then(|node| node.parent.as_deref());
        }
        ordered_ids.reverse();
    } else {
        let mut nodes: Vec<_> = convo
            .mapping
            .iter()
            .filter_map(|(id, node)| {
                node.message
                    .as_ref()
                    .and_then(|message| message.create_time)
                    .map(|ts| (id.clone(), ts))
            })
            .collect();
        nodes.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        ordered_ids = nodes.into_iter().map(|(id, _)| id).collect();
    }

    let mut messages = Vec::new();
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();
    for id in ordered_ids {
        if let Some(node) = convo.mapping.get(&id) {
            if let Some(message) = &node.message {
                let role = message
                    .author
                    .as_ref()
                    .and_then(|author| author.role.as_deref())
                    .unwrap_or("unknown");
                let normalized_role = normalize_role(role);
                let timestamp = message.create_time.and_then(timestamp_from_f64);

                let added_artifact = collect_chatgpt_artifacts(
                    message,
                    &normalized_role,
                    timestamp,
                    &mut artifacts,
                    &mut seen,
                );

                if let Some(text) = extract_text(&message.content) {
                    if !text.trim().is_empty() {
                        messages.push(Message {
                            role: normalized_role.clone(),
                            content: text,
                        });
                        continue;
                    }
                }

                if added_artifact {
                    messages.push(Message {
                        role: normalized_role.clone(),
                        content: "[attachments uploaded]".to_string(),
                    });
                }
            }
        }
    }

    messages.retain(|message| !message.content.trim().is_empty());

    (messages, artifacts)
}

fn collect_chatgpt_artifacts(
    message: &ChatGptMessageRecord,
    role: &str,
    timestamp: Option<DateTime<Utc>>,
    artifacts: &mut Vec<Artifact>,
    seen: &mut HashSet<String>,
) -> bool {
    let mut added = false;

    if let Some(Value::Object(map)) = &message.content {
        if let Some(Value::Array(parts)) = map.get("parts") {
            for part in parts {
                if looks_like_artifact(part) {
                    added |= push_artifact(
                        artifacts,
                        seen,
                        role,
                        value_get_string(
                            part,
                            &["file_name", "name", "filename", "display_name", "title"],
                        ),
                        value_get_string(part, &["file_type", "mime_type", "type", "content_type"]),
                        "content part",
                        value_get_u64(part, &["file_size", "size", "bytes", "size_bytes"]),
                        value_get_string(part, &["download_url", "file_url", "url", "href"]),
                        value_get_string(part, &["description", "caption", "alt"]),
                        timestamp,
                    );
                }
            }
        }
    }

    if let Some(Value::Object(meta)) = message.metadata.as_ref() {
        if let Some(Value::Array(attachments)) = meta.get("attachments") {
            for attachment in attachments {
                added |= push_artifact(
                    artifacts,
                    seen,
                    role,
                    value_get_string(
                        attachment,
                        &["file_name", "name", "filename", "display_name", "title"],
                    ),
                    value_get_string(attachment, &["file_type", "mime_type", "type"]),
                    "attachment",
                    value_get_u64(attachment, &["file_size", "size", "bytes", "size_bytes"]),
                    value_get_string(attachment, &["download_url", "file_url", "url", "href"]),
                    value_get_string(attachment, &["description", "caption", "alt"]),
                    timestamp,
                );
            }
        }
    }

    added
}

fn extract_claude_messages(chat_messages: Vec<ClaudeChatMessage>) -> (Vec<Message>, Vec<Artifact>) {
    let mut messages = Vec::new();
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();

    for message in chat_messages {
        let role = normalize_role(message.sender.as_str());
        let timestamp = message.created_at.as_deref().and_then(parse_rfc3339);

        let mut added_artifact = false;

        for attachment in &message.attachments {
            added_artifact |= push_artifact(
                &mut artifacts,
                &mut seen,
                &role,
                value_get_string(
                    attachment,
                    &["file_name", "name", "filename", "display_name", "title"],
                ),
                value_get_string(attachment, &["file_type", "type", "mime_type"]),
                "attachment",
                value_get_u64(attachment, &["file_size", "size", "bytes", "size_bytes"]),
                value_get_string(attachment, &["download_url", "file_url", "url", "href"]),
                value_get_string(attachment, &["description", "caption"]),
                timestamp,
            );
        }

        for file in &message.files {
            added_artifact |= push_artifact(
                &mut artifacts,
                &mut seen,
                &role,
                value_get_string(
                    file,
                    &["file_name", "name", "filename", "display_name", "title"],
                ),
                value_get_string(file, &["file_type", "type", "mime_type"]),
                "file",
                value_get_u64(file, &["file_size", "size", "bytes", "size_bytes"]),
                value_get_string(file, &["download_url", "file_url", "url", "href"]),
                value_get_string(file, &["description", "caption"]),
                timestamp,
            );
        }

        let text = message
            .text
            .as_deref()
            .filter(|text| !text.trim().is_empty())
            .map(|text| text.to_string())
            .or_else(|| aggregate_claude_content(&message.content));

        if let Some(content) = text {
            messages.push(Message {
                role: role.clone(),
                content,
            });
        } else if added_artifact {
            messages.push(Message {
                role: role.clone(),
                content: "[attachments uploaded]".to_string(),
            });
        }
    }

    messages.retain(|message| !message.content.trim().is_empty());

    (messages, artifacts)
}

fn aggregate_claude_content(segments: &[ClaudeContent]) -> Option<String> {
    let mut parts = Vec::new();
    for segment in segments {
        match segment.kind.as_str() {
            "text" => {
                if let Some(text) = segment.text.as_deref() {
                    if !text.trim().is_empty() {
                        parts.push(text.to_string());
                    }
                }
            }
            other => parts.push(format!("[{other} content]")),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

fn normalize_role(role: &str) -> String {
    match role.to_lowercase().as_str() {
        "human" | "user" => "user".to_string(),
        "assistant" => "assistant".to_string(),
        "system" => "system".to_string(),
        "tool" => "tool".to_string(),
        other => other.to_string(),
    }
}

fn extract_text(value: &Option<Value>) -> Option<String> {
    let value = value.as_ref()?;
    match value {
        Value::Object(map) => {
            let mut parts_out = Vec::new();

            if let Some(Value::Array(parts)) = map.get("parts") {
                for part in parts {
                    match part {
                        Value::String(text) => {
                            if !text.trim().is_empty() {
                                parts_out.push(text.to_string());
                            }
                        }
                        Value::Object(obj) => {
                            if let Some(Value::String(text)) = obj.get("text") {
                                if !text.trim().is_empty() {
                                    parts_out.push(text.to_string());
                                }
                            } else if let Some(Value::String(kind)) = obj.get("type") {
                                let label = obj
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map(|name| format!("[{kind}: {name}]"))
                                    .unwrap_or_else(|| format!("[{kind} content]"));
                                parts_out.push(label);
                            }
                        }
                        _ => {}
                    }
                }
            }

            if parts_out.is_empty() {
                if let Some(Value::String(text)) = map.get("text") {
                    if !text.trim().is_empty() {
                        parts_out.push(text.to_string());
                    }
                }
            }

            if parts_out.is_empty() {
                None
            } else {
                Some(parts_out.join("\n\n"))
            }
        }
        Value::String(text) => {
            if text.trim().is_empty() {
                None
            } else {
                Some(text.to_string())
            }
        }
        _ => None,
    }
}

fn timestamp_from_f64(ts: f64) -> Option<DateTime<Utc>> {
    if !ts.is_finite() {
        return None;
    }
    let seconds = ts.trunc() as i64;
    let fraction = (ts - seconds as f64).clamp(0.0, 0.999_999_999_9);
    let mut nanos = (fraction * 1_000_000_000.0).round() as u32;
    if nanos >= 1_000_000_000 {
        nanos = 999_999_999;
    }
    DateTime::<Utc>::from_timestamp(seconds, nanos)
}

fn parse_rfc3339(input: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(input)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

// Helper functions for working with JSON values

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                Some(u.to_string())
            } else if let Some(i) = num.as_i64() {
                Some(i.to_string())
            } else if let Some(f) = num.as_f64() {
                Some(f.to_string())
            } else {
                None
            }
        }
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_get_string(value: &Value, keys: &[&str]) -> Option<String> {
    if keys.is_empty() {
        return value_as_string(value);
    }
    if let Value::Object(map) = value {
        for key in keys {
            if let Some(entry) = map.get(*key) {
                if let Some(result) = value_as_string(entry) {
                    let trimmed = result.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                } else if let Some(result) = value_get_string(entry, &[]) {
                    let trimmed = result.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        for nested_key in ["display", "metadata", "data"] {
            if let Some(entry) = map.get(nested_key) {
                if let Some(result) = value_get_string(entry, keys) {
                    let trimmed = result.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                Some(u)
            } else if let Some(i) = num.as_i64() {
                (i >= 0).then_some(i as u64)
            } else if let Some(f) = num.as_f64() {
                if f >= 0.0 {
                    Some(f.floor() as u64)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn value_get_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    if keys.is_empty() {
        return value_as_u64(value);
    }
    if let Value::Object(map) = value {
        for key in keys {
            if let Some(entry) = map.get(*key) {
                if let Some(result) = value_as_u64(entry) {
                    return Some(result);
                }
            }
        }
    }
    None
}

fn push_artifact(
    artifacts: &mut Vec<Artifact>,
    seen: &mut HashSet<String>,
    role: &str,
    name: Option<String>,
    kind_hint: Option<String>,
    default_kind: &str,
    size_bytes: Option<u64>,
    url: Option<String>,
    description: Option<String>,
    created_at: Option<DateTime<Utc>>,
) -> bool {
    let name = name
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "(unnamed attachment)".to_string());
    let kind = kind_hint
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| default_kind.to_string());
    let url = url
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    let description = description
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());

    let key = format!("{}|{}|{}", role, name, url.clone().unwrap_or_default());
    if !seen.insert(key) {
        return false;
    }

    artifacts.push(Artifact {
        role: role.to_string(),
        name,
        kind,
        size_bytes,
        url,
        description,
        created_at,
    });
    true
}

fn looks_like_artifact(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let type_hint = map
                .get("type")
                .and_then(|entry| entry.as_str())
                .map(|entry| entry.to_lowercase())
                .unwrap_or_default();
            map.contains_key("file_name")
                || map.contains_key("filename")
                || map.contains_key("file_id")
                || map.contains_key("download_url")
                || map.contains_key("file_url")
                || map.contains_key("asset_pointer")
                || type_hint.contains("file")
                || type_hint.contains("attachment")
                || type_hint.contains("image")
        }
        _ => false,
    }
}
