//! File discovery and conversation loading.

use crate::parser::{detect_export_kind, parse_chatgpt_conversations, parse_claude_conversations};
use crate::types::{Conversation, ConversationSummary};
use anyhow::{Context, Result, anyhow};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SCAN_DEPTH: usize = 3;

/// Find all conversations.json files in the given directory, scanning up to 3 levels deep.
pub fn find_conversation_files(root: &Path) -> Result<Vec<PathBuf>> {
    if root.is_file() {
        let file_name = root.file_name().and_then(|name| name.to_str());
        if file_name == Some("conversations.json") {
            return Ok(vec![root.to_path_buf()]);
        }
        return Err(anyhow!(
            "expected conversations.json but found `{}`",
            root.display()
        ));
    }

    let direct = root.join("conversations.json");
    if direct.is_file() {
        return Ok(vec![direct]);
    }

    let mut results = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    let mut visited = HashSet::new();

    queue.push_back((root.to_path_buf(), 0));

    while let Some((current, depth)) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }

        if depth > MAX_SCAN_DEPTH {
            continue;
        }

        if current != root {
            let candidate = current.join("conversations.json");
            if candidate.is_file() {
                results.push(candidate);
                continue;
            }
        }

        if depth == MAX_SCAN_DEPTH {
            continue;
        }

        let entries = fs::read_dir(&current)
            .with_context(|| format!("reading directory `{}`", current.display()))?;
        for entry in entries {
            let entry =
                entry.with_context(|| format!("reading entry inside `{}`", current.display()))?;
            let path = entry.path();
            if path.is_dir() {
                queue.push_back((path, depth + 1));
            }
        }
    }

    if results.is_empty() {
        Err(anyhow!(
            "could not find conversations.json inside `{}`",
            root.display()
        ))
    } else {
        results.sort();
        results.dedup();
        Ok(results)
    }
}

/// Load all conversations from the given export directory.
///
/// This function automatically detects the export format (ChatGPT or Claude)
/// and parses the conversations accordingly.
pub fn load_conversations(path: &Path) -> Result<Vec<Conversation>> {
    let files = find_conversation_files(path)?;
    let mut conversations = Vec::new();
    let mut seen_ids = HashSet::new();

    for file_path in files {
        let raw = fs::read_to_string(&file_path)
            .with_context(|| format!("reading `{}`", file_path.display()))?;
        let json: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing `{}`", file_path.display()))?;
        let items = json
            .as_array()
            .ok_or_else(|| anyhow!("expected top-level array in `{}`", file_path.display()))?;

        let kind = detect_export_kind(items)?;
        let mut parsed = match kind {
            crate::types::ExportKind::ChatGpt => parse_chatgpt_conversations(&raw)?,
            crate::types::ExportKind::Claude => parse_claude_conversations(&raw)?,
        };

        parsed.retain(|conversation| seen_ids.insert(conversation.id.clone()));
        conversations.extend(parsed);
    }

    if conversations.is_empty() {
        Err(anyhow!("no conversations found in `{}`", path.display()))
    } else {
        Ok(conversations)
    }
}

/// Build summaries from a list of conversations, sorted by creation date (newest first).
pub fn build_summaries(conversations: &[Conversation]) -> Vec<ConversationSummary> {
    let mut summaries: Vec<_> = conversations
        .iter()
        .enumerate()
        .map(|(idx, conversation)| ConversationSummary {
            index: idx,
            id: conversation.id.clone(),
            title: if conversation.title.trim().is_empty() {
                "(untitled conversation)".to_string()
            } else {
                conversation.title.clone()
            },
            created_at: conversation.created_at,
        })
        .collect();

    summaries.sort_by(|a, b| {
        let a_key = a.created_at.map(|dt| dt.timestamp()).unwrap_or(i64::MIN);
        let b_key = b.created_at.map(|dt| dt.timestamp()).unwrap_or(i64::MIN);
        b_key.cmp(&a_key).then_with(|| a.index.cmp(&b.index))
    });

    summaries
}

/// Filter conversations by title or ID matching a query string.
pub fn filter_conversations<'a>(
    summaries: &'a [ConversationSummary],
    query: &str,
) -> Vec<&'a ConversationSummary> {
    let query_lower = query.to_lowercase();
    summaries
        .iter()
        .filter(|summary| {
            query.is_empty()
                || summary.title.to_lowercase().contains(&query_lower)
                || summary.id.to_lowercase().contains(&query_lower)
        })
        .collect()
}

/// Resolve a conversation ID string (either a number or hash) to an index.
///
/// The ID can be:
/// - A number (1-based index into the summaries list)
/// - A full conversation hash/UUID
/// - A prefix of a conversation hash/UUID
pub fn resolve_conversation_id(
    id_str: &str,
    summaries: &[ConversationSummary],
) -> Result<usize> {
    // Try to parse as a number first
    if let Ok(number) = id_str.parse::<usize>() {
        if number == 0 {
            return Err(anyhow!("Conversation number must be greater than zero."));
        }
        let index = number - 1;
        if index >= summaries.len() {
            return Err(anyhow!(
                "Conversation number {} out of range (1..={})",
                number,
                summaries.len()
            ));
        }
        return Ok(index);
    }

    // Otherwise, treat it as a hash (conversation ID)
    // Try exact match first
    for (idx, summary) in summaries.iter().enumerate() {
        if summary.id == id_str {
            return Ok(idx);
        }
    }

    // Try prefix match
    let matching: Vec<usize> = summaries
        .iter()
        .enumerate()
        .filter(|(_, summary)| summary.id.starts_with(id_str))
        .map(|(idx, _)| idx)
        .collect();

    match matching.len() {
        0 => Err(anyhow!("No conversation found with hash matching `{}`", id_str)),
        1 => Ok(matching[0]),
        _ => Err(anyhow!(
            "Ambiguous hash `{}`: matches {} conversations",
            id_str,
            matching.len()
        )),
    }
}

/// Find an artifact file in the export directory by name.
pub fn find_artifact_file(export_path: &Path, artifact_name: &str) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(export_path.to_path_buf());

    while let Some(current) = queue.pop_front() {
        let entries = fs::read_dir(&current)
            .with_context(|| format!("reading directory `{}`", current.display()))?;

        for entry in entries {
            let entry =
                entry.with_context(|| format!("reading entry in `{}`", current.display()))?;
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    // Exact match (case-insensitive)
                    if file_name.eq_ignore_ascii_case(artifact_name) {
                        candidates.push(path.clone());
                    }
                    // Partial match for files like "file-<id>-<uuid>.ext"
                    else if file_name.contains(artifact_name)
                        || artifact_name.contains(file_name)
                    {
                        candidates.push(path.clone());
                    }
                }
            } else if path.is_dir() {
                // Don't descend into .git or target directories
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if dir_name != ".git" && dir_name != "target" {
                        queue.push_back(path);
                    }
                }
            }
        }
    }

    // Prefer exact matches
    for candidate in &candidates {
        if let Some(file_name) = candidate.file_name().and_then(|n| n.to_str()) {
            if file_name.eq_ignore_ascii_case(artifact_name) {
                return Ok(candidate.clone());
            }
        }
    }

    // Fall back to any match
    if let Some(candidate) = candidates.first() {
        return Ok(candidate.clone());
    }

    Err(anyhow!(
        "could not find artifact file `{}` in export directory",
        artifact_name
    ))
}

/// Check if an artifact file exists in the export directory.
pub fn artifact_exists(export_path: &Path, artifact_name: &str) -> bool {
    find_artifact_file(export_path, artifact_name).is_ok()
}
