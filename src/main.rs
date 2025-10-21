use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

fn main() -> Result<()> {
    let mut args = env::args_os();
    let _ = args.next(); // executable name

    let Some(export_arg) = args.next() else {
        eprintln!("Usage: chatgpt-reader <path-to-export>");
        std::process::exit(64);
    };

    if args.next().is_some() {
        eprintln!("Only one export path is expected.");
        std::process::exit(64);
    }

    let export_path = PathBuf::from(export_arg);
    if !export_path.exists() {
        eprintln!(
            "The provided path `{}` does not exist.",
            export_path.display()
        );
        std::process::exit(66);
    }

    if !export_path.is_dir() {
        eprintln!(
            "The provided path `{}` is not a directory.",
            export_path.display()
        );
        std::process::exit(66);
    }

    if let Err(err) = run(&export_path) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
    Ok(())
}

fn run(export_path: &Path) -> Result<()> {
    println!(
        "Opening export at `{}`...",
        export_path
            .canonicalize()
            .unwrap_or_else(|_| export_path.to_path_buf())
            .display()
    );

    print!("  Loading conversations.json ... ");
    io::stdout().flush()?;
    let conversations = load_conversations(export_path)?;
    println!("done ({} conversation(s)).", conversations.len());

    print!("  Indexing conversations ... ");
    io::stdout().flush()?;
    let summaries = build_summaries(&conversations);
    println!("done.");

    browse_conversations(&conversations, &summaries)?;

    println!("Goodbye!");
    Ok(())
}

fn load_conversations(path: &Path) -> Result<Vec<ConversationRecord>> {
    let file_path = path.join("conversations.json");
    let file = fs::File::open(&file_path)
        .with_context(|| format!("opening conversations file at {file_path:?}"))?;
    let conversations: Vec<ConversationRecord> =
        serde_json::from_reader(file).with_context(|| "parsing conversations.json")?;
    Ok(conversations)
}

fn build_summaries(conversations: &[ConversationRecord]) -> Vec<ConversationSummary> {
    let mut summaries: Vec<_> = conversations
        .iter()
        .enumerate()
        .map(|(idx, convo)| ConversationSummary {
            index: idx,
            id: convo.id.clone(),
            title: convo
                .title
                .as_deref()
                .filter(|title| !title.trim().is_empty())
                .unwrap_or("(untitled conversation)")
                .to_string(),
            create_time: convo.create_time,
        })
        .collect();

    summaries.sort_by(|a, b| {
        let a_time = a.create_time.unwrap_or(f64::MIN);
        let b_time = b.create_time.unwrap_or(f64::MIN);
        b_time
            .partial_cmp(&a_time)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    summaries
}

fn browse_conversations(
    conversations: &[ConversationRecord],
    summaries: &[ConversationSummary],
) -> Result<()> {
    println!("Commands: press Enter to list all, type text to filter titles, `q` to quit.");

    loop {
        print!("\nsearch> ");
        io::stdout().flush()?;
        let input = read_line()?;
        let trimmed = input.trim();

        if trimmed.eq_ignore_ascii_case("q") {
            return Ok(());
        }

        let matches = filter_conversations(summaries, trimmed);
        if matches.is_empty() {
            if trimmed.is_empty() {
                println!("No conversations available.");
            } else {
                println!("No conversations matched `{trimmed}`.");
            }
            continue;
        }

        let total = show_matches(&matches);

        if total == 0 {
            println!("Nothing to select; refine the search.");
            continue;
        }

        let Some(choice) = prompt_match_choice(total)? else {
            continue;
        };

        let summary = &matches[choice].summary;
        let conversation = &conversations[summary.index];

        println!("\n=== {} ===", summary.title);
        if let Some(created) = summary.create_time.and_then(format_timestamp) {
            println!("Started: {created}");
        }
        println!("Conversation ID: {}", summary.id);
        println!("----------------------------------------");

        let messages = extract_conversation_messages(conversation);
        if messages.is_empty() {
            println!("[No printable messages in this conversation]");
        } else {
            for message in messages {
                println!(
                    // "\n{role} {time}\n{content}",
                    "\n{role}{content}",
                    role = format_role(&message.role),
                    // time = message
                    //     .time
                    //     .and_then(format_timestamp)
                    //     .map(|t| format!("({t})"))
                    //     .unwrap_or_default(),
                    content = message.content
                );
            }
        }

        println!("\n----------------------------------------");
        println!("Press Enter to return to the search prompt.");
        if read_line().is_err() {
            return Ok(());
        }
    }
}

fn filter_conversations<'a>(
    summaries: &'a [ConversationSummary],
    query: &str,
) -> Vec<MatchedConversation<'a>> {
    let query_lower = query.to_lowercase();
    summaries
        .iter()
        .filter_map(|summary| {
            if query.is_empty()
                || summary.title.to_lowercase().contains(&query_lower)
                || summary.id.to_lowercase().contains(&query_lower)
            {
                Some(MatchedConversation { summary })
            } else {
                None
            }
        })
        .collect()
}

fn show_matches(matches: &[MatchedConversation<'_>]) -> usize {
    println!("Found {} conversation(s).", matches.len());

    for (ordinal, matched) in matches.iter().enumerate().rev() {
        let summary = matched.summary;
        let timestamp = summary
            .create_time
            .and_then(format_timestamp)
            .unwrap_or_else(|| "unknown time".to_string());
        println!(
            "[{index:>2}] {title} — {timestamp}",
            index = ordinal + 1,
            title = summary.title
        );
    }

    matches.len()
}

fn prompt_match_choice(count: usize) -> Result<Option<usize>> {
    if count == 0 {
        return Ok(None);
    }
    println!("Select a conversation number from the list or press Enter to search again.");
    loop {
        print!("choice> ");
        io::stdout().flush()?;
        let input = read_line()?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if let Ok(num) = trimmed.parse::<usize>() {
            if (1..=count).contains(&num) {
                return Ok(Some(num - 1));
            }
        }
        println!("Please enter a number between 1 and {count}, or press Enter to cancel.");
    }
}

fn extract_conversation_messages(convo: &ConversationRecord) -> Vec<MessageView> {
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
        // Fallback: include every node with a timestamp, sorted chronologically.
        let mut nodes: Vec<_> = convo
            .mapping
            .iter()
            .filter_map(|(id, node)| {
                node.message
                    .as_ref()
                    .and_then(|m| m.create_time)
                    .map(|ts| (id.clone(), ts))
            })
            .collect();
        nodes.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        ordered_ids = nodes.into_iter().map(|(id, _)| id).collect();
    }

    let mut messages = Vec::new();
    for id in ordered_ids {
        if let Some(node) = convo.mapping.get(&id) {
            if let Some(message) = &node.message {
                let role = message
                    .author
                    .as_ref()
                    .and_then(|author| author.role.as_deref())
                    .unwrap_or("unknown")
                    .to_string();
                if let Some(text) = extract_text(&message.content) {
                    if text.trim().is_empty() {
                        continue;
                    }
                    messages.push(MessageView {
                        role,
                        content: text,
                        time: message.create_time,
                    });
                }
            }
        }
    }

    messages
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

fn format_role(role: &str) -> String {
    match role {
        // "user" => "USER".to_string(),
        "user" => "\n>>> ".to_string(),
        // "assistant" => "ASSISTANT".to_string(),
        "assistant" => "".to_string(),
        // "system" => "SYSTEM".to_string(),
        // "tool" => "TOOL".to_string(),
        other => format!("<{}>", other),
    }
}

fn format_timestamp(ts: f64) -> Option<String> {
    if !ts.is_finite() {
        return None;
    }
    let seconds = ts.trunc() as i64;
    let fraction = (ts - seconds as f64).clamp(0.0, 0.999_999_999_9);
    let mut nanos = (fraction * 1_000_000_000.0).round() as u32;
    if nanos >= 1_000_000_000 {
        nanos = 999_999_999;
    }
    let datetime = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    Some(datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

fn read_line() -> Result<String> {
    let mut buf = String::new();
    let bytes = io::stdin().read_line(&mut buf)?;
    if bytes == 0 {
        Err(anyhow!("input closed"))
    } else {
        Ok(buf)
    }
}

#[derive(Debug, Deserialize)]
struct ConversationRecord {
    id: String,
    title: Option<String>,
    create_time: Option<f64>,
    current_node: Option<String>,
    mapping: HashMap<String, ConversationNode>,
}

#[derive(Debug, Deserialize)]
struct ConversationNode {
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    message: Option<MessageRecord>,
}

#[derive(Debug, Deserialize)]
struct MessageRecord {
    #[serde(default)]
    author: Option<MessageAuthor>,
    #[serde(default)]
    create_time: Option<f64>,
    #[serde(default)]
    content: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct MessageAuthor {
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug)]
struct ConversationSummary {
    index: usize,
    id: String,
    title: String,
    create_time: Option<f64>,
}

#[derive(Debug)]
struct MatchedConversation<'a> {
    summary: &'a ConversationSummary,
}

#[derive(Debug)]
struct MessageView {
    role: String,
    content: String,
    time: Option<f64>,
}
