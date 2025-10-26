use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use nu_ansi_term::{Color, Style as AnsiStyle};
use once_cell::sync::Lazy;
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag};
use serde::Deserialize;
use serde_json::Value;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::{LinesWithEndings, as_24_bit_terminal_escaped};

const USER_SHADE: Color = Color::Rgb(200, 200, 200);
const ACCENT_COLOR: Color = Color::Rgb(188, 205, 238);
const EDGE_COLOR: Color = Color::Rgb(217, 182, 203);
const DIM_COLOR: Color = Color::Rgb(125, 132, 140);
const DOT_ACTIVE_COLOR: Color = Color::Rgb(188, 205, 238);
const DOT_INACTIVE_COLOR: Color = Color::Rgb(90, 94, 104);
const AVAILABLE_COLOR: Color = Color::Rgb(120, 200, 120);
const UNAVAILABLE_COLOR: Color = Color::Rgb(220, 100, 100);
const PROGRESS_FRAMES: [&str; 6] = ["●○○○○○", "●●○○○○", "●●●○○○", "●●●●○○", "●●●●●○", "●●●●●●"];

enum Mode {
    Interactive,
    ListOnly,
    ListAllArtifacts,
    ShowIndex { index: usize, show_artifacts: bool },
    DownloadArtifact {
        conversation_index: usize,
        artifact_number: usize,
        output_dir: Option<PathBuf>,
    },
}

fn accent_style() -> AnsiStyle {
    AnsiStyle::new().fg(ACCENT_COLOR)
}

fn dim_style() -> AnsiStyle {
    AnsiStyle::new().fg(DIM_COLOR)
}

fn edge_style() -> AnsiStyle {
    AnsiStyle::new().fg(EDGE_COLOR)
}

fn user_style() -> AnsiStyle {
    AnsiStyle::new().fg(USER_SHADE)
}

fn accent(text: &str) -> String {
    accent_style().paint(text).to_string()
}

fn dim(text: &str) -> String {
    dim_style().paint(text).to_string()
}

fn edge(text: &str) -> String {
    edge_style().paint(text).to_string()
}

fn user_prefix() -> String {
    user_style().paint(">>> ").to_string()
}

fn colorize_user_text(text: &str) -> String {
    user_style().paint(text).to_string()
}

fn accent_prompt(label: &str) -> String {
    AnsiStyle::new()
        .fg(ACCENT_COLOR)
        .bold()
        .paint(label)
        .to_string()
}

fn accent_bullet() -> String {
    edge_style().paint("⋆").to_string()
}

fn pastel_rule() -> String {
    edge_style()
        .paint("────────────────────────────────")
        .to_string()
}

fn style_frame(frame: &str) -> String {
    frame
        .chars()
        .map(|ch| match ch {
            '●' => AnsiStyle::new()
                .fg(DOT_ACTIVE_COLOR)
                .bold()
                .paint("●")
                .to_string(),
            '○' => AnsiStyle::new()
                .fg(DOT_INACTIVE_COLOR)
                .paint("○")
                .to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join("")
}

fn print_banner(export_path: &Path) {
    println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
    println!("{} {}", accent_bullet(), accent("convos is warming up"));
    println!("{}", accent("      /\\_/\\"));
    println!("{} {}", accent_bullet(), accent(" ( o.o )  miaou!"));
    println!("{}", accent("      > ^ <"));
    println!(
        "{} {}",
        accent_bullet(),
        dim(&format!("source {}", export_path.display()))
    );
    println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
}

fn with_progress<F, T>(label: &str, action: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let running = Arc::new(AtomicBool::new(true));
    let spinner_running = Arc::clone(&running);
    let display_label = format!("{} {}", accent_bullet(), accent(&format!("{}...", label)));
    let spinner_label = display_label.clone();

    let handle = thread::spawn(move || {
        let mut index = 0usize;
        while spinner_running.load(Ordering::Relaxed) {
            let frame = PROGRESS_FRAMES[index % PROGRESS_FRAMES.len()];
            let styled = style_frame(frame);
            print!("\r{} {}", spinner_label, styled);
            let _ = io::stdout().flush();
            index += 1;
            thread::sleep(Duration::from_millis(110));
        }
    });

    let result = action();

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
    let final_frame = style_frame(PROGRESS_FRAMES.last().copied().unwrap_or("●●●●●●"));
    print!("\r{} {}\n", display_label, final_frame);
    io::stdout().flush()?;

    result
}

fn main() -> Result<()> {
    let mut args = env::args_os();
    let _ = args.next();

    let Some(export_arg) = args.next() else {
        eprintln!("Usage: convos <path-to-export> [--list|NUMBER [--artifacts [ARTIFACT_NUMBER [OUTPUT_DIR]]]]");
        std::process::exit(64);
    };

    let export_path = PathBuf::from(&export_arg);

    let tail_args: Vec<String> = args.map(|arg| arg.to_string_lossy().to_string()).collect();

    let mode = match tail_args.as_slice() {
        [] => Mode::Interactive,
        [flag] if flag == "--list" => Mode::ListOnly,
        [flag] if flag == "--artifacts" => Mode::ListAllArtifacts,
        [flag] => {
            let number: usize = flag.parse().unwrap_or_else(|_| {
                eprintln!("Invalid conversation number `{}`.", flag);
                std::process::exit(64);
            });
            if number == 0 {
                eprintln!("Conversation number must be greater than zero.");
                std::process::exit(64);
            }
            Mode::ShowIndex {
                index: number - 1,
                show_artifacts: false,
            }
        }
        [number, flag] if flag == "--artifacts" => {
            let parsed: usize = number.parse().unwrap_or_else(|_| {
                eprintln!("Invalid conversation number `{}`.", number);
                std::process::exit(64);
            });
            if parsed == 0 {
                eprintln!("Conversation number must be greater than zero.");
                std::process::exit(64);
            }
            Mode::ShowIndex {
                index: parsed - 1,
                show_artifacts: true,
            }
        }
        [number, flag, artifact_num] if flag == "--artifacts" => {
            let conv_index: usize = number.parse().unwrap_or_else(|_| {
                eprintln!("Invalid conversation number `{}`.", number);
                std::process::exit(64);
            });
            if conv_index == 0 {
                eprintln!("Conversation number must be greater than zero.");
                std::process::exit(64);
            }
            let artifact_number: usize = artifact_num.parse().unwrap_or_else(|_| {
                eprintln!("Invalid artifact number `{}`.", artifact_num);
                std::process::exit(64);
            });
            if artifact_number == 0 {
                eprintln!("Artifact number must be greater than zero.");
                std::process::exit(64);
            }
            Mode::DownloadArtifact {
                conversation_index: conv_index - 1,
                artifact_number,
                output_dir: None,
            }
        }
        [number, flag, artifact_num, output_dir] if flag == "--artifacts" => {
            let conv_index: usize = number.parse().unwrap_or_else(|_| {
                eprintln!("Invalid conversation number `{}`.", number);
                std::process::exit(64);
            });
            if conv_index == 0 {
                eprintln!("Conversation number must be greater than zero.");
                std::process::exit(64);
            }
            let artifact_number: usize = artifact_num.parse().unwrap_or_else(|_| {
                eprintln!("Invalid artifact number `{}`.", artifact_num);
                std::process::exit(64);
            });
            if artifact_number == 0 {
                eprintln!("Artifact number must be greater than zero.");
                std::process::exit(64);
            }
            Mode::DownloadArtifact {
                conversation_index: conv_index - 1,
                artifact_number,
                output_dir: Some(PathBuf::from(output_dir)),
            }
        }
        [flag, ..] if flag == "--list" => {
            eprintln!("`--list` does not accept additional arguments.");
            eprintln!("Usage: convos <path-to-export> [--list|NUMBER [--artifacts [ARTIFACT_NUMBER [OUTPUT_DIR]]]]");
            std::process::exit(64);
        }
        [flag, ..] if flag == "--artifacts" => {
            eprintln!("`--artifacts` must follow a conversation number.");
            eprintln!("Usage: convos <path-to-export> [--list|NUMBER [--artifacts [ARTIFACT_NUMBER [OUTPUT_DIR]]]]");
            std::process::exit(64);
        }
        _ => {
            eprintln!("Too many arguments provided.");
            eprintln!("Usage: convos <path-to-export> [--list|NUMBER [--artifacts [ARTIFACT_NUMBER [OUTPUT_DIR]]]]");
            std::process::exit(64);
        }
    };

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

    if let Err(err) = run(&export_path, mode) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
    Ok(())
}

fn run(export_path: &Path, mode: Mode) -> Result<()> {
    if matches!(mode, Mode::Interactive) {
        print_banner(export_path);
    }

    let show_progress = matches!(mode, Mode::Interactive);

    let conversations = if show_progress {
        with_progress("loading conversations", || load_conversations(export_path))?
    } else {
        load_conversations(export_path)?
    };

    let summaries = if show_progress {
        with_progress("organising threads", || Ok(build_summaries(&conversations)))?
    } else {
        build_summaries(&conversations)
    };

    let total = conversations.len();
    let count_note = dim(&format!("{} threads detected", total));

    match mode {
        Mode::Interactive => {
            println!("{} {}", accent_bullet(), count_note);
            browse_conversations(export_path, &conversations, &summaries)?;
            println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
            println!("{}", dim("see you next time!"));
            println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
        }
        Mode::ListOnly => {
            println!("{} {}", accent_bullet(), count_note);
            print_conversation_list(&summaries);
        }
        Mode::ListAllArtifacts => {
            println!("{} {}", accent_bullet(), count_note);
            list_all_artifacts(export_path, &conversations, &summaries);
        }
        Mode::ShowIndex {
            index,
            show_artifacts,
        } => {
            if summaries.is_empty() {
                return Err(anyhow!("no conversations available"));
            }
            let summary = summaries.get(index).ok_or_else(|| {
                anyhow!(
                    "conversation number {} out of range (1..={})",
                    index + 1,
                    summaries.len()
                )
            })?;
            let conversation = &conversations[summary.index];
            if show_artifacts {
                print_conversation_artifacts(export_path, conversation, summary, false);
            } else {
                print_conversation(export_path, conversation, summary, false);
            }
        }
        Mode::DownloadArtifact {
            conversation_index,
            artifact_number,
            output_dir,
        } => {
            if summaries.is_empty() {
                return Err(anyhow!("no conversations available"));
            }
            let summary = summaries.get(conversation_index).ok_or_else(|| {
                anyhow!(
                    "conversation number {} out of range (1..={})",
                    conversation_index + 1,
                    summaries.len()
                )
            })?;
            let conversation = &conversations[summary.index];

            if conversation.artifacts.is_empty() {
                return Err(anyhow!(
                    "conversation {} has no artifacts",
                    conversation_index + 1
                ));
            }

            let artifact_index = artifact_number - 1;
            let artifact = conversation.artifacts.get(artifact_index).ok_or_else(|| {
                anyhow!(
                    "artifact number {} out of range (1..={})",
                    artifact_number,
                    conversation.artifacts.len()
                )
            })?;

            download_artifact(export_path, artifact, output_dir.as_deref())?;
        }
    }

    Ok(())
}

fn find_conversation_files(root: &Path) -> Result<Vec<PathBuf>> {
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
    const MAX_SCAN_DEPTH: usize = 3;

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

fn load_conversations(path: &Path) -> Result<Vec<Conversation>> {
    let files = find_conversation_files(path)?;
    let mut conversations = Vec::new();
    let mut seen_ids = HashSet::new();

    for file_path in files {
        let raw = fs::read_to_string(&file_path)
            .with_context(|| format!("reading `{}`", file_path.display()))?;
        let json: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing `{}`", file_path.display()))?;
        let items = json
            .as_array()
            .ok_or_else(|| anyhow!("expected top-level array in `{}`", file_path.display()))?;

        let kind = detect_export_kind(items)?;
        let mut parsed = match kind {
            ExportKind::ChatGpt => parse_chatgpt_conversations(&raw)?,
            ExportKind::Claude => parse_claude_conversations(&raw)?,
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

fn detect_export_kind(items: &[Value]) -> Result<ExportKind> {
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

fn parse_chatgpt_conversations(raw: &str) -> Result<Vec<Conversation>> {
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

fn parse_claude_conversations(raw: &str) -> Result<Vec<Conversation>> {
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

fn build_summaries(conversations: &[Conversation]) -> Vec<ConversationSummary> {
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

fn print_conversation_list(summaries: &[ConversationSummary]) {
    println!(
        "{} {}",
        accent_bullet(),
        accent(&format!("found {} conversation(s).", summaries.len()))
    );

    for (ordinal, summary) in summaries.iter().enumerate() {
        let timestamp = summary
            .created_at
            .map(format_timestamp)
            .unwrap_or_else(|| "unknown time".to_string());
        println!(
            "{} [{}] {} {}",
            edge("|"),
            accent(&format!("{:>2}", ordinal + 1)),
            summary.title,
            dim(&format!("· {}", timestamp))
        );
    }
}

fn list_all_artifacts(export_path: &Path, conversations: &[Conversation], summaries: &[ConversationSummary]) {
    // Count total artifacts
    let total_artifacts: usize = conversations.iter().map(|c| c.artifacts.len()).sum();

    println!(
        "{} {}",
        accent_bullet(),
        accent(&format!("found {} artifact(s) across all conversations.", total_artifacts))
    );

    if total_artifacts == 0 {
        return;
    }

    println!();

    // Iterate through summaries (which are sorted by date)
    for summary in summaries {
        let conversation = &conversations[summary.index];

        if conversation.artifacts.is_empty() {
            continue;
        }

        // Print conversation header
        println!("{}", pastel_rule());
        println!("{} {}", accent_bullet(), accent(&summary.title));
        if let Some(created) = summary.created_at.map(format_timestamp) {
            println!("{} {}", accent_bullet(), dim(&format!("started {created}")));
        }
        println!("{} {}", accent_bullet(), dim(&format!("id {}", summary.id)));
        println!(
            "{} {}",
            accent_bullet(),
            accent(&format!("{} artifact(s)", conversation.artifacts.len()))
        );

        // List artifacts
        for (idx, artifact) in conversation.artifacts.iter().enumerate() {
            let indicator = artifact_availability_indicator(export_path, &artifact.name);
            println!(
                "{} [{}] {} {}",
                edge("|"),
                accent(&format!("{:>2}", idx + 1)),
                indicator,
                artifact.name
            );

            let mut details = Vec::new();
            details.push(format!("from {}", artifact.role));
            if !artifact.kind.is_empty() {
                details.push(artifact.kind.clone());
            }
            if let Some(size) = artifact.size_bytes {
                details.push(format_size(size));
            }
            if let Some(created_at) = artifact.created_at {
                details.push(format!("at {}", format_timestamp(created_at)));
            }
            if let Some(url) = &artifact.url {
                details.push(url.clone());
            }

            if !details.is_empty() {
                println!("{}   {}", edge("|"), dim(&details.join(" · ")));
            }

            if let Some(description) = &artifact.description {
                let desc_trimmed = description.trim();
                if !desc_trimmed.is_empty() {
                    let mut snippet: String = desc_trimmed.chars().take(240).collect();
                    if desc_trimmed.chars().count() > 240 {
                        snippet.push('…');
                    }
                    println!("{}   {}", edge("|"), dim(&snippet));
                }
            }
        }
    }

    println!("{}", pastel_rule());
}

fn print_conversation(
    export_path: &Path,
    conversation: &Conversation,
    summary: &ConversationSummary,
    leading_newline: bool,
) {
    if leading_newline {
        println!();
    }
    println!("{}", pastel_rule());
    println!("{} {}", accent_bullet(), accent(&summary.title));
    if let Some(created) = summary.created_at.map(format_timestamp) {
        println!("{} {}", accent_bullet(), dim(&format!("started {created}")));
    }
    println!("{} {}", accent_bullet(), dim(&format!("id {}", summary.id)));
    println!("{}", pastel_rule());

    if conversation.messages.is_empty() {
        println!("{}", dim("[no printable messages in this conversation]"));
    } else {
        for message in &conversation.messages {
            let rendered = render_markdown(&message.content);
            match message.role.as_str() {
                "user" => {
                    let content = colorize_user_text(&rendered);
                    println!("\n{}{}", user_prefix(), content);
                }
                "assistant" => {
                    println!("\n{}", rendered);
                }
                other => {
                    let tag = accent(&format!("[{}] ", other.to_uppercase()));
                    let content = dim(&rendered);
                    println!("\n{}{}", tag, content);
                }
            }
        }
    }

    // Display artifacts if present
    if !conversation.artifacts.is_empty() {
        println!();
        println!(
            "{} {}",
            accent_bullet(),
            accent(&format!("{} artifact(s)", conversation.artifacts.len()))
        );

        for (idx, artifact) in conversation.artifacts.iter().enumerate() {
            let indicator = artifact_availability_indicator(export_path, &artifact.name);
            println!(
                "{} [{}] {} {}",
                edge("|"),
                accent(&format!("{:>2}", idx + 1)),
                indicator,
                artifact.name
            );

            let mut details = Vec::new();
            details.push(format!("from {}", artifact.role));
            if !artifact.kind.is_empty() {
                details.push(artifact.kind.clone());
            }
            if let Some(size) = artifact.size_bytes {
                details.push(format_size(size));
            }
            if let Some(created_at) = artifact.created_at {
                details.push(format!("at {}", format_timestamp(created_at)));
            }
            if let Some(url) = &artifact.url {
                details.push(url.clone());
            }

            if !details.is_empty() {
                println!("{}   {}", edge("|"), dim(&details.join(" · ")));
            }

            if let Some(description) = &artifact.description {
                let desc_trimmed = description.trim();
                if !desc_trimmed.is_empty() {
                    let mut snippet: String = desc_trimmed.chars().take(240).collect();
                    if desc_trimmed.chars().count() > 240 {
                        snippet.push('…');
                    }
                    println!("{}   {}", edge("|"), dim(&snippet));
                }
            }
        }
    }

    println!();
    println!("{}", pastel_rule());
}

fn print_conversation_artifacts(
    export_path: &Path,
    conversation: &Conversation,
    summary: &ConversationSummary,
    leading_newline: bool,
) {
    if leading_newline {
        println!();
    }
    println!("{}", pastel_rule());
    println!("{} {}", accent_bullet(), accent(&summary.title));
    if let Some(created) = summary.created_at.map(format_timestamp) {
        println!("{} {}", accent_bullet(), dim(&format!("started {created}")));
    }
    println!("{} {}", accent_bullet(), dim(&format!("id {}", summary.id)));
    println!("{}", pastel_rule());

    if conversation.artifacts.is_empty() {
        println!(
            "{} {}",
            accent_bullet(),
            dim("no artifacts found in this conversation.")
        );
        println!("{}", pastel_rule());
        return;
    }

    println!(
        "{} {}",
        accent_bullet(),
        accent(&format!("{} artifact(s)", conversation.artifacts.len()))
    );

    for (idx, artifact) in conversation.artifacts.iter().enumerate() {
        let indicator = artifact_availability_indicator(export_path, &artifact.name);
        println!(
            "{} [{}] {} {}",
            edge("|"),
            accent(&format!("{:>2}", idx + 1)),
            indicator,
            artifact.name
        );

        let mut details = Vec::new();
        details.push(format!("from {}", artifact.role));
        if !artifact.kind.is_empty() {
            details.push(artifact.kind.clone());
        }
        if let Some(size) = artifact.size_bytes {
            details.push(format_size(size));
        }
        if let Some(created_at) = artifact.created_at {
            details.push(format!("at {}", format_timestamp(created_at)));
        }
        if let Some(url) = &artifact.url {
            details.push(url.clone());
        }

        if !details.is_empty() {
            println!("{}   {}", edge("|"), dim(&details.join(" · ")));
        }

        if let Some(description) = &artifact.description {
            let desc_trimmed = description.trim();
            if !desc_trimmed.is_empty() {
                let mut snippet: String = desc_trimmed.chars().take(240).collect();
                if desc_trimmed.chars().count() > 240 {
                    snippet.push('…');
                }
                println!("{}   {}", edge("|"), dim(&snippet));
            }
        }
    }

    println!("{}", pastel_rule());
}

fn download_artifact(
    export_path: &Path,
    artifact: &Artifact,
    output_dir: Option<&Path>,
) -> Result<()> {
    // Determine the source file path by searching in the export directory
    let source_path = find_artifact_file(export_path, &artifact.name)?;

    // Determine the output path
    let output_path = match output_dir {
        Some(dir) => {
            if !dir.exists() {
                fs::create_dir_all(dir)
                    .with_context(|| format!("creating directory `{}`", dir.display()))?;
            }
            if !dir.is_dir() {
                return Err(anyhow!(
                    "output path `{}` exists but is not a directory",
                    dir.display()
                ));
            }
            dir.join(&artifact.name)
        }
        None => PathBuf::from(&artifact.name),
    };

    // Copy the file
    fs::copy(&source_path, &output_path).with_context(|| {
        format!(
            "copying `{}` to `{}`",
            source_path.display(),
            output_path.display()
        )
    })?;

    // Print confirmation
    println!(
        "{} {}",
        accent("-->"),
        if output_dir.is_some() {
            format!("downloaded to {}", output_path.display())
        } else {
            format!("downloaded {}", artifact.name)
        }
    );

    Ok(())
}

fn find_artifact_file(export_path: &Path, artifact_name: &str) -> Result<PathBuf> {
    // Search for files matching the artifact name in the export directory and subdirectories
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
                    // Partial match for files like "file-<id>-<uuid>.ext" that might contain the artifact name
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

fn artifact_availability_indicator(export_path: &Path, artifact_name: &str) -> String {
    // Check if artifact file exists
    let available = find_artifact_file(export_path, artifact_name).is_ok();

    if available {
        AnsiStyle::new()
            .fg(AVAILABLE_COLOR)
            .bold()
            .paint("●")
            .to_string()
    } else {
        AnsiStyle::new()
            .fg(UNAVAILABLE_COLOR)
            .bold()
            .paint("●")
            .to_string()
    }
}

fn browse_conversations(
    export_path: &Path,
    conversations: &[Conversation],
    summaries: &[ConversationSummary],
) -> Result<()> {
    println!(
        "{}",
        dim("type to filter titles, press Enter to list all, q to exit.")
    );
    loop {
        print!("{} ", accent_prompt("search>"));
        io::stdout().flush()?;
        let input = read_line()?;
        let trimmed = input.trim();

        if trimmed.eq_ignore_ascii_case("q") {
            return Ok(());
        }

        let matches = filter_conversations(summaries, trimmed);
        if matches.is_empty() {
            if trimmed.is_empty() {
                println!("{}", dim("no conversations available."));
            } else {
                println!(
                    "{}",
                    dim(&format!("no conversations matched `{}`.", trimmed))
                );
            }
            continue;
        }

        let total = show_matches(&matches);

        if total == 0 {
            println!("{}", dim("nothing to select; refine the search."));
            continue;
        }

        let Some(choice) = prompt_match_choice(total)? else {
            continue;
        };

        let summary = &matches[choice].summary;
        let conversation = &conversations[summary.index];
        print_conversation(export_path, conversation, summary, true);

        // Allow downloading artifacts or returning to search
        if !conversation.artifacts.is_empty() {
            println!(
                "{}",
                dim("press Enter to return to the search prompt, or enter artifact number to download")
            );
            print!("{} ", accent_prompt(">"));
        } else {
            println!("{}", dim("press Enter to return to the search prompt"));
            print!("{} ", accent_prompt(">"));
        }

        io::stdout().flush()?;
        let input = match read_line() {
            Ok(line) => line,
            Err(_) => return Ok(()),
        };

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse download command: NUMBER or NUMBER DIR
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        match parts.as_slice() {
            [num_str] => {
                // Download to current directory
                if let Ok(artifact_num) = num_str.parse::<usize>() {
                    if artifact_num == 0 || artifact_num > conversation.artifacts.len() {
                        println!(
                            "{}",
                            dim(&format!(
                                "artifact number must be between 1 and {}",
                                conversation.artifacts.len()
                            ))
                        );
                        continue;
                    }
                    let artifact = &conversation.artifacts[artifact_num - 1];
                    if let Err(e) = download_artifact(export_path, artifact, None) {
                        eprintln!("error downloading artifact: {}", e);
                    }
                } else {
                    println!("{}", dim("invalid artifact number"));
                }
            }
            [num_str, dir_str] => {
                // Download to specified directory
                if let Ok(artifact_num) = num_str.parse::<usize>() {
                    if artifact_num == 0 || artifact_num > conversation.artifacts.len() {
                        println!(
                            "{}",
                            dim(&format!(
                                "artifact number must be between 1 and {}",
                                conversation.artifacts.len()
                            ))
                        );
                        continue;
                    }
                    let artifact = &conversation.artifacts[artifact_num - 1];
                    let output_dir = PathBuf::from(dir_str);
                    if let Err(e) = download_artifact(export_path, artifact, Some(&output_dir)) {
                        eprintln!("error downloading artifact: {}", e);
                    }
                } else {
                    println!("{}", dim("invalid artifact number"));
                }
            }
            _ => {
                println!("{}", dim("usage: ARTIFACT_NUMBER [OUTPUT_DIR]"));
            }
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
    println!(
        "{} {}",
        accent_bullet(),
        accent(&format!("found {} conversation(s).", matches.len()))
    );

    for (ordinal, matched) in matches.iter().enumerate().rev() {
        let summary = matched.summary;
        let timestamp = summary
            .created_at
            .map(format_timestamp)
            .unwrap_or_else(|| "unknown time".to_string());
        println!(
            "{} [{}] {} {}",
            edge("|"),
            accent(&format!("{:>2}", ordinal + 1)),
            summary.title,
            dim(&format!("· {}", timestamp))
        );
    }

    matches.len()
}

fn prompt_match_choice(count: usize) -> Result<Option<usize>> {
    if count == 0 {
        return Ok(None);
    }
    println!(
        "{}",
        dim("select a conversation number or press Enter to search again.")
    );
    loop {
        print!("{} ", accent_prompt("choice>"));
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
        println!(
            "{}",
            dim(&format!(
                "please enter a number between 1 and {}, or press Enter to cancel.",
                count
            ))
        );
    }
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

fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[derive(Debug)]
struct Conversation {
    id: String,
    title: String,
    created_at: Option<DateTime<Utc>>,
    messages: Vec<Message>,
    artifacts: Vec<Artifact>,
}

#[derive(Debug)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Clone)]
struct Artifact {
    role: String,
    name: String,
    kind: String,
    size_bytes: Option<u64>,
    url: Option<String>,
    description: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

fn format_size(bytes: u64) -> String {
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

#[derive(Debug)]
struct ConversationSummary {
    index: usize,
    id: String,
    title: String,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct MatchedConversation<'a> {
    summary: &'a ConversationSummary,
}

#[derive(Debug, Deserialize)]
struct ChatGptConversationRecord {
    id: String,
    title: Option<String>,
    create_time: Option<f64>,
    current_node: Option<String>,
    mapping: HashMap<String, ChatGptConversationNode>,
}

#[derive(Debug, Deserialize)]
struct ChatGptConversationNode {
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    message: Option<ChatGptMessageRecord>,
}

#[derive(Debug, Deserialize)]
struct ChatGptMessageRecord {
    #[serde(default)]
    author: Option<ChatGptMessageAuthor>,
    #[serde(default)]
    create_time: Option<f64>,
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ChatGptMessageAuthor {
    #[serde(default)]
    role: Option<String>,
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

#[derive(Debug, Deserialize)]
struct ClaudeConversationRecord {
    uuid: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    chat_messages: Vec<ClaudeChatMessage>,
}

#[derive(Debug, Deserialize)]
struct ClaudeChatMessage {
    sender: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    content: Vec<ClaudeContent>,
    #[serde(default)]
    attachments: Vec<Value>,
    #[serde(default)]
    files: Vec<Value>,
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
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

static SYNTAX_SET: Lazy<SyntaxSet> = Lazy::new(SyntaxSet::load_defaults_newlines);
static THEME: Lazy<Theme> = Lazy::new(|| {
    let theme_set = ThemeSet::load_defaults();
    theme_set
        .themes
        .get("base16-ocean.dark")
        .cloned()
        .unwrap_or_else(|| theme_set.themes.values().next().cloned().unwrap())
});

fn render_markdown(text: &str) -> String {
    let mut output = String::new();
    let mut inline_styles: Vec<InlineStyle> = Vec::new();
    let mut list_stack: Vec<ListState> = Vec::new();
    let mut code_block: Option<(Option<String>, String)> = None;

    let options = Options::ENABLE_TABLES | Options::ENABLE_FOOTNOTES;
    let parser = Parser::new_ext(text, options);

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let language = match kind {
                    CodeBlockKind::Fenced(lang) => {
                        let trimmed = lang.into_string();
                        let trimmed = trimmed.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    }
                    CodeBlockKind::Indented => None,
                };
                code_block = Some((language, String::new()));
            }
            Event::End(Tag::CodeBlock(_)) => {
                if let Some((language, buffer)) = code_block.take() {
                    if !output.ends_with('\n') && !output.is_empty() {
                        output.push('\n');
                    }
                    let highlighted = highlight_code_block(&buffer, language.as_deref());
                    output.push_str(&highlighted);
                    if !highlighted.ends_with('\n') {
                        output.push('\n');
                    }
                }
            }
            Event::Text(segment) => {
                if let Some((_, ref mut buffer)) = code_block {
                    buffer.push_str(&segment);
                } else {
                    output.push_str(&apply_inline_styles(&inline_styles, &segment));
                }
            }
            Event::Code(code) => {
                output.push_str(&highlight_inline_code(&code));
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some((_, ref mut buffer)) = code_block {
                    buffer.push('\n');
                } else {
                    output.push('\n');
                }
            }
            Event::Start(Tag::Strong) => inline_styles.push(InlineStyle::Bold),
            Event::End(Tag::Strong) => pop_style(&mut inline_styles, InlineStyle::Bold),
            Event::Start(Tag::Emphasis) => inline_styles.push(InlineStyle::Italic),
            Event::End(Tag::Emphasis) => pop_style(&mut inline_styles, InlineStyle::Italic),
            Event::Start(Tag::Heading(_, _, _)) => {
                if !output.ends_with('\n') && !output.is_empty() {
                    output.push('\n');
                }
                inline_styles.push(InlineStyle::Heading);
            }
            Event::End(Tag::Heading(_, _, _)) => {
                pop_style(&mut inline_styles, InlineStyle::Heading);
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Event::Start(Tag::Paragraph) => {
                if !output.ends_with('\n') && !output.is_empty() {
                    output.push('\n');
                }
            }
            Event::End(Tag::Paragraph) => {
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Event::Start(Tag::BlockQuote) => {
                inline_styles.push(InlineStyle::BlockQuote);
                if !output.ends_with('\n') && !output.is_empty() {
                    output.push('\n');
                }
                output.push_str("> ");
            }
            Event::End(Tag::BlockQuote) => {
                pop_style(&mut inline_styles, InlineStyle::BlockQuote);
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Event::Start(Tag::List(start)) => match start {
                Some(number) => {
                    let start_at = if number == 0 { 1 } else { number };
                    list_stack.push(ListState::Ordered(start_at as u64));
                }
                None => list_stack.push(ListState::Unordered),
            },
            Event::End(Tag::List(_)) => {
                list_stack.pop();
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Event::Start(Tag::Item) => {
                if !output.ends_with('\n') && !output.is_empty() {
                    output.push('\n');
                }
                match list_stack.last_mut() {
                    Some(ListState::Ordered(number)) => {
                        output.push_str(&format!("{number}. "));
                        *number += 1;
                    }
                    Some(ListState::Unordered) => output.push_str("- "),
                    None => {}
                }
            }
            Event::End(Tag::Item) => {
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Event::Html(html) => output.push_str(&html),
            Event::FootnoteReference(reference) => {
                output.push_str(&format!("[^{}]", reference));
            }
            Event::TaskListMarker(checked) => {
                let marker = if checked { "[x] " } else { "[ ] " };
                output.push_str(marker);
            }
            Event::Rule => {
                if !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str("----\n");
            }
            Event::Start(_) | Event::End(_) => {}
        }
    }

    if let Some((language, buffer)) = code_block.take() {
        if !output.ends_with('\n') && !output.is_empty() {
            output.push('\n');
        }
        let highlighted = highlight_code_block(&buffer, language.as_deref());
        output.push_str(&highlighted);
        if !highlighted.ends_with('\n') {
            output.push('\n');
        }
    }

    output.trim_end().to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InlineStyle {
    Bold,
    Italic,
    Heading,
    BlockQuote,
}

#[derive(Clone, Debug)]
enum ListState {
    Unordered,
    Ordered(u64),
}

fn pop_style(stack: &mut Vec<InlineStyle>, style: InlineStyle) {
    if let Some(index) = stack.iter().rposition(|entry| *entry == style) {
        stack.remove(index);
    }
}

fn apply_inline_styles(stack: &[InlineStyle], text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut style = AnsiStyle::new();
    let mut styled = false;
    let mut color: Option<Color> = None;

    for entry in stack {
        match entry {
            InlineStyle::Bold => {
                style = style.bold();
                styled = true;
            }
            InlineStyle::Italic => {
                style = style.italic();
                styled = true;
            }
            InlineStyle::Heading => {
                style = style.bold();
                color = color.or(Some(Color::LightBlue));
                styled = true;
            }
            InlineStyle::BlockQuote => {
                color = color.or(Some(Color::Cyan));
                styled = true;
            }
        }
    }

    if let Some(color) = color {
        style = style.fg(color);
        styled = true;
    }

    if styled {
        style.paint(text).to_string()
    } else {
        text.to_string()
    }
}

fn highlight_inline_code(code: &str) -> String {
    let style = AnsiStyle::new()
        .fg(Color::Rgb(255, 224, 138))
        .on(Color::Rgb(60, 63, 65));
    style.paint(code).to_string()
}

fn highlight_code_block(code: &str, language: Option<&str>) -> String {
    let syntax_set: &SyntaxSet = &SYNTAX_SET;
    let theme: &Theme = &THEME;

    let syntax: &SyntaxReference =
        match language.and_then(|lang| syntax_set.find_syntax_by_token(lang)) {
            Some(syntax) => syntax,
            None => syntax_set.find_syntax_plain_text(),
        };

    let mut highlighter = HighlightLines::new(syntax, theme);
    let mut highlighted = String::new();

    for line in LinesWithEndings::from(code) {
        match highlighter.highlight_line(line, syntax_set) {
            Ok(ranges) => highlighted.push_str(&as_24_bit_terminal_escaped(&ranges, false)),
            Err(_) => highlighted.push_str(line),
        }
    }

    highlighted
}

enum ExportKind {
    ChatGpt,
    Claude,
}
