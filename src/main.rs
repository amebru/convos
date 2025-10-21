use std::collections::{HashMap, HashSet};
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
const PROGRESS_FRAMES: [&str; 6] = ["●○○○○○", "●●○○○○", "●●●○○○", "●●●●○○", "●●●●●○", "●●●●●●"];

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
        eprintln!("Usage: convos <path-to-export>");
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
    print_banner(export_path);

    let conversations = with_progress("loading conversations", || load_conversations(export_path))?;
    let count_note = dim(&format!("{} threads detected", conversations.len()));
    println!("{} {}", accent_bullet(), count_note);

    let summaries = with_progress("organising threads", || Ok(build_summaries(&conversations)))?;

    browse_conversations(&conversations, &summaries)?;

    println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
    println!("{}", dim("see you next time!"));
    println!("{}", edge("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"));
    Ok(())
}

fn load_conversations(path: &Path) -> Result<Vec<Conversation>> {
    let file_path = path.join("conversations.json");
    if !file_path.exists() {
        return Err(anyhow!(
            "expected conversations.json in `{}`",
            path.display()
        ));
    }

    let raw = fs::read_to_string(&file_path).with_context(|| format!("reading {file_path:?}"))?;
    let json: Value = serde_json::from_str(&raw).with_context(|| "parsing conversations.json")?;
    let items = json
        .as_array()
        .ok_or_else(|| anyhow!("expected top-level array in conversations.json"))?;

    let kind = detect_export_kind(items)?;
    match kind {
        ExportKind::ChatGpt => parse_chatgpt_conversations(&raw),
        ExportKind::Claude => parse_claude_conversations(&raw),
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
        let messages = extract_chatgpt_messages(&record);
        conversations.push(Conversation {
            id,
            title,
            created_at,
            messages,
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

        let messages = record
            .chat_messages
            .into_iter()
            .filter_map(|message| {
                let role = normalize_role(message.sender.as_str());
                let text = message
                    .text
                    .as_deref()
                    .filter(|text| !text.trim().is_empty())
                    .map(|text| text.to_string())
                    .or_else(|| aggregate_claude_content(&message.content));
                text.map(|content| Message { role, content })
            })
            .collect();

        conversations.push(Conversation {
            id: record.uuid,
            title,
            created_at,
            messages,
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

fn browse_conversations(
    conversations: &[Conversation],
    summaries: &[ConversationSummary],
) -> Result<()> {
    println!("{}", dim("type to filter titles, press Enter to list all, q to exit."));
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

        println!("\n{}", pastel_rule());
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

        println!("\n{}", pastel_rule());
        println!("{}", dim("press Enter to return to the search prompt"));
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
}

#[derive(Debug)]
struct Message {
    role: String,
    content: String,
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
}

#[derive(Debug, Deserialize)]
struct ChatGptMessageAuthor {
    #[serde(default)]
    role: Option<String>,
}

fn extract_chatgpt_messages(convo: &ChatGptConversationRecord) -> Vec<Message> {
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
    for id in ordered_ids {
        if let Some(node) = convo.mapping.get(&id) {
            if let Some(message) = &node.message {
                let role = message
                    .author
                    .as_ref()
                    .and_then(|author| author.role.as_deref())
                    .unwrap_or("unknown");
                if let Some(text) = extract_text(&message.content) {
                    if text.trim().is_empty() {
                        continue;
                    }
                    messages.push(Message {
                        role: normalize_role(role.as_ref()),
                        content: text,
                    });
                }
            }
        }
    }

    messages
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
