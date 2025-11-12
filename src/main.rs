use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nu_ansi_term::{Color, Style as AnsiStyle};

use convos::{
    Conversation, ConversationSummary, Artifact,
    load_conversations, build_summaries, filter_conversations,
    resolve_conversation_id, find_artifact_file, artifact_exists,
    render_markdown, format_size, format_timestamp,
};

const USER_SHADE: Color = Color::Rgb(200, 200, 200);
const ACCENT_COLOR: Color = Color::Rgb(188, 205, 238);
const EDGE_COLOR: Color = Color::Rgb(217, 182, 203);
const DIM_COLOR: Color = Color::Rgb(125, 132, 140);
const DOT_ACTIVE_COLOR: Color = Color::Rgb(188, 205, 238);
const DOT_INACTIVE_COLOR: Color = Color::Rgb(90, 94, 104);
const AVAILABLE_COLOR: Color = Color::Rgb(120, 200, 120);
const UNAVAILABLE_COLOR: Color = Color::Rgb(220, 100, 100);
const PROGRESS_FRAMES: [&str; 6] = ["●○○○○○", "●●○○○○", "●●●○○○", "●●●●○○", "●●●●●○", "●●●●●●"];

/// Command-line browser for exported gen-AI conversations
#[derive(Parser, Debug)]
#[command(name = "convos")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the exported conversation directory
    export_path: PathBuf,

    /// Conversation number (1-based index) or hash to display
    conversation_id: Option<String>,

    /// List all conversations
    #[arg(short, long, conflicts_with_all = ["artifacts"])]
    list: bool,

    /// Show or list artifacts
    #[arg(short, long)]
    artifacts: bool,

    /// Artifact number to download (requires conversation_number and --artifacts)
    artifact_number: Option<usize>,

    /// Output directory for downloaded artifact
    output_dir: Option<PathBuf>,
}

enum Mode {
    Interactive,
    ListOnly,
    ListAllArtifacts,
    ShowConversation { id: String, show_artifacts: bool },
    DownloadArtifact {
        conversation_id: String,
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
    let args = Args::parse();

    // Validate export path
    if !args.export_path.exists() {
        eprintln!(
            "The provided path `{}` does not exist.",
            args.export_path.display()
        );
        std::process::exit(66);
    }

    if !args.export_path.is_dir() {
        eprintln!(
            "The provided path `{}` is not a directory.",
            args.export_path.display()
        );
        std::process::exit(66);
    }

    // Determine mode based on arguments
    let mode = if args.list {
        Mode::ListOnly
    } else if args.conversation_id.is_none() && args.artifacts {
        Mode::ListAllArtifacts
    } else if args.conversation_id.is_none() {
        Mode::Interactive
    } else {
        let conversation_id = args.conversation_id.unwrap();

        if args.artifacts && args.artifact_number.is_some() {
            let artifact_number = args.artifact_number.unwrap();
            if artifact_number == 0 {
                eprintln!("Artifact number must be greater than zero.");
                std::process::exit(64);
            }
            Mode::DownloadArtifact {
                conversation_id,
                artifact_number,
                output_dir: args.output_dir,
            }
        } else if args.artifacts {
            Mode::ShowConversation {
                id: conversation_id,
                show_artifacts: true,
            }
        } else {
            if args.artifact_number.is_some() {
                eprintln!("Artifact number requires --artifacts flag.");
                std::process::exit(64);
            }
            if args.output_dir.is_some() {
                eprintln!("Output directory requires --artifacts and artifact number.");
                std::process::exit(64);
            }
            Mode::ShowConversation {
                id: conversation_id,
                show_artifacts: false,
            }
        }
    };

    if let Err(err) = run(&args.export_path, mode) {
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
        Mode::ShowConversation {
            id,
            show_artifacts,
        } => {
            if summaries.is_empty() {
                return Err(anyhow::anyhow!("no conversations available"));
            }
            let index = resolve_conversation_id(&id, &summaries)?;
            let summary = &summaries[index];
            let conversation = &conversations[summary.index];
            if show_artifacts {
                print_conversation_artifacts(export_path, conversation, summary, false);
            } else {
                print_conversation(export_path, conversation, summary, false);
            }
        }
        Mode::DownloadArtifact {
            conversation_id,
            artifact_number,
            output_dir,
        } => {
            if summaries.is_empty() {
                return Err(anyhow::anyhow!("no conversations available"));
            }
            let conversation_index = resolve_conversation_id(&conversation_id, &summaries)?;
            let summary = &summaries[conversation_index];
            let conversation = &conversations[summary.index];

            if conversation.artifacts.is_empty() {
                return Err(anyhow::anyhow!(
                    "conversation `{}` has no artifacts",
                    conversation_id
                ));
            }

            let artifact_index = artifact_number - 1;
            let artifact = conversation.artifacts.get(artifact_index).ok_or_else(|| {
                anyhow::anyhow!(
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
            "{} [{}] {}",
            edge("|"),
            accent(&format!("{:>2}", ordinal + 1)),
            summary.title
        );
        println!(
            "{}     {} · {}",
            edge("|"),
            dim(&summary.id),
            dim(&timestamp)
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
                return Err(anyhow::anyhow!(
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

fn artifact_availability_indicator(export_path: &Path, artifact_name: &str) -> String {
    // Check if artifact file exists
    let available = artifact_exists(export_path, artifact_name);

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

        let summary = matches[choice];
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

fn show_matches(matches: &[&ConversationSummary]) -> usize {
    println!(
        "{} {}",
        accent_bullet(),
        accent(&format!("found {} conversation(s).", matches.len()))
    );

    for (ordinal, summary) in matches.iter().enumerate().rev() {
        let timestamp = summary
            .created_at
            .map(format_timestamp)
            .unwrap_or_else(|| "unknown time".to_string());
        println!(
            "{} [{}] {}",
            edge("|"),
            accent(&format!("{:>2}", ordinal + 1)),
            summary.title
        );
        println!(
            "{}     {} · {}",
            edge("|"),
            dim(&summary.id),
            dim(&timestamp)
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
        Err(anyhow::anyhow!("input closed"))
    } else {
        Ok(buf)
    }
}
