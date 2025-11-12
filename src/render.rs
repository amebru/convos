//! Markdown rendering with syntax highlighting (optional for GUI apps).

use nu_ansi_term::{Color, Style as AnsiStyle};
use once_cell::sync::Lazy;
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser as MarkdownParser, Tag};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::{LinesWithEndings, as_24_bit_terminal_escaped};

static SYNTAX_SET: Lazy<SyntaxSet> = Lazy::new(SyntaxSet::load_defaults_newlines);
static THEME: Lazy<Theme> = Lazy::new(|| {
    let theme_set = ThemeSet::load_defaults();
    theme_set
        .themes
        .get("base16-ocean.dark")
        .cloned()
        .unwrap_or_else(|| theme_set.themes.values().next().cloned().unwrap())
});

/// Render markdown text with ANSI colors and syntax highlighting.
pub fn render_markdown(text: &str) -> String {
    let mut output = String::new();
    let mut inline_styles: Vec<InlineStyle> = Vec::new();
    let mut list_stack: Vec<ListState> = Vec::new();
    let mut code_block: Option<(Option<String>, String)> = None;

    let options = Options::ENABLE_TABLES | Options::ENABLE_FOOTNOTES;
    let parser = MarkdownParser::new_ext(text, options);

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
