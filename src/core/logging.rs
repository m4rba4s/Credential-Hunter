use std::fmt;

use chrono::Local;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::{FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Maximum width of the fancy log frame interior (characters).
const FRAME_WIDTH: usize = 76;

/// ANSI escape prefix used for coloring output.
const ESC: &str = "\x1b";

/// Hyper-visual formatter that renders tracing events inside an ASCII art frame with colors.
#[derive(Default)]
pub struct FancyLogFormatter;

impl<S, N> FormatEvent<S, N> for FancyLogFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let message = visitor
            .message
            .unwrap_or_else(|| "<no message provided>".to_string());

        let mut lines: Vec<String> = message
            .lines()
            .map(|line| line.trim_end().to_string())
            .collect();

        if lines.is_empty() {
            lines.push("<empty>".to_string());
        }

        for (key, value) in visitor.extra_fields {
            lines.push(format!("{key}: {value}"));
        }

        if let Some(span) = ctx.lookup_current() {
            let span_info = format!("span: {}", span.name());
            lines.push(span_info);
        }

        let (color, glyph, label) = match *metadata.level() {
            tracing::Level::ERROR => ("31;1", "✖", "ERROR"),
            tracing::Level::WARN => ("33;1", "⚠", "WARN"),
            tracing::Level::INFO => ("36;1", "★", "INFO"),
            tracing::Level::DEBUG => ("35;1", "⚙", "DEBUG"),
            tracing::Level::TRACE => ("90", "⋯", "TRACE"),
        };

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let header = format!("{glyph} {label} :: {} :: {}", timestamp, metadata.target());

        writer.write_str("\n")?;
        write_horizontal_border(&mut writer, color, '╔', '╗')?;
        write_content_line(&mut writer, color, &header)?;
        write_horizontal_border(&mut writer, color, '╠', '╣')?;

        for line in lines {
            write_content_line(&mut writer, color, &line)?;
        }

        write_horizontal_border(&mut writer, color, '╚', '╝')?;
        writer.write_str("\n")
    }
}

/// Records fields emitted by tracing events for later formatting.
#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    extra_fields: Vec<(String, String)>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.capture(field, format!("{:?}", value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.capture(field, value.to_string());
    }
}

impl FieldVisitor {
    fn capture(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.extra_fields.push((field.name().to_string(), value));
        }
    }
}

fn write_horizontal_border(
    writer: &mut Writer<'_>,
    color: &str,
    left: char,
    right: char,
) -> fmt::Result {
    let fill = "═".repeat(FRAME_WIDTH + 2);
    writeln!(
        writer,
        "{esc}[{color}m{left}{fill}{right}{esc}[0m",
        esc = ESC,
        color = color,
        left = left,
        right = right,
        fill = fill,
    )
}

fn write_content_line(writer: &mut Writer<'_>, color: &str, content: &str) -> fmt::Result {
    let mut display = content.to_string();
    let max = FRAME_WIDTH;
    if display.len() > max {
        display.truncate(max.saturating_sub(3));
        display.push_str("...");
    }
    let padding = max.saturating_sub(display.len());
    writeln!(
        writer,
        "{esc}[{color}m║ {line}{space} ║{esc}[0m",
        esc = ESC,
        color = color,
        line = display,
        space = " ".repeat(padding)
    )
}

/// Emit the high-energy startup banner with gradients and ASCII art.
pub fn emit_banner() {
    const BANNER: [&str; 7] = [
        " ███████╗ ██████╗██╗  ██╗",
        " ██╔════╝██╔════╝██║ ██╔╝",
        " █████╗  ██║     █████╔╝ ",
        " ██╔══╝  ██║     ██╔═██╗ ",
        " ██║     ╚██████╗██║  ██╗",
        " ╚═╝      ╚═════╝╚═╝  ╚═╝",
        " Enterprise Credential Hunter",
    ];

    let palette = [214, 209, 203, 198, 164, 129, 93];

    println!("\n{esc}[1m{esc}[38;5;51m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{esc}[0m", esc = ESC);
    for (line, color) in BANNER.iter().zip(palette.iter().cycle()) {
        println!(
            "{esc}[38;5;{color}m┃ {line:<54} ┃{esc}[0m",
            esc = ESC,
            color = color,
            line = line,
        );
    }
    println!("{esc}[1m{esc}[38;5;51m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{esc}[0m\n", esc = ESC);
}
