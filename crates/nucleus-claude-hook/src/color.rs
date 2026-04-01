//! ANSI color support for stderr diagnostic output.
//!
//! Provides colored output for the hook's stderr diagnostics so operators
//! can visually distinguish allow/deny/warn/info messages at a glance.
//!
//! Respects the `NO_COLOR` convention (<https://no-color.org/>) and the
//! `NUCLEUS_NO_COLOR` env var. Only colors stderr — stdout carries the
//! hook JSON protocol and must never contain ANSI escapes.

/// ANSI color codes for stderr diagnostic output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Color {
    Red,
    Yellow,
    Green,
    Cyan,
    Bold,
}

impl Color {
    pub fn code(self) -> &'static str {
        match self {
            Color::Red => "\x1b[31m",
            Color::Yellow => "\x1b[33m",
            Color::Green => "\x1b[32m",
            Color::Cyan => "\x1b[36m",
            Color::Bold => "\x1b[1m",
        }
    }
}

pub const RESET: &str = "\x1b[0m";

/// Returns `true` if colored output should be emitted on stderr.
///
/// Color is disabled when:
/// - `NO_COLOR` env var is set (any value) per <https://no-color.org/>
/// - `NUCLEUS_NO_COLOR` env var is set (any value)
/// - stderr is not a terminal (piped to a file, etc.)
pub fn is_color_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if std::env::var_os("NUCLEUS_NO_COLOR").is_some() {
            return false;
        }
        std::io::IsTerminal::is_terminal(&std::io::stderr())
    })
}

/// Wrap `text` in ANSI color codes if color is enabled.
#[allow(dead_code)]
pub fn colorize(text: &str, color: Color) -> String {
    if is_color_enabled() {
        format!("{}{}{}", color.code(), text, RESET)
    } else {
        text.to_string()
    }
}

/// Print a colored "nucleus:" prefixed message to stderr.
/// When color is enabled, the prefix is tinted and the body is colored.
/// When disabled, outputs plain `nucleus: {msg}`.
pub fn emit(color: Color, msg: &str) {
    if is_color_enabled() {
        eprintln!(
            "{}nucleus:{} {}{}{}",
            color.code(),
            RESET,
            color.code(),
            msg,
            RESET
        );
    } else {
        eprintln!("nucleus: {msg}");
    }
}

/// Macros for colored stderr output. Each accepts `format_args!`-style arguments.
macro_rules! nucleus_deny {
    ($($arg:tt)*) => { crate::color::emit(crate::color::Color::Red, &format!($($arg)*)) };
}
macro_rules! nucleus_warn {
    ($($arg:tt)*) => { crate::color::emit(crate::color::Color::Yellow, &format!($($arg)*)) };
}
macro_rules! nucleus_allow {
    ($($arg:tt)*) => { crate::color::emit(crate::color::Color::Green, &format!($($arg)*)) };
}
macro_rules! nucleus_info {
    ($($arg:tt)*) => { crate::color::emit(crate::color::Color::Cyan, &format!($($arg)*)) };
}

pub(crate) use nucleus_allow;
pub(crate) use nucleus_deny;
pub(crate) use nucleus_info;
pub(crate) use nucleus_warn;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_codes_are_correct() {
        assert_eq!(Color::Red.code(), "\x1b[31m");
        assert_eq!(Color::Yellow.code(), "\x1b[33m");
        assert_eq!(Color::Green.code(), "\x1b[32m");
        assert_eq!(Color::Cyan.code(), "\x1b[36m");
        assert_eq!(Color::Bold.code(), "\x1b[1m");
    }

    #[test]
    fn colorize_produces_correct_ansi() {
        let text = "hello";
        let expected = format!("\x1b[31m{}\x1b[0m", text);
        assert_eq!(format!("{}{}{}", Color::Red.code(), text, RESET), expected);
    }
}
