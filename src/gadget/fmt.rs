use std::collections::BTreeMap;
use std::fmt::Display;
use std::hash::Hasher;

use colored::Colorize;
use rayon::prelude::*;
use rustc_hash::FxHasher;

use crate::gadget;

// Public Types and Traits ---------------------------------------------------------------------------------------------

/// Implementors track count of visible terminal characters for `Display`'s `fmt` function (for colored strings).
pub trait DisplayLen: Display {
    /// Get the count of visible terminal characters for `Display`'s `fmt` function
    fn len(&self) -> usize;
}

/// String wrapper that tracks count of visible terminal characters for `Display`'s `fmt` function.
pub struct DisplayString(pub String);

impl DisplayLen for DisplayString {
    /// Get the count of visible terminal characters for `Display`'s `fmt` function
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for DisplayString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Format list of gadgets in parallel, return alphabetically sorted `String`s
pub fn fmt_gadget_str_list(
    gadgets: &[gadget::Gadget],
    att_syntax: bool,
    color: bool,
) -> Vec<(String, String)> {
    let mut instr_addr_str_tuples = gadgets
        .par_iter()
        .map(|g| {
            let output_instrs = g.fmt_instrs(att_syntax, color);
            let output_addrs = g
                .fmt_best_match_addrs(color)
                .unwrap_or(Box::new(DisplayString(String::new())));

            (format!("{}", output_instrs), format!("{}", output_addrs))
        })
        .collect::<Vec<(String, String)>>();

    instr_addr_str_tuples.sort_unstable(); // Alphabetical order, for analyst workflow
    instr_addr_str_tuples
}

/// Get instruction formatter (ATT or Intel syntax).
pub fn get_formatter(att_syntax: bool) -> Box<dyn iced_x86::Formatter> {
    match att_syntax {
        true => {
            let mut formatter = iced_x86::GasFormatter::new();
            config_formatter(&mut formatter);
            Box::new(formatter)
        }
        false => {
            let mut formatter = iced_x86::IntelFormatter::new();
            config_formatter(&mut formatter);
            Box::new(formatter)
        }
    }
}

// Private Gadget Formatter --------------------------------------------------------------------------------------------

// Custom instruction formatter output, enables coloring.
// Avoids storing duplicate colored strings - good for longer gadgets with repeating operators/operands
pub(crate) struct GadgetFormatterOutput {
    tokens: BTreeMap<u64, colored::ColoredString>,
    order: Vec<u64>,
    display_len: usize,
}

impl GadgetFormatterOutput {
    /// Constructor
    pub fn new() -> Self {
        Self {
            tokens: BTreeMap::new(),
            order: Vec::new(),
            display_len: 0,
        }
    }

    // Compute hash for a (text, kind) tuple
    #[inline]
    fn compute_hash(text: &str, kind: iced_x86::FormatterTextKind) -> u64 {
        let mut h = FxHasher::default();
        h.write(text.as_bytes());
        h.write_u8(kind as u8);

        h.finish()
    }
}

impl iced_x86::FormatterOutput for GadgetFormatterOutput {
    fn write(&mut self, text: &str, kind: iced_x86::FormatterTextKind) {
        self.display_len += text.len();
        let hash = Self::compute_hash(text, kind);
        match self.tokens.contains_key(&hash) {
            true => self.order.push(hash),
            false => {
                self.tokens.insert(hash, color_token(text, kind));
                self.order.push(hash);
            }
        }
    }
}

impl Display for GadgetFormatterOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for hash in &self.order {
            if let Some(token) = self.tokens.get(hash) {
                write!(f, "{}", token)?;
            }
        }
        Ok(())
    }
}

impl DisplayLen for GadgetFormatterOutput {
    fn len(&self) -> usize {
        self.display_len
    }
}

// Private API ---------------------------------------------------------------------------------------------------------

// Configure instruction formatter
#[inline]
fn config_formatter<F: iced_x86::Formatter>(formatter: &mut F) {
    let fmt_opts = formatter.options_mut();
    fmt_opts.set_first_operand_char_index(0);
    fmt_opts.set_uppercase_hex(false);
    fmt_opts.set_rip_relative_addresses(true);
    fmt_opts.set_hex_prefix("0x");
    fmt_opts.set_hex_suffix("");
    fmt_opts.set_small_hex_numbers_in_decimal(false);
    fmt_opts.set_space_after_operand_separator(true);
}

// Coloring ruleset
#[inline]
fn color_token<'a>(s: &str, kind: iced_x86::FormatterTextKind) -> colored::ColoredString {
    match kind {
        iced_x86::FormatterTextKind::Directive | iced_x86::FormatterTextKind::Keyword => s.blue(),
        iced_x86::FormatterTextKind::Prefix | iced_x86::FormatterTextKind::Mnemonic => s.cyan(),
        iced_x86::FormatterTextKind::Label | iced_x86::FormatterTextKind::Function => {
            s.bright_green()
        }
        iced_x86::FormatterTextKind::LabelAddress
        | iced_x86::FormatterTextKind::FunctionAddress => s.green(),
        iced_x86::FormatterTextKind::Punctuation => s.bright_magenta(),
        iced_x86::FormatterTextKind::Register => {
            // Special case the stack pointer - typically don't want to overwrite
            match s {
                "rsp" | "esp" | "sp" => s.red(),
                _ => s.yellow(),
            }
        }
        _ => s.white(),
    }
}

/*
// Coloring ruleset
#[inline]
fn write_color<'a>(s: &'a String, kind: iced_x86::FormatterTextKind, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match kind {
        iced_x86::FormatterTextKind::Directive | iced_x86::FormatterTextKind::Keyword => write!(f, "{}", s.blue()),
        iced_x86::FormatterTextKind::Prefix | iced_x86::FormatterTextKind::Mnemonic => write!(f, "{}", s.cyan()),
        iced_x86::FormatterTextKind::Label | iced_x86::FormatterTextKind::Function => {
            write!(f, "{}", s.bright_green())
        }
        iced_x86::FormatterTextKind::LabelAddress
        | iced_x86::FormatterTextKind::FunctionAddress => write!(f, "{}", s.green()),
        iced_x86::FormatterTextKind::Punctuation => write!(f, "{}", s.bright_magenta()),
        iced_x86::FormatterTextKind::Register => {
            // Special case the stack pointer - typically don't want to overwrite
            match s.as_str() {
                "rsp" | "esp" | "sp" => write!(f, "{}", s.red()),
                _ => write!(f, "{}", s.yellow()),
            }
        }
        _ => write!(f, "{}", s.white()),
    }
}
*/
