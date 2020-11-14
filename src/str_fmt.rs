use std::collections::BTreeMap;

use colored::Colorize;
use iced_x86;
use rayon::prelude::*;

use crate::binary;
use crate::gadget;

// Public API ----------------------------------------------------------------------------------------------------------

/// Format list of gadgets in parallel, return alphabetically sorted
pub fn str_fmt_gadgets(
    gadgets: &[gadget::Gadget],
    att_syntax: bool,
    color: bool,
) -> Vec<(String, String)> {
    let mut instr_addr_str_tuples = gadgets
        .par_iter()
        .map(|g| {
            // Thread state
            let mut instr_str = String::new();
            let mut addrs_str = String::new();
            let mut formatter = get_formatter(att_syntax);
            let mut output = GadgetFormatterOutput::new();

            // Instruction
            for instr in &g.instrs {
                // Instruction contents
                output.tokens.clear();
                formatter.format(&instr, &mut output);
                for (text, kind) in output.tokens.iter() {
                    if color {
                        if (*kind == iced_x86::FormatterTextKind::Register) && (text.contains("sp"))
                        {
                            instr_str.push_str(&format!("{}", text.as_str().red()));
                        } else {
                            instr_str.push_str(&format!("{}", set_color(text.as_str(), *kind)));
                        }
                    } else {
                        instr_str.push_str(text.as_str());
                    }
                }

                // Instruction separator
                if color {
                    instr_str.push_str(&format!("{} ", ";".bright_magenta()));
                } else {
                    instr_str.push_str(";");
                }
            }

            // Full match address
            if let Some(addr) = g.first_full_match() {
                if color {
                    addrs_str.push_str(&format!("[ {} ]", format!("0x{:016x}", addr).green()));
                } else {
                    addrs_str.push_str(&format!("[ 0x{:016x} ]", addr));
                }

            // Partial match address(es)
            } else if let Some(partial_match_str) = str_fmt_partial_matches(&g, color) {
                addrs_str.push_str(&format!("[ {} ]", &partial_match_str));
            }

            (instr_str, addrs_str)
        })
        .collect::<Vec<(String, String)>>();

    instr_addr_str_tuples.sort(); // Alphabetical order, for analyst workflow
    instr_addr_str_tuples
}

/// Format partial matches for a given gadget
pub fn str_fmt_partial_matches(gadget: &gadget::Gadget, color: bool) -> Option<String> {
    str_fmt_partial_matches_internal(&mut gadget.partial_matches.clone(), color)
}

// Private API ---------------------------------------------------------------------------------------------------------

// Get instruction formatter
fn get_formatter(att_syntax: bool) -> Box<dyn iced_x86::Formatter> {
    if att_syntax {
        let mut formatter = iced_x86::GasFormatter::new();
        config_formatter(&mut formatter);
        Box::new(formatter)
    } else {
        let mut formatter = iced_x86::IntelFormatter::new();
        config_formatter(&mut formatter);
        Box::new(formatter)
    }
}

// Configure instruction formatter
fn config_formatter<F: iced_x86::Formatter>(formatter: &mut F) {
    formatter.options_mut().set_first_operand_char_index(0);
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_rip_relative_addresses(true);
    formatter
        .options_mut()
        .set_hex_prefix_string("0x".to_string());
    formatter
        .options_mut()
        .set_hex_suffix_string("".to_string());
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
}

// Partial match format helper, recursively shrinks a working set
fn str_fmt_partial_matches_internal(
    mut partial_matches: &mut BTreeMap<u64, Vec<&binary::Binary>>,
    color: bool,
) -> Option<String> {
    // Find largest subset of binaries with match for a given address (best partial match)
    match partial_matches
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()))
    {
        Some((bpm_addr, bpm_bins)) => {
            let mut match_str = String::new();

            // This pair of clones ends a borrow fo partial_matches and lets us remove from it later
            // This eliminates the need to clone the whole map each level of recursion
            let bpm_addr = *bpm_addr;
            let mut bpm_bins = bpm_bins.clone();
            bpm_bins.sort_by(|b1, b2| b1.name.to_lowercase().cmp(&b2.name.to_lowercase()));

            // Commit best partial match
            match bpm_bins.split_last() {
                Some((last_bin, prior_bpm_bins)) => {
                    for pb in prior_bpm_bins {
                        match_str.push_str(&format!("'{}', ", pb.name));
                    }
                    match_str.push_str(&format!("'{}': ", last_bin.name));
                    if color {
                        match_str.push_str(&format!("{}", format!("0x{:016x}", bpm_addr).green()));
                    } else {
                        match_str.push_str(&format!("0x{:016x}", bpm_addr));
                    }
                }
                None => return None,
            }

            // Remove committed binaries from the remainder of partial matches
            partial_matches.remove(&bpm_addr);
            partial_matches
                .iter_mut()
                .for_each(|(_, bins)| bins.retain(|&b| !bpm_bins.contains(&b)));

            // Recursion depth bound by number of binaries
            match str_fmt_partial_matches_internal(&mut partial_matches, color) {
                Some(remaining_match_str) => {
                    match_str.push_str(", ");
                    match_str.push_str(&remaining_match_str);
                    Some(match_str)
                }
                None => Some(match_str),
            }
        }
        None => None,
    }
}

// Coloring ------------------------------------------------------------------------------------------------------------

// Custom instruction formatter output, enables coloring
struct GadgetFormatterOutput {
    tokens: Vec<(String, iced_x86::FormatterTextKind)>,
}

impl GadgetFormatterOutput {
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }
}

impl iced_x86::FormatterOutput for GadgetFormatterOutput {
    fn write(&mut self, text: &str, kind: iced_x86::FormatterTextKind) {
        self.tokens.push((String::from(text), kind));
    }
}

// Coloring ruleset, but doesn't account for special casing the stack pointer
fn set_color(s: &str, kind: iced_x86::FormatterTextKind) -> colored::ColoredString {
    match kind {
        iced_x86::FormatterTextKind::Directive | iced_x86::FormatterTextKind::Keyword => s.blue(),
        iced_x86::FormatterTextKind::Prefix | iced_x86::FormatterTextKind::Mnemonic => s.cyan(),
        iced_x86::FormatterTextKind::Register => s.yellow(),
        iced_x86::FormatterTextKind::Number => s.white().bold(),
        _ => s.white(),
    }
}
