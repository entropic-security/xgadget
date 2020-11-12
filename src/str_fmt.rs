use std::any::Any;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write;

use colored::Colorize;

use crate::binary;
use crate::gadget;

// Public API ----------------------------------------------------------------------------------------------------------

/// Format list of gadgets using a single formatter instance
pub fn str_fmt_gadgets(
    gadgets: &[gadget::Gadget],
    att_syntax: bool,
    color: bool,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    const BACKING_BUF_LEN: usize = 200;
    let mut backing_buf = [0_u8; BACKING_BUF_LEN];
    let mut format_buf = zydis::OutputBuffer::new(&mut backing_buf[..]);
    let mut instr_addr_str_tuples = Vec::new();

    let mut formatter = if att_syntax {
        zydis::formatter::Formatter::new(zydis::enums::FormatterStyle::ATT)?
    } else {
        zydis::formatter::Formatter::new(zydis::enums::FormatterStyle::INTEL)?
    };

    if color {
        formatter.set_print_mnemonic(Box::new(color_mnemonic_callback))?;
        formatter.set_print_register(Box::new(color_reg_callback))?;
    }

    for g in gadgets {
        let mut instr_str = String::new();
        let mut addrs_str = String::new();

        // Instruction
        for instr in &g.instrs {
            formatter.format_instruction(&instr, &mut format_buf, None, None)?;
            if color {
                instr_str.push_str(&format!("{}{} ", format_buf, ";".bright_magenta()));
            } else {
                instr_str.push_str(&format!("{}; ", format_buf));
            }
        }

        // Full match address
        if let Some(lowest_addr) = g.first_full_match() {
            if color {
                addrs_str.push_str(&format!(
                    "[ {} ]",
                    format!("0x{:016x}", lowest_addr).green()
                ));
            } else {
                addrs_str.push_str(&format!("[ 0x{:016x} ]", lowest_addr));
            }

        // Partial match address(es)
        } else if let Some(partial_match_str) = str_fmt_partial_matches(&g.partial_matches, color) {
            addrs_str.push_str(&format!("[ {} ]", &partial_match_str));
        }

        // Compensate for oddity in coloring callbacks
        instr_str.retain(|c| c != '\x1f');
        addrs_str.retain(|c| c != '\x1f');

        instr_addr_str_tuples.push((instr_str, addrs_str));
    }

    instr_addr_str_tuples.sort(); // Alphabetical
    Ok(instr_addr_str_tuples)
}

/// Format partial matches for a given gadget
pub fn str_fmt_partial_matches(
    partial_matches: &BTreeMap<u64, Vec<&binary::Binary>>,
    color: bool,
) -> Option<String> {
    str_fmt_partial_matches_internal(&mut partial_matches.clone(), color)
}

// Private API ---------------------------------------------------------------------------------------------------------

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

// Mnemonic coloring CFFI callback
fn color_mnemonic_callback(
    _formatter: &zydis::Formatter,
    buffer: &mut zydis::FormatterBuffer,
    ctx: &mut zydis::FormatterContext,
    _user_data: Option<&mut dyn Any>,
) -> Result<(), zydis::Status> {
    let instr = unsafe { &*ctx.instruction }; // Unsafe necessary due to Zydis CFFI
    buffer.append(zydis::TOKEN_MNEMONIC)?;
    let out_str = buffer.get_string()?;
    let mnemonic_str = instr.mnemonic.get_string().ok_or(zydis::Status::User)?;

    // TOOD: Without leading byte in format string, this panics...why?
    write!(out_str, "\x1f{}", mnemonic_str.cyan()).map_err(|_| zydis::Status::User)
}

// Register coloring CFFI callback
fn color_reg_callback(
    _formatter: &zydis::Formatter,
    buffer: &mut zydis::FormatterBuffer,
    _ctx: &mut zydis::FormatterContext,
    reg: zydis::enums::Register,
    _user_data: Option<&mut dyn Any>,
) -> Result<(), zydis::Status> {
    buffer.append(zydis::TOKEN_REGISTER)?;
    let out_str = buffer.get_string()?;
    let reg_str = reg.get_string().ok_or(zydis::Status::User)?;
    let reg_str_colored = match reg {
        zydis::Register::RSP | zydis::Register::ESP | zydis::Register::SP => reg_str.red(),
        _ => reg_str.yellow(),
    };

    // TOOD: Without leading byte in format string, this panics...why?
    write!(out_str, "\x1f{}", reg_str_colored).map_err(|_| zydis::Status::User)
}
