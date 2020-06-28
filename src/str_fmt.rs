use std::error::Error;
use std::any::Any;
use std::fmt::Write;
use std::collections::{BTreeMap};

use colored::Colorize;

use crate::gadget;
use crate::binary;

// Public API ----------------------------------------------------------------------------------------------------------

/// Print list of gadgets using a single formatter instance
pub fn str_fmt_gadgets(gadgets: &[gadget::Gadget], att_syntax: bool, color: bool) -> Result<Vec<(String, String)>, Box<dyn Error>> {
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
                instr_str.push_str(&format!("{}{} ", format_buf, ";".magenta()));
            } else {
                instr_str.push_str(&format!("{}; ", format_buf));
            }
        }

        // Full match address
        if let Some(lowest_addr) = g.full_matches.iter().collect::<Vec<&u64>>().iter().next() {
            if color {
                addrs_str.push_str(&format!("[ {} ]", format!("0x{:016x}", lowest_addr).green()));
            } else {
                addrs_str.push_str(&format!("[ 0x{:016x} ]", lowest_addr));
            }

        // Partial match address(es)
        } else if let Some(partial_match_str) = str_fmt_partial_matches(&g.partial_matches, color) {
            addrs_str.push_str(&format!("[ {} ]", &partial_match_str));
        }

        instr_addr_str_tuples.push((instr_str.trim().to_string(), addrs_str));
    }

    instr_addr_str_tuples.sort(); // Alphabetical
    Ok(instr_addr_str_tuples)
}

// TODO (tnballo): the output is clean, but the performance of this function is awful!!! E.g.
//
// Unique cross-variant gadgets found ..... 174839
// Search/filter time ..................... 8.234118991s
// Print time ............................. 147.605491848s
//
/// Print partial matches for a given gadget
pub fn str_fmt_partial_matches(partial_matches: &BTreeMap<u64, Vec<&binary::Binary>>, color: bool) -> Option<String> {

    if let Some((mut addr_largest_subset, mut bins_largest_subset)) = partial_matches.iter().next() {

        let mut match_str = String::new();

        // Find largest subset of binaries with match for a given address
        for (addr, bins) in partial_matches {
            if bins.len() > bins_largest_subset.len() {
                addr_largest_subset = &addr;
                bins_largest_subset = &bins;
            }
        }

        // Commit result to string
        if let Some((last_bin, prior_bins)) = bins_largest_subset.split_last() {
            for pb in prior_bins {
                match_str.push_str(&format!("'{}', ", pb.name));
            }
            match_str.push_str(&format!("'{}': ", last_bin.name));
            if color {
                match_str.push_str(&format!("{}", format!("0x{:016x}", addr_largest_subset).green()));
            } else {
                match_str.push_str(&format!("0x{:016x}", addr_largest_subset));
            }
        } else {
            return None;
        }

        // Remove committed binaries from the remainder of partial matches
        let mut remaining_matches = partial_matches.clone();
        remaining_matches.remove(addr_largest_subset);

        let mut empty_addrs = Vec::new();
        for (addr, bins) in remaining_matches.iter_mut() {
            bins.retain(|&b| !bins_largest_subset.contains(&b));
            if bins.is_empty() {
                empty_addrs.push(*addr);
            }
        }

        for addr in empty_addrs {
            remaining_matches.remove(&addr);
        }

        // Recursively repeat!
        match str_fmt_partial_matches(&remaining_matches, color) {
            Some(remaining_match_str) => {
                match_str.push_str(", ");
                match_str.push_str(&remaining_match_str);
                return Some(match_str)
            },
            None => return Some(match_str)
        }
    }

    None
}

// Private API ---------------------------------------------------------------------------------------------------------

fn color_mnemonic_callback(
    _formatter: &zydis::Formatter,
    buffer: &mut zydis::FormatterBuffer,
    ctx: &mut zydis::FormatterContext,
    _user_data: Option<&mut dyn Any>,
) -> Result<(), zydis::Status> {

    let instr = unsafe { &*ctx.instruction };
    buffer.append(zydis::TOKEN_MNEMONIC)?;
    let out_str = buffer.get_string()?;
    let mnemonic_str = instr.mnemonic.get_string().ok_or(zydis::Status::Failed)?;

    // TOOD: Without leading byte in format string, this panics...why?
    write!(out_str, "\x1e{}", mnemonic_str.cyan()).map_err(|_| zydis::Status::Failed)
}

fn color_reg_callback(
    _formatter: &zydis::Formatter,
    buffer: &mut zydis::FormatterBuffer,
    _ctx: &mut zydis::FormatterContext,
    reg: zydis::enums::Register,
    _user_data: Option<&mut dyn Any>,
) -> Result<(), zydis::Status> {

    buffer.append(zydis::TOKEN_REGISTER)?;
    let out_str = buffer.get_string()?;
    let reg_str = reg.get_string().ok_or(zydis::Status::Failed)?;

    // TOOD: Without leading byte in format string, this panics...why?
    write!(out_str, "\x1e{}", reg_str.yellow()).map_err(|_| zydis::Status::Failed)
}