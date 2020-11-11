use std::collections::BTreeSet;
use std::error::Error;

//use hashbrown::{HashMap, HashSet};
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::binary;
use crate::gadget;
use crate::semantics;

/// Max instruction size in bytes
pub const MAX_INSTR_BYTE_CNT: usize = 15;

// Search Flags --------------------------------------------------------------------------------------------------------

bitflags! {
    /// Bitflag that controls search parameters
    pub struct SearchConfig: u32 {
        const UNSET = 0b0000_0000;
        const ROP   = 0b0000_0001;
        const JOP   = 0b0000_0010;
        const SYS   = 0b0000_0100;
        const IMM16 = 0b0000_1000;
        const PART  = 0b0001_0000;
        //const JMP   = 0b0010_0000;  // TODO: use this to allow search with mid-gadget jumps (non-default)
        const DEFAULT = Self::ROP.bits | Self::JOP.bits | Self::SYS.bits;
    }
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Search 1+ binaries for ROP gadgets (common gadgets if > 1)
pub fn find_gadgets<'a>(
    bins: &'a [binary::Binary],
    max_len: usize,
    s_config: SearchConfig,
) -> Result<Vec<gadget::Gadget<'a>>, Box<dyn Error>> {
    // Process binaries in parallel
    let decoders = get_all_decoders(&bins)?;
    let parallel_results: Vec<(&binary::Binary, HashSet<gadget::Gadget>)> = bins
        .par_iter()
        .zip(decoders)
        .map(|(bin, dec)| (bin, find_gadgets_single_bin(bin, &dec, max_len, s_config)))
        .collect();

    // Filter to cross-variant gadgets
    match parallel_results.split_first() {
        Some((first_result, remaining_results)) => {
            let (first_bin, first_set) = first_result;
            let mut common_gadgets = first_set.clone();

            for (next_bin, next_set) in remaining_results {
                // Filter common gadgets (set intersection)
                common_gadgets.retain(|g| next_set.contains(&g));

                // TODO (tnballo): there has to be a cleaner way to implement this!
                // Update full and partial matches
                let mut temp_gadgets = HashSet::default();
                for common_g in common_gadgets {
                    match next_set.get(&common_g) {
                        Some(next_set_g) => {
                            // Full matches
                            let full_matches: BTreeSet<_> = common_g
                                .full_matches
                                .intersection(&next_set_g.full_matches)
                                .cloned()
                                .collect();

                            // Short-circuit partial collector if not requested
                            if !s_config.intersects(SearchConfig::PART) && full_matches.is_empty() {
                                continue;
                            }

                            // Cross-variant gadget!
                            let mut updated_g = gadget::Gadget::new(common_g.instrs, full_matches);

                            // Partial matches (optional)
                            if s_config.intersects(SearchConfig::PART) {
                                for addr in &common_g.full_matches {
                                    updated_g.partial_matches.insert(*addr, vec![first_bin]);
                                }

                                for addr in &next_set_g.full_matches {
                                    match updated_g.partial_matches.get_mut(&addr) {
                                        Some(bin_ref_vec) => bin_ref_vec.push(*next_bin),
                                        // TODO: Replace with unwrap_none() once on stable
                                        _ => {
                                            updated_g.partial_matches.insert(*addr, vec![next_bin]);
                                        }
                                    }
                                }
                            }

                            temp_gadgets.insert(updated_g);
                        }
                        None => return Err("Fatal gadget comparison logic bug!".into()),
                    }
                }
                common_gadgets = temp_gadgets;
            }
            Ok(common_gadgets.into_iter().collect())
        }
        _ => Err("No binaries to search!".into()),
    }
}

// Private API ---------------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct DecodeConfig<'a> {
    bin: &'a binary::Binary,
    seg: &'a binary::Segment,
    decoder: &'a zydis::Decoder,
    stop_idx: usize,
    flow_op_idx: usize,
    max_len: usize,
}

// Get offsets of potential gadget tails within a segment
fn get_gadget_tail_offsets(
    seg: &binary::Segment,
    s_config: SearchConfig,
    decoder: &zydis::Decoder,
) -> Vec<usize> {
    (1..seg.bytes.len())
        .into_par_iter()
        .filter(|offset| match decoder.decode(&seg.bytes[(*offset)..]) {
            Ok(res) => match res {
                Some(instr) => {
                    (s_config.intersects(SearchConfig::ROP)
                        && semantics::is_ret(&instr)
                        && !semantics::is_ret_imm16(&instr))
                        || (s_config.intersects(SearchConfig::IMM16)
                            && semantics::is_ret_imm16(&instr))
                        || (s_config.intersects(SearchConfig::JOP)
                            && semantics::is_jop_gadget_tail(&instr))
                        || (s_config.intersects(SearchConfig::SYS)
                            && semantics::is_sys_gadget_tail(&instr))
                }
                None => false,
            },
            Err(_) => false,
        })
        .collect()
}

// Get Zydis decoder for binary
fn get_decoder(bin: &binary::Binary) -> Result<zydis::Decoder, Box<dyn Error>> {
    let (machine_mode, addr_width) = match &bin.arch {
        binary::Arch::X8086 => (
            zydis::enums::MachineMode::LONG_COMPAT_16,
            zydis::enums::AddressWidth::_16,
        ),
        binary::Arch::X86 => (
            zydis::enums::MachineMode::LONG_COMPAT_32,
            zydis::enums::AddressWidth::_32,
        ),
        binary::Arch::X64 => (
            zydis::enums::MachineMode::LONG_64,
            zydis::enums::AddressWidth::_64,
        ),
        _ => {
            return Err(format!("Cannot init decoder for architecture \'{:?}\'!", bin.arch).into())
        }
    };

    let decoder = zydis::Decoder::new(machine_mode, addr_width)?;
    Ok(decoder)
}

// Get decoders for a list of binaries, any single failure -> all fail
fn get_all_decoders(bins: &[binary::Binary]) -> Result<Vec<zydis::Decoder>, Box<dyn Error>> {
    let (decoders, errors): (Vec<_>, Vec<_>) = bins
        .iter()
        .map(|bin| get_decoder(bin))
        .partition(Result::is_ok);

    let decoders: Vec<_> = decoders.into_iter().map(Result::unwrap).collect();
    let errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

    if !errors.is_empty() {
        return Err("Failed to get decoder for 1 or more binaries!".into());
    }

    Ok(decoders)
}

/// Setup search parameters
fn get_decode_config<'a>(
    bin: &'a binary::Binary,
    seg: &'a binary::Segment,
    decoder: &'a zydis::Decoder,
    flow_op_idx: usize,
    max_len: usize,
) -> DecodeConfig<'a> {
    let mut stop_idx = 0;

    // Optional early stop
    let ret_prefix_size = max_len * MAX_INSTR_BYTE_CNT;
    if (max_len != 0) && (flow_op_idx > ret_prefix_size) {
        stop_idx = flow_op_idx - ret_prefix_size;
    }

    DecodeConfig {
        bin,
        seg,
        decoder,
        stop_idx,
        flow_op_idx,
        max_len,
    }
}

/// Iterative search backwards from instance of ret opcode
fn iterative_decode(d_config: &DecodeConfig) -> Vec<(Vec<zydis::DecodedInstruction>, u64)> {
    let mut instr_sequences = Vec::new();

    for offset in (d_config.stop_idx..=d_config.flow_op_idx).rev() {
        let mut instrs = Vec::new();
        let buf_start_addr = d_config.seg.addr + offset as u64;
        let flow_op_addr = d_config.seg.addr + d_config.flow_op_idx as u64;

        // Zydis iterator implements early decode stop on invalid instruction
        // https://docs.rs/zydis/3.0.0/zydis/ffi/struct.Decoder.html#method.instruction_iterator
        for (i, pc) in d_config
            .decoder
            .instruction_iterator(&d_config.seg.bytes[offset..], buf_start_addr)
        {
            // Early decode stop if control flow doesn't reach ret opcode
            let gadget_tail = semantics::is_gadget_tail(&i);
            if (pc > flow_op_addr)
                || ((pc != flow_op_addr) && gadget_tail)
                || (semantics::is_call(&i) && !gadget_tail)
                || (semantics::is_jmp(&i) && !gadget_tail)
                || semantics::is_int(&i)
            {
                break;
            }

            instrs.push(i);

            // Early decode stop if length limit hit
            if (d_config.max_len != 0) && (instrs.len() == d_config.max_len) {
                break;
            }
        }

        // Find gadgets. Awww yisss.
        if let Some(i) = instrs.last() {
            // ROP
            if (semantics::is_ret(&i) && (instrs.len() > 1))

                // JOP
                || (semantics::is_reg_set_jmp(&i)
                    || semantics::is_mem_ptr_set_jmp(&i)
                    || semantics::is_reg_set_call(&i)
                    || semantics::is_mem_ptr_set_call(&i))

                // SYS
                || (semantics::is_syscall(&i)
                    || (semantics::is_legacy_linux_syscall(&i) && (d_config.bin.format == binary::Format::ELF)))
            {
                instr_sequences.push((instrs, buf_start_addr));
            }
        }
    }

    instr_sequences
}

/// Search a binary for ROP gadgets
fn find_gadgets_single_bin<'a>(
    bin: &'a binary::Binary,
    decoder: &zydis::Decoder,
    max_len: usize,
    config: SearchConfig,
) -> HashSet<gadget::Gadget<'a>> {
    let mut gadget_collector: HashMap<Vec<zydis::DecodedInstruction>, BTreeSet<u64>> =
        HashMap::default();

    for seg in &bin.segments {
        let flow_op_idxs = get_gadget_tail_offsets(seg, config, decoder);

        // Parallel search. Only dissemble offsets from existing gadget tail opcodes.
        let parallel_results: Vec<(Vec<zydis::DecodedInstruction>, u64)> = flow_op_idxs
            .par_iter()
            .map(|&flow_op_idx| get_decode_config(bin, seg, decoder, flow_op_idx, max_len))
            .flat_map(|config| iterative_decode(&config))
            .collect();

        // Running consolidation of parallel results
        for (instrs, addr) in parallel_results {
            match gadget_collector.get_mut(&instrs) {
                Some(addrs) => {
                    addrs.insert(addr);
                }
                _ => {
                    let mut addrs = BTreeSet::new();
                    addrs.insert(addr);
                    gadget_collector.insert(instrs, addrs);
                }
            }
        }
    }

    // Finalize parallel results
    gadget_collector
        .into_iter()
        .map(|(instrs, addrs)| gadget::Gadget::new(instrs, addrs))
        .collect()
}