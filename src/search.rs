use std::collections::BTreeSet;
use std::error::Error;

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
        const PART  = 0b0000_1000;
        const IMM16 = 0b0001_0000;
        const CALL  = 0b0010_0000;
        const DEFAULT = Self::ROP.bits | Self::JOP.bits | Self::SYS.bits;
    }
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Search 1+ binaries for ROP gadgets (common gadgets if > 1)
pub fn find_gadgets(
    bins: &[binary::Binary],
    max_len: usize,
    s_config: SearchConfig,
) -> Result<Vec<gadget::Gadget>, Box<dyn Error>> {
    // Process binaries in parallel
    let parallel_results: Vec<(&binary::Binary, HashSet<gadget::Gadget>)> = bins
        .par_iter()
        .map(|bin| (bin, find_gadgets_single_bin(bin, max_len, s_config)))
        .collect();

    // Filter to cross-variant gadgets
    match parallel_results.split_first() {
        Some((first_result, remaining_results)) => {
            let (first_bin, first_set) = first_result;
            let mut common_gadgets = first_set.clone();

            for (next_bin, next_set) in remaining_results {
                // Filter common gadgets (set intersection)
                common_gadgets.retain(|g| next_set.contains(&g));

                // TODO (tnballo): there has to be a cleaner way to implement this! Once drain_filter() on stable?
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

                            // Short-circuit if no full matches and partial collector if not requested
                            if (!s_config.intersects(SearchConfig::PART)) && full_matches.is_empty()
                            {
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
    s_config: SearchConfig,
    stop_idx: usize,
    flow_op_idx: usize,
    max_len: usize,
}

impl<'a> DecodeConfig<'a> {
    // Setup search parameters
    fn new(
        bin: &'a binary::Binary,
        seg: &'a binary::Segment,
        s_config: SearchConfig,
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
            s_config,
            stop_idx,
            flow_op_idx,
            max_len,
        }
    }
}

// Get offsets of all potential gadget tails within a segment.
// Maximizes accuracy by checking every possible instruction in parallel
fn get_gadget_tail_offsets(
    bin: &binary::Binary,
    seg: &binary::Segment,
    s_config: SearchConfig,
) -> Vec<usize> {
    (1..seg.bytes.len())
        .into_par_iter()
        .filter(|offset| {
            let offset = *offset;
            let mut decoder = iced_x86::Decoder::new(
                bin.bits(),
                &seg.bytes[(offset)..],
                iced_x86::DecoderOptions::NONE,
            );
            decoder.set_ip(seg.addr + (offset as u64));
            let instr = decoder.decode();

            // ROP tail
            (s_config.intersects(SearchConfig::ROP)
                && semantics::is_ret(&instr)
                && !semantics::is_ret_imm16(&instr))

                // ROP tail changing stack pointer (typically not desirable)
                || (s_config.intersects(SearchConfig::IMM16)
                    && semantics::is_ret_imm16(&instr))

                // JOP tail
                || (s_config.intersects(SearchConfig::JOP)
                    && semantics::is_jop_gadget_tail(&instr))


                // SYS tail
                || (s_config.intersects(SearchConfig::SYS)
                    && semantics::is_sys_gadget_tail(&instr))
        })
        .collect()
}

/// Iterative search backwards from instance of gadget tail instruction
fn iterative_decode(d_config: &DecodeConfig) -> Vec<(Vec<iced_x86::Instruction>, u64)> {
    let mut instr_sequences = Vec::new();

    for offset in (d_config.stop_idx..=d_config.flow_op_idx).rev() {
        let mut instrs = Vec::new();
        let buf_start_addr = d_config.seg.addr + offset as u64;
        let tail_addr = d_config.seg.addr + d_config.flow_op_idx as u64;

        let mut decoder = iced_x86::Decoder::new(
            d_config.bin.bits(),
            &d_config.seg.bytes[offset..],
            iced_x86::DecoderOptions::NONE,
        );
        decoder.set_ip(buf_start_addr);

        for i in &mut decoder {
            // Early stop if invalid encoding
            if i.code() == iced_x86::Code::INVALID {
                break;
            }

            // Early decode stop if control flow doesn't reach gadget tail
            let pc = i.ip();
            if (pc > tail_addr)
                || ((pc != tail_addr) && semantics::is_gadget_tail(&i))
                || (semantics::is_direct_call(&i)
                    && !d_config.s_config.intersects(SearchConfig::CALL))
                || (semantics::is_uncond_fixed_jmp(&i))
                || (semantics::is_int(&i))
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
            // Note: 1 instr gadget (e.g. "ret;") for 16 byte re-alignment of stack pointer (avoid movaps segfault)
            if (semantics::is_ret(&i))

                // JOP
                || (semantics::is_jop_gadget_tail(&i))

                // SYS
                || (semantics::is_syscall(&i)
                    || (semantics::is_legacy_linux_syscall(&i) && (d_config.bin.format() == binary::Format::ELF)))
            {
                debug_assert!(instrs[0].ip() == buf_start_addr);
                instr_sequences.push((instrs, buf_start_addr));
            }
        }
    }

    instr_sequences
}

/// Search a binary for gadgets
fn find_gadgets_single_bin(
    bin: &binary::Binary,
    max_len: usize,
    s_config: SearchConfig,
) -> HashSet<gadget::Gadget> {
    let mut gadget_collector: HashMap<Vec<iced_x86::Instruction>, BTreeSet<u64>> =
        HashMap::default();

    for seg in bin.segments() {
        // Search backward for all potential tails (possible duplicates)
        let parallel_results: Vec<(Vec<iced_x86::Instruction>, u64)> =
            get_gadget_tail_offsets(bin, seg, s_config)
                .par_iter()
                .map(|&offset| DecodeConfig::new(bin, seg, s_config, offset, max_len))
                .flat_map(|d_config| iterative_decode(&d_config))
                .collect();

        // Running consolidation of parallel results (de-dup instr sequences, aggregate occurrence addrs)
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
