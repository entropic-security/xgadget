use std::collections::BTreeSet;

use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::binary;
use crate::error::Error;
use crate::fess::FESSColumn;
use crate::gadget;
use crate::semantics;

/// Max instruction size in bytes
pub const X86_MAX_INSTR_BYTE_CNT: usize = 15;

// Search Flags --------------------------------------------------------------------------------------------------------

bitflags! {
    /// Bitflag that controls search parameters
    #[derive(Debug, Copy, Clone)]
    pub struct SearchConfig: u32 {
        /// Include ROP gadgets in search
        const ROP   = 0b0000_0001;
        /// Include JOP gadgets in search
        const JOP   = 0b0000_0010;
        /// Include SYSCALL gadgets in search
        const SYS   = 0b0000_0100;
        /// Include partial (same gadget, different address) cross-variant matches
        const PART  = 0b0000_1000;
        /// Include ROP gadgets with '{ret, ret far} imm16' (e.g. add to stack ptr) tails
        const IMM16 = 0b0001_0000;
        /// Include JOP gadgets containing a non-tail call
        const CALL  = 0b0010_0000;
    }
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self::ROP | Self::JOP | Self::SYS
    }
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Search 1+ binaries for ROP gadgets (common gadgets if > 1)
pub fn find_gadgets(
    bins: &[binary::Binary],
    max_len: usize,
    s_config: SearchConfig,
) -> Result<Vec<gadget::Gadget>, Error> {
    find_gadgets_multi_bin(bins, max_len, s_config, None)
}

// Crate-internal API --------------------------------------------------------------------------------------------------

/// Search 1+ binaries for ROP gadgets (common gadgets if > 1)
/// Optionally collect FESS data for table
pub(crate) fn find_gadgets_multi_bin<'a>(
    bins: &'a [binary::Binary],
    max_len: usize,
    s_config: SearchConfig,
    fess_tbl: Option<&mut Vec<FESSColumn>>,
) -> Result<Vec<gadget::Gadget<'a>>, Error> {
    let bin_cnt = bins.len();

    // Process binaries in parallel
    let parallel_results: Vec<(&binary::Binary, HashSet<gadget::Gadget>)> = bins
        .par_iter()
        .map(|bin| {
            (
                bin,
                find_gadgets_single_bin(bin, max_len, bin_cnt, s_config),
            )
        })
        .collect();

    // Filter to cross-variant gadgets
    match parallel_results.split_first() {
        Some((first_result, remaining_results)) => {
            let (first_bin, first_set) = first_result;
            let mut common_gadgets = first_set.clone();
            let base_count = FESSColumn::get_totals(&common_gadgets);

            // Compute 1st FESS table column
            if let Some(&mut ref mut fess) = fess_tbl {
                fess.push(FESSColumn::from_gadget_list(0, None, first_bin, first_set));
            }

            for (idx, (next_bin, next_set)) in remaining_results.iter().enumerate() {
                // Filter common gadgets (set intersection)
                common_gadgets.retain(|g| next_set.contains(g));

                // Update full and partial matches
                common_gadgets = common_gadgets
                    .into_iter()
                    .filter_map(|common_g| {
                        match next_set.get(&common_g) {
                            Some(next_set_g) => {
                                // Full matches
                                let full_matches: BTreeSet<_> = common_g
                                    .full_matches
                                    .intersection(&next_set_g.full_matches)
                                    .copied()
                                    .collect();

                                // Short-circuit if no full matches and partial collector if not requested
                                if (!s_config.intersects(SearchConfig::PART))
                                    && full_matches.is_empty()
                                {
                                    return None;
                                }

                                // Cross-variant gadget!
                                let mut updated_g = gadget::Gadget::new_multi_bin(
                                    common_g.instrs,
                                    full_matches,
                                    bin_cnt,
                                );

                                // Partial matches (optional)
                                if s_config.intersects(SearchConfig::PART) {
                                    for addr in &common_g.full_matches {
                                        updated_g.partial_matches.insert(*addr, vec![first_bin]);
                                    }

                                    for addr in &next_set_g.full_matches {
                                        match updated_g.partial_matches.get_mut(addr) {
                                            Some(bin_ref_vec) => bin_ref_vec.push(*next_bin),
                                            None => {
                                                updated_g
                                                    .partial_matches
                                                    .insert(*addr, vec![next_bin]);
                                            }
                                        }
                                    }
                                }

                                Some(updated_g)
                            }
                            None => unreachable!(),
                        }
                    })
                    .collect();

                // Update FESS table
                if let Some(&mut ref mut fess) = fess_tbl {
                    fess.push(FESSColumn::from_gadget_list(
                        idx + 1,
                        Some(base_count),
                        next_bin,
                        &common_gadgets,
                    ));
                }
            }

            Ok(common_gadgets.into_iter().collect())
        }
        _ => Err(Error::NoBinaries),
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
        let ret_prefix_size = max_len * X86_MAX_INSTR_BYTE_CNT;
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

            // TODO: some of these semantics funcs sould be replace with instr flow control

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
            if semantics::is_gadget_tail(i) {
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
    bin_cnt: usize,
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
        .map(|(instrs, addrs)| gadget::Gadget::new_multi_bin(instrs, addrs, bin_cnt))
        .collect()
}
