use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::hash::{Hash, Hasher};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::binary;
use crate::semantics;

// Search Flags --------------------------------------------------------------------------------------------------------

bitflags! {
    /// Bitflags that control search parameters
    pub struct SearchConfig: u32 {
        const UNSET = 0b0000_0000;
        const ROP   = 0b0000_0001;
        const JOP   = 0b0000_0010;
        const SYS   = 0b0000_0100;
        const IMM16 = 0b0000_1000;
        const PART  = 0b0001_0000;
        const DEFAULT = Self::ROP.bits | Self::JOP.bits | Self::SYS.bits;
    }
}

// Opcodes -------------------------------------------------------------------------------------------------------------

/// Max instruction size in bytes
pub const MAX_INSTR_BYTE_CNT: usize = 15;

// https://c9x.me/x86/html/file_module_x86_id_147.html
/// call r/m16, call r/m32, jmp r/m16, jmp r/m32
pub const JMP_CALL_ABS: u8 = 0xff;

// https://c9x.me/x86/html/file_module_x86_id_313.html
/// sysenter first opcode (0x0f 0x34)
pub const SYSENTER: u8 = 0x0f;
/// int opcode (non-imm8)
pub const INT: u8 = 0xcd;

// https://c9x.me/x86/html/file_module_x86_id_280.html
/// ret
pub const RET_NEAR: u8 = 0xc3;
/// ret far
pub const RET_FAR: u8 = 0xcb;
/// ret imm16
pub const RET_NEAR_IMM: u8 = 0xc2;
/// ret far imm16
pub const RET_FAR_IMM: u8 = 0xca;

/// ret {far}
#[rustfmt::skip]
pub const CDECL_RET_OPCODES: &[u8] = &[
    RET_NEAR,
    RET_FAR,
];

/// ret {far} imm16
#[rustfmt::skip]
pub const IMM16_RET_OPCODES: &[u8] = &[
    RET_NEAR_IMM,
    RET_FAR_IMM,
];

/// call r/m16, call r/m32, jmp r/m16, jmp r/m32
#[rustfmt::skip]
pub const JOP_OPCODES: &[u8] = &[
    JMP_CALL_ABS,
];

/// sysenter, int imm8
#[rustfmt::skip]
pub const SYSCALL_OPCODES: &[u8] = &[
    SYSENTER,
    INT,
];

// Gadget --------------------------------------------------------------------------------------------------------------

/// Gadget instructions (data) coupled with occurrence addresses for full and partial matches (metadata).
/// Gadgets sortable by lowest occurrence address.
/// Hash and equality consider only gadget instructions, not occurrence addresses (fast de-duplication via sets).
#[derive(Clone)]
pub struct Gadget<'a> {
    pub instrs: Vec<zydis::DecodedInstruction>,
    pub full_matches: BTreeSet<u64>,
    pub partial_matches: BTreeMap<u64, Vec<&'a binary::Binary>>,
}

impl<'a> Gadget<'a> {
    /// Assumes instructions are correctly sorted, address guaranteed to be sorted
    pub fn new(instrs: Vec<zydis::DecodedInstruction>, full_matches: BTreeSet<u64>) -> Gadget<'a> {
        Gadget {
            instrs,
            full_matches,
            partial_matches: BTreeMap::new(),
        }
    }

    /// Get tail
    pub fn last_instr(&self) -> Option<&zydis::DecodedInstruction> {
        self.instrs.iter().next_back()
    }

    // Ord helper: Lowest gadget occurrence address, full matches preferred
    fn min_addr(&self) -> Option<&u64> {
        if let Some(min_full) = self.full_matches.iter().next() {
            Some(min_full)
        } else if let Some(min_part) = self.partial_matches.keys().next() {
            Some(min_part)
        } else {
            None
        }
    }
}

impl Eq for Gadget<'_> {}
impl PartialEq for Gadget<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.instrs == other.instrs
    }
}

impl Ord for Gadget<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        if let Some(self_min_addr) = self.min_addr() {
            // Both have a minimum address -> compare minimums
            if let Some(other_min_addr) = other.min_addr() {
                (*self_min_addr).cmp(other_min_addr)
            // Self addresses non-empty, other addresses empty -> other is less
            } else {
                Ordering::Greater
            }
        } else {
            // Self addresses empty, other addresses non-empty -> self is less
            if other.min_addr().is_some() {
                Ordering::Less
            // Self addresses empty, other addresses empty -> equal
            } else {
                Ordering::Equal
            }
        }
    }
}

impl PartialOrd for Gadget<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// SET DE-DUPLICATION PERFORMANCE (see [http://cglab.ca/~abeinges/blah/hash-rs/](http://cglab.ca/~abeinges/blah/hash-rs/)):
//
/// * SipHash 2-4 (default): Resistant to an advanced form of DDoS attack, but slow.
///     * Important for parsing untrusted inputs (e.g. network data), but not for our tool (it parses local binaries)
///     * We default to FxHash to run about 30% faster
///     * TODO (tnballo): HOWEVER an optional build config macro enables SipHash 2-4 (for parsing untrusted binaries, e.g. malware)
///     * That's paranoid, malware doesn't control hashing logic for our lib's decoding structs
///
/// * Fowler-Noll-Vo, aka FNV: fastest option, but only for small key sizes. Our key, Vec<zydis::DecodedInstruction>,
/// is large and scales proportionally with the flag `--max-len` (gadget instr count).
///     * Not a good choice.
///
/// * FxHash: fast, non-cryptographic hash used in Firefox and maintained by the Rust Core team. Our default for
/// approximately 30% speed gains via "drop-in" replacement.
///
impl Hash for Gadget<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.instrs.hash(state);
    }
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Return opcodes relevant to requested search
pub fn get_flow_opcodes(s_config: SearchConfig) -> Vec<u8> {
    let mut flow_op_codes = Vec::new();

    if s_config.intersects(SearchConfig::ROP) {
        flow_op_codes.extend_from_slice(&CDECL_RET_OPCODES);
    }

    if s_config.intersects(SearchConfig::IMM16) {
        flow_op_codes.extend_from_slice(&IMM16_RET_OPCODES);
    }

    if s_config.intersects(SearchConfig::JOP) {
        flow_op_codes.extend_from_slice(&JOP_OPCODES);
    }

    if s_config.intersects(SearchConfig::SYS) {
        flow_op_codes.extend_from_slice(&SYSCALL_OPCODES);
    }

    flow_op_codes
}

/// Search 1+ binaries for ROP gadgets (common gadgets if > 1)
pub fn find_gadgets<'a>(
    bins: &'a [binary::Binary],
    max_len: usize,
    s_config: SearchConfig,
) -> Result<Vec<Gadget<'a>>, Box<dyn Error>> {
    // Process binaries in parallel
    let decoders = get_all_decoders(&bins)?;
    let parallel_results: Vec<(&binary::Binary, FxHashSet<Gadget>)> = bins
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
                let mut temp_gadgets = FxHashSet::default();
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
                            let mut updated_g = Gadget::new(common_g.instrs, full_matches);

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

    // Early termination if no viable gadget tail, don't waste time on iterative decode backwards
    match d_config
        .decoder
        .decode(&d_config.seg.bytes[d_config.flow_op_idx..])
    {
        Err(_) => return instr_sequences,
        Ok(opt) => match opt {
            None => return instr_sequences,
            Some(i) => {
                if !semantics::is_gadget_tail(&i) {
                    return instr_sequences;
                }
            }
        },
    }

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
) -> FxHashSet<Gadget<'a>> {
    let mut gadget_collector: FxHashMap<Vec<zydis::DecodedInstruction>, BTreeSet<u64>> =
        FxHashMap::default();
    let flow_op_codes = get_flow_opcodes(config);

    for seg in &bin.segments {
        let flow_op_idxs = seg.get_matching_offsets(&flow_op_codes);

        // Parallel search. Only dissemble offsets from existing ret opcodes (e.g. not entire segments)
        let parallel_results: Vec<(Vec<zydis::DecodedInstruction>, u64)> = flow_op_idxs
            .par_iter()
            .filter(|&offset| *offset != 0)
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
        .map(|(instrs, addrs)| Gadget::new(instrs, addrs))
        .collect()
}
