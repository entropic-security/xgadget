use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::marker::Send;

use iced_x86::FormatterOutput;

use super::fmt;
use super::fmt::DisplayLen;
use crate::binary;

// TODO: implement Ord for binary, use BTReeSet instead of Vector to maintain sorted order on insertion
// will have nicer output at partial match at cost of speed (how much?)

// Gadget --------------------------------------------------------------------------------------------------------------

/// Gadget instructions (data) coupled with occurrence addresses for full and partial matches (metadata).
/// Gadgets sortable by lowest occurrence address.
/// Hash and equality consider only gadget instructions, not occurrence addresses (fast de-duplication via sets).
#[derive(Clone, Debug)]
pub struct Gadget<'a> {
    pub(crate) instrs: Vec<iced_x86::Instruction>,
    pub(crate) full_matches: BTreeSet<u64>,
    pub(crate) partial_matches: BTreeMap<u64, Vec<&'a binary::Binary>>,
}

impl<'a> Gadget<'a> {
    // Public API ------------------------------------------------------------------------------------------------------

    /// Assumes instructions are correctly sorted, address guaranteed to be sorted
    pub fn new(instrs: Vec<iced_x86::Instruction>, full_matches: BTreeSet<u64>) -> Self {
        Gadget {
            instrs,
            full_matches,
            partial_matches: BTreeMap::new(),
        }
    }

    /// Get a instructions
    pub fn instrs(&self) -> &[iced_x86::Instruction] {
        &self.instrs
    }

    /// Get tail
    pub fn last_instr(&self) -> Option<&iced_x86::Instruction> {
        self.instrs.iter().next_back()
    }

    /// Get a full matches
    pub fn full_matches(&self) -> &BTreeSet<u64> {
        &self.full_matches
    }

    /// Get partial matches
    pub fn partial_matches(&self) -> &BTreeMap<u64, Vec<&'a binary::Binary>> {
        &self.partial_matches
    }

    /// Get first full match
    pub fn first_full_match(&self) -> Option<u64> {
        match self.full_matches.iter().next() {
            Some(addr) => Some(*addr),
            None => None,
        }
    }

    /// String format gadget instructions
    pub fn fmt_instrs(&self, att_syntax: bool, color: bool) -> Box<dyn DisplayLen + Send> {
        match color {
            true => {
                let mut formatter = fmt::get_formatter(att_syntax);
                let mut output = fmt::GadgetFormatterOutput::new();
                for instr in &self.instrs {
                    formatter.format(&instr, &mut output);
                    output.write("; ", iced_x86::FormatterTextKind::Punctuation);
                }
                Box::new(output)
            }
            false => Box::new(fmt::DisplayString(self.write_instrs_internal(att_syntax))),
        }
    }

    /// String format first full match address, if any
    pub fn fmt_first_full_match_addr(&self, color: bool) -> Option<Box<dyn DisplayLen + Send>> {
        match &self.first_full_match() {
            Some(addr) => match color {
                true => {
                    let mut output = fmt::GadgetFormatterOutput::new();
                    output.write(
                        &format!("{:#016x}", addr),
                        iced_x86::FormatterTextKind::LabelAddress,
                    );
                    Some(Box::new(output))
                }
                false => {
                    let mut output = String::new();
                    output.write(
                        &format!("{:#016x}", addr),
                        iced_x86::FormatterTextKind::LabelAddress,
                    );
                    Some(Box::new(fmt::DisplayString(output)))
                }
            },
            None => None,
        }
    }

    /// String format partial match addresses, if any
    pub fn fmt_partial_match_addrs(&self, color: bool) -> Option<Box<dyn DisplayLen + Send>> {
        match color {
            true => {
                let mut output = fmt::GadgetFormatterOutput::new();
                Self::fmt_partial_matches_internal(&mut output, &mut self.partial_matches.clone());
                match output.is_empty() {
                    true => None,
                    false => Some(Box::new(output)),
                }
            }
            false => {
                let mut output = String::new();
                Self::fmt_partial_matches_internal(&mut output, &mut self.partial_matches.clone());
                match output.is_empty() {
                    true => None,
                    false => Some(Box::new(fmt::DisplayString(output))),
                }
            }
        }
    }

    /// String format match addresses, prioritizing full matches over partial, if any
    pub fn fmt_best_match_addrs(&self, color: bool) -> Option<Box<dyn DisplayLen + Send>> {
        match self.first_full_match() {
            Some(_) => self.fmt_first_full_match_addr(color),
            None => match self.partial_matches.is_empty() {
                false => self.fmt_partial_match_addrs(color),
                true => None,
            },
        }
    }

    // Returns instruction string for regex filtering
    pub fn fmt_for_filter(&self, att_syntax: bool) -> String {
        self.write_instrs_internal(att_syntax)
    }

    /// Format a single gadget, return an `(instrs, addr(s))` tuple
    pub fn fmt(
        &self,
        att_syntax: bool,
        color: bool,
    ) -> (Box<dyn DisplayLen + Send>, Box<dyn DisplayLen + Send>) {
        let output_instrs = self.fmt_instrs(att_syntax, color);
        let output_addrs = self
            .fmt_best_match_addrs(color)
            .unwrap_or(Box::new(fmt::DisplayString(String::new())));

        (output_instrs, output_addrs)
    }

    // Private API -----------------------------------------------------------------------------------------------------

    // Ord helper: Lowest gadget occurrence address, full matches preferred
    #[inline]
    fn min_addr(&self) -> Option<&u64> {
        if let Some(min_full) = self.full_matches.iter().next() {
            Some(min_full)
        } else if let Some(min_part) = self.partial_matches.keys().next() {
            Some(min_part)
        } else {
            None
        }
    }

    #[inline]
    fn write_instrs_internal(&self, att_syntax: bool) -> String {
        let mut formatter = fmt::get_formatter(att_syntax);
        let mut output = String::new();
        for instr in &self.instrs {
            formatter.format(&instr, &mut output);
            output.write("; ", iced_x86::FormatterTextKind::Punctuation);
        }
        output
    }

    // Partial match format helper, shrinks a working set
    #[inline]
    fn fmt_partial_matches_internal(
        match_str: &mut impl iced_x86::FormatterOutput,
        partial_matches: &mut BTreeMap<u64, Vec<&binary::Binary>>,
    ) {
        let mut add_sep = false;

        // Find largest subset of binaries with match for a given address (best partial match)
        while let Some((bpm_addr, bpm_bins)) = partial_matches
            .iter()
            .max_by(|a, b| a.1.len().cmp(&b.1.len()))
        {
            // This pair of clones ends borrow of partial_matches and lets us remove from it later
            let bpm_addr = *bpm_addr;
            let mut bpm_bins = bpm_bins.clone();
            bpm_bins.sort_by(|b1, b2| b1.name().to_lowercase().cmp(&b2.name().to_lowercase()));

            // Commit best partial match
            match bpm_bins.split_last() {
                Some((last_bin, prior_bpm_bins)) => {
                    if add_sep {
                        match_str.write(", ", iced_x86::FormatterTextKind::Punctuation);
                    } else {
                        add_sep = true;
                    }

                    for pb in prior_bpm_bins {
                        Self::write_bin_name(&pb.name(), match_str);
                    }

                    Self::write_bin_name(&last_bin.name(), match_str);
                    match_str.write(
                        &format!("{:#016x}", bpm_addr),
                        iced_x86::FormatterTextKind::LabelAddress,
                    );
                }
                None => break,
            }

            // Remove committed binaries from the remainder of partial matches
            partial_matches.remove(&bpm_addr);
            partial_matches
                .iter_mut()
                .for_each(|(_, bins)| bins.retain(|&b| !bpm_bins.contains(&b)));
        }
    }

    #[inline]
    fn write_bin_name(name: &str, output: &mut impl iced_x86::FormatterOutput) {
        output.write("'", iced_x86::FormatterTextKind::Punctuation);
        output.write(name, iced_x86::FormatterTextKind::Text);
        output.write("': ", iced_x86::FormatterTextKind::Punctuation);
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

impl Hash for Gadget<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.instrs.hash(state);
    }
}
