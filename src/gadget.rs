use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use iced_x86;

use crate::binary;

// TODO: implement Ord for binary, use BTReeSet instead of Vector to maintain sorted order on insertion - will have nicer output at partial match at cost of speed (how much?)

/// Gadget instructions (data) coupled with occurrence addresses for full and partial matches (metadata).
/// Gadgets sortable by lowest occurrence address.
/// Hash and equality consider only gadget instructions, not occurrence addresses (fast de-duplication via sets).
#[derive(Clone, Debug)]
pub struct Gadget<'a> {
    pub instrs: Vec<iced_x86::Instruction>,
    pub full_matches: BTreeSet<u64>,
    pub partial_matches: BTreeMap<u64, Vec<&'a binary::Binary>>,
}

// TODO: other/getter/setter APIs and private fields?
impl<'a> Gadget<'a> {
    /// Assumes instructions are correctly sorted, address guaranteed to be sorted
    pub fn new(instrs: Vec<iced_x86::Instruction>, full_matches: BTreeSet<u64>) -> Gadget<'a> {
        Gadget {
            instrs,
            full_matches,
            partial_matches: BTreeMap::new(),
        }
    }

    /// Get tail
    pub fn last_instr(&self) -> Option<&iced_x86::Instruction> {
        self.instrs.iter().next_back()
    }

    /// Get first full match
    pub fn first_full_match(&self) -> Option<u64> {
        match self.full_matches.iter().next() {
            Some(addr) => Some(*addr),
            None => None,
        }
    }

    // TODO: use this API
    /// Add a new partial match address/binary tuple
    pub fn add_partial_match(&mut self, addr: u64, bin: &'a binary::Binary) {
        match self.partial_matches.get_mut(&addr) {
            Some(bins) => bins.push(bin),
            None => {
                // TODO: Use unwrap_none() once on stable
                match self.partial_matches.insert(addr, vec![bin]) {
                    Some(_) => return,
                    None => return,
                }
            }
        };
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

impl Hash for Gadget<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.instrs.hash(state);
    }
}
