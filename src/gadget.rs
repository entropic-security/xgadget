use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use crate::binary;

/// Gadget instructions (data) coupled with occurrence addresses for full and partial matches (metadata).
/// Gadgets sortable by lowest occurrence address.
/// Hash and equality consider only gadget instructions, not occurrence addresses (fast de-duplication via sets).
#[derive(Clone, Debug)]
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

    /// Get first full match
    pub fn first_full_match(&self) -> Option<u64> {
        match self.full_matches.iter().next() {
            Some(addr) => Some(*addr),
            None => None,
        }
    }

    // TODO: other APIs and private fields?

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
