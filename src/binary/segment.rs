use rayon::prelude::*;

/// A single executable segment
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Segment {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

impl Segment {
    /// Constructor
    pub fn new(addr: u64, bytes: Vec<u8>) -> Segment {
        Segment { addr, bytes }
    }

    /// Check if contains address
    pub fn contains(&self, addr: u64) -> bool {
        (self.addr <= addr) && (addr < (self.addr + self.bytes.len() as u64))
    }

    /// Get offsets of byte occurrences
    pub fn get_matching_offsets(&self, vals: &[u8]) -> Vec<usize> {
        self.bytes
            .par_iter()
            .enumerate()
            .filter(|&(_, b)| vals.contains(b))
            .map(|(i, _)| i)
            .collect()
    }
}
