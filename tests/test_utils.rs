use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Test Utils ----------------------------------------------------------------------------------------------------------

#[allow(dead_code)]
pub fn get_raw_bin(name: &str, bytes: &[u8]) -> xgadget::Binary {
    let mut bin = xgadget::Binary::from_bytes(&name, &bytes).unwrap();
    assert_eq!(bin.format, xgadget::Format::Raw);
    assert_eq!(bin.arch, xgadget::Arch::Unknown);
    bin.arch = xgadget::Arch::X64;

    bin
}

#[allow(dead_code)]
pub fn get_gadget_strs(gadgets: &Vec<xgadget::Gadget>, att_syntax: bool) -> Vec<String> {
    let mut strs = Vec::new();
    for (mut instr, addrs) in xgadget::str_fmt_gadgets(&gadgets, att_syntax).unwrap() {
        instr.push(' ');
        strs.push(format!("{:-<150} {}", instr, addrs));
    }
    strs
}

#[allow(dead_code)]
pub fn print_gadget_strs(gadget_strs: &Vec<String>) {
    println!("Found {} gadgets\n", gadget_strs.len());
    for s in gadget_strs {
        println!("{}", s);
    }
}

#[allow(dead_code)]
pub fn gadget_strs_contains_sub_str(gadget_strs: &Vec<String>, substring: &str) -> bool {
    for gs in gadget_strs {
        if gs.contains(substring) {
            return true;
        }
    }
    false
}

#[allow(dead_code)]
pub fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}