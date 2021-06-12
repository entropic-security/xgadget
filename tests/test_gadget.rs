use std::collections::{BTreeSet, HashSet};

mod common;

#[test]
fn test_gadget_hasher() {
    let pop_r15: [u8; 2] = [0x41, 0x5f];
    let jmp_rax: [u8; 2] = [0xff, 0xe0];
    let jmp_rax_deref: [u8; 2] = [0xff, 0x20];

    let jmp_rax_instr = common::decode_single_x64_instr(0, &jmp_rax);
    let jmp_rax_deref_instr = common::decode_single_x64_instr(0, &jmp_rax_deref);
    let pop_r15_instr = common::decode_single_x64_instr(0, &pop_r15);

    let mut addr_1 = BTreeSet::new();
    addr_1.insert(0);

    let mut addr_2 = BTreeSet::new();
    addr_2.insert(1);

    // Different instructions, different address - custom hash mismatch
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_deref_instr], addr_2.clone());
    assert!(common::hash(&g1) != common::hash(&g2));

    // Different instructions, same address - custom hash mismatch
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_deref_instr], addr_1.clone());
    assert!(common::hash(&g1) != common::hash(&g2));

    // Same instructions, same address - custom hash match
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    assert!(common::hash(&g1) == common::hash(&g2));

    // Same instructions, different address - custom hash match
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_2.clone());
    assert!(common::hash(&g1) == common::hash(&g2));

    // Same instructions, different decode addresses - custom hash match
    // https://github.com/0xd4d/iced/blob/3ed6e0eadffb61daa50e041eb28633f17a9957e9/src/rust/iced-x86/src/instruction.rs#L7574
    let decode_addr_5 = 5;
    let decode_addr_10 = 10;
    let jmp_rax_instr_5 = common::decode_single_x64_instr(decode_addr_5, &jmp_rax);
    let jmp_rax_instr_10 = common::decode_single_x64_instr(decode_addr_10, &jmp_rax);

    let g1 = xgadget::Gadget::new(vec![jmp_rax_instr_5], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![jmp_rax_instr_10], addr_1.clone());
    let g3 = xgadget::Gadget::new(vec![jmp_rax_instr_10], addr_2);
    assert!(common::hash(&g1) == common::hash(&g2));
    assert!(common::hash(&g2) == common::hash(&g3));

    // Hash set intersection
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_deref_instr], addr_1);

    let mut g_set_1: HashSet<_> = HashSet::default();
    g_set_1.insert(g1.clone());
    g_set_1.insert(g2.clone());

    let mut g_set_2 = HashSet::default();
    g_set_2.insert(g1.clone());

    let g_set_intersect: HashSet<_> = g_set_1.intersection(&g_set_2).collect();
    assert!(g_set_intersect.contains(&g1));
    assert!(!g_set_intersect.contains(&g2));
}
