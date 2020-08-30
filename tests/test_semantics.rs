use std::collections::BTreeSet;

use rustc_hash::FxHashSet;


mod test_utils;

#[test]
fn test_rop_semantics() {

    let decoder = zydis::Decoder::new(zydis::enums::MachineMode::LONG_64, zydis::enums::AddressWidth::_64).unwrap();

    // ROP
    let ret: [u8; 1] = [0xc3];
    let ret_far: [u8; 1] = [0xcb];
    let ret_imm: [u8; 3] = [0xc2, 0xaa, 0xbb];
    let ret_far_imm: [u8; 3] = [0xca, 0xaa, 0xbb];

    let instr = decoder.decode(&ret).unwrap().unwrap();
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = decoder.decode(&ret_far).unwrap().unwrap();
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = decoder.decode(&ret_imm).unwrap().unwrap();
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = decoder.decode(&ret_far_imm).unwrap().unwrap();
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
}

#[test]
fn test_jop_semantics() {

    let decoder = zydis::Decoder::new(zydis::enums::MachineMode::LONG_64, zydis::enums::AddressWidth::_64).unwrap();

    // JOP
    let jmp_rax: [u8; 2] = [0xff, 0xe0];
    let jmp_rax_deref: [u8; 2] = [0xff, 0x20];
    let jmp_rax_deref_offset: [u8; 3] = [0xff, 0x60, 0x10];
    let jmp_fixed_deref: [u8; 7] = [0xff, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00];
    let call_rax: [u8; 2] = [0xff, 0xd0];
    let call_rax_deref: [u8; 2] = [0xff, 0x10];
    let call_rax_deref_offset: [u8; 3] = [0xff, 0x50, 0x10];
    let call_fixed_deref: [u8; 7] = [0xff, 0x14, 0x25, 0x10, 0x00, 0x00, 0x00];

    let instr = decoder.decode(&jmp_rax).unwrap().unwrap();
    assert!(xgadget::is_single_reg_read(&instr));
    assert!(xgadget::is_reg_set_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = decoder.decode(&jmp_rax_deref).unwrap().unwrap();
    assert!(xgadget::is_single_reg_deref_read(&instr));
    assert!(xgadget::is_mem_ptr_set_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = decoder.decode(&jmp_rax_deref_offset).unwrap().unwrap();
    assert!(xgadget::is_single_reg_deref_read(&instr));
    assert!(xgadget::is_mem_ptr_set_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    // Negative test
    let instr = decoder.decode(&jmp_fixed_deref).unwrap().unwrap();
    assert!(!xgadget::is_single_reg_deref_read(&instr));
    assert!(!xgadget::is_mem_ptr_set_jmp(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_jop_gadget_tail(&instr));

    let instr = decoder.decode(&call_rax).unwrap().unwrap();
    assert!(xgadget::is_single_reg_read(&instr));
    assert!(xgadget::is_reg_set_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = decoder.decode(&call_rax_deref).unwrap().unwrap();
    assert!(xgadget::is_single_reg_deref_read(&instr));
    assert!(xgadget::is_mem_ptr_set_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = decoder.decode(&call_rax_deref_offset).unwrap().unwrap();
    assert!(xgadget::is_single_reg_deref_read(&instr));
    assert!(xgadget::is_mem_ptr_set_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    // Negative test
    let instr = decoder.decode(&call_fixed_deref).unwrap().unwrap();
    assert!(!xgadget::is_single_reg_deref_read(&instr));
    assert!(!xgadget::is_mem_ptr_set_call(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_jop_gadget_tail(&instr));
}

#[test]
fn test_sys_semantics() {
    let decoder = zydis::Decoder::new(zydis::enums::MachineMode::LONG_64, zydis::enums::AddressWidth::_64).unwrap();

    // SYSCALL
    let syscall: [u8; 2] = [0x0f, 0x05];
    let sysenter: [u8; 2] = [0x0f, 0x34];
    let int_0x80: [u8; 2] = [0xcd, 0x80];
    let int_0x10: [u8; 2] = [0xcd, 0x10];

    let instr = decoder.decode(&syscall).unwrap().unwrap();
    assert!(xgadget::is_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    let instr = decoder.decode(&sysenter).unwrap().unwrap();
    assert!(xgadget::is_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    let instr = decoder.decode(&int_0x80).unwrap().unwrap();
    assert!(xgadget::is_legacy_linux_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    // Negative test
    let instr = decoder.decode(&int_0x10).unwrap().unwrap();
    assert!(!xgadget::is_legacy_linux_syscall(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_sys_gadget_tail(&instr));
}

#[test]
fn test_gadget_hasher() {
    let pop_r15: [u8; 2] = [0x41, 0x5f];
    let jmp_rax: [u8; 2] = [0xff, 0xe0];
    let jmp_rax_deref: [u8; 2] = [0xff, 0x20];

    let decoder = zydis::Decoder::new(zydis::enums::MachineMode::LONG_64, zydis::enums::AddressWidth::_64).unwrap();
    let jmp_rax_instr = decoder.decode(&jmp_rax).unwrap().unwrap();
    let jmp_rax_deref_instr = decoder.decode(&jmp_rax_deref).unwrap().unwrap();
    let pop_r15_instr = decoder.decode(&pop_r15).unwrap().unwrap();

    let mut addr_1 = BTreeSet::new();
    addr_1.insert(0);

    let mut addr_2 = BTreeSet::new();
    addr_2.insert(1);

    // Different instructions, different address - custom hash mismatch
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_deref_instr.clone()], addr_2.clone());
    assert!(test_utils::hash(&g1) != test_utils::hash(&g2));

    // Different instructions, same address - custom hash mismatch
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_deref_instr.clone()], addr_1.clone());
    assert!(test_utils::hash(&g1) != test_utils::hash(&g2));

    // Same instructions, same address - custom hash match
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_1.clone());
    assert!(test_utils::hash(&g1) == test_utils::hash(&g2));

    // Same instructions, different address - custom hash match
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr.clone()], addr_2);
    assert!(test_utils::hash(&g1) == test_utils::hash(&g2));

    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![pop_r15_instr, jmp_rax_deref_instr], addr_1);

    let mut g_set_1 = FxHashSet::default();
    g_set_1.insert(g1.clone());
    g_set_1.insert(g2.clone());

    let mut g_set_2 = FxHashSet::default();
    g_set_2.insert(g1.clone());

    let g_set_intersect: FxHashSet<_>= g_set_1.intersection(&g_set_2).collect();
    assert!(g_set_intersect.contains(&g1));
    assert!(!g_set_intersect.contains(&g2));
}