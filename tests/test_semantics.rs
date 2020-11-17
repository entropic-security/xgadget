use std::collections::{BTreeSet, HashSet};

mod common;

#[test]
fn test_rop_semantics() {
    // ROP
    let ret: [u8; 1] = [0xc3];
    let ret_far: [u8; 1] = [0xcb];
    let ret_imm: [u8; 3] = [0xc2, 0xaa, 0xbb];
    let ret_far_imm: [u8; 3] = [0xca, 0xaa, 0xbb];

    let instr = common::decode_single_x64_instr(0, &ret);
    assert!(!xgadget::is_ret_imm16(&instr));
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &ret_far);
    assert!(!xgadget::is_ret_imm16(&instr));
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &ret_imm);
    assert!(xgadget::is_ret_imm16(&instr));
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &ret_far_imm);
    assert!(xgadget::is_ret_imm16(&instr));
    assert!(xgadget::is_ret(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
}

#[test]
fn test_jop_semantics() {
    // JOP
    let jmp_rax: [u8; 2] = [0xff, 0xe0];
    let jmp_rax_deref: [u8; 2] = [0xff, 0x20];
    let jmp_rax_deref_offset: [u8; 3] = [0xff, 0x60, 0x10];
    let jmp_fixed_deref: [u8; 7] = [0xff, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00];
    let call_rax: [u8; 2] = [0xff, 0xd0];
    let call_rax_deref: [u8; 2] = [0xff, 0x10];
    let call_rax_deref_offset: [u8; 3] = [0xff, 0x50, 0x10];
    let call_fixed_deref: [u8; 7] = [0xff, 0x14, 0x25, 0x10, 0x00, 0x00, 0x00];

    let instr = common::decode_single_x64_instr(0, &jmp_rax);
    assert!(xgadget::is_reg_indirect_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &jmp_rax_deref);
    assert!(xgadget::is_reg_indirect_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &jmp_rax_deref_offset);
    assert!(xgadget::is_reg_indirect_jmp(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    // Negative test
    let instr = common::decode_single_x64_instr(0, &jmp_fixed_deref);
    assert!(!xgadget::is_reg_indirect_jmp(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_jop_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &call_rax);
    assert!(xgadget::is_reg_indirect_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &call_rax_deref);
    assert!(xgadget::is_reg_indirect_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &call_rax_deref_offset);
    assert!(xgadget::is_reg_indirect_call(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_jop_gadget_tail(&instr));

    // Negative test
    let instr = common::decode_single_x64_instr(0, &call_fixed_deref);
    assert!(!xgadget::is_reg_indirect_call(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_jop_gadget_tail(&instr));
}

#[test]
fn test_sys_semantics() {
    // SYSCALL
    let syscall: [u8; 2] = [0x0f, 0x05];
    let sysenter: [u8; 2] = [0x0f, 0x34];
    let int_0x80: [u8; 2] = [0xcd, 0x80];
    let int_0x10: [u8; 2] = [0xcd, 0x10];

    let instr = common::decode_single_x64_instr(0, &syscall);
    assert!(xgadget::is_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &sysenter);
    assert!(xgadget::is_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    let instr = common::decode_single_x64_instr(0, &int_0x80);
    assert!(xgadget::is_legacy_linux_syscall(&instr));
    assert!(xgadget::is_gadget_tail(&instr));
    assert!(xgadget::is_sys_gadget_tail(&instr));

    // Negative test
    let instr = common::decode_single_x64_instr(0, &int_0x10);
    assert!(!xgadget::is_legacy_linux_syscall(&instr));
    assert!(!xgadget::is_gadget_tail(&instr));
    assert!(!xgadget::is_sys_gadget_tail(&instr));
}

#[test]
fn test_rw_semantics() {
    let add_rax_0x08: [u8; 4] = [0x48, 0x83, 0xc0, 0x08];
    let instr = common::decode_single_x64_instr(0, &add_rax_0x08);
    assert!(xgadget::semantics::is_reg_rw(
        &instr,
        &iced_x86::Register::RAX
    ));
}

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
    let g1 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_1.clone(),
    );
    let g2 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_deref_instr.clone()],
        addr_2.clone(),
    );
    assert!(common::hash(&g1) != common::hash(&g2));

    // Different instructions, same address - custom hash mismatch
    let g1 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_1.clone(),
    );
    let g2 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_deref_instr.clone()],
        addr_1.clone(),
    );
    assert!(common::hash(&g1) != common::hash(&g2));

    // Same instructions, same address - custom hash match
    let g1 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_1.clone(),
    );
    let g2 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_1.clone(),
    );
    assert!(common::hash(&g1) == common::hash(&g2));

    // Same instructions, different address - custom hash match
    let g1 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_1.clone(),
    );
    let g2 = xgadget::Gadget::new(
        vec![pop_r15_instr.clone(), jmp_rax_instr.clone()],
        addr_2.clone(),
    );
    assert!(common::hash(&g1) == common::hash(&g2));

    // Same instructions, different decode addresses - custom hash match
    // https://github.com/0xd4d/iced/blob/3ed6e0eadffb61daa50e041eb28633f17a9957e9/src/rust/iced-x86/src/instruction.rs#L7574
    let decode_addr_5 = 5;
    let decode_addr_10 = 10;
    let jmp_rax_instr_5 = common::decode_single_x64_instr(decode_addr_5, &jmp_rax);
    let jmp_rax_instr_10 = common::decode_single_x64_instr(decode_addr_10, &jmp_rax);

    let g1 = xgadget::Gadget::new(vec![jmp_rax_instr_5.clone()], addr_1.clone());
    let g2 = xgadget::Gadget::new(vec![jmp_rax_instr_10.clone()], addr_1.clone());
    let g3 = xgadget::Gadget::new(vec![jmp_rax_instr_10.clone()], addr_2);
    assert!(common::hash(&g1) == common::hash(&g2));
    assert!(common::hash(&g2) == common::hash(&g3));

    // Hash set intersection
    let g1 = xgadget::Gadget::new(vec![pop_r15_instr.clone(), jmp_rax_instr], addr_1.clone());
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
