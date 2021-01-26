mod common;

#[test]
fn test_x64_ret_after_jne() {
    let bin_ret_post_jmp = common::get_raw_bin("bin_ret_post_jmp", &common::RET_AFTER_JNE_X64);
    let bins = vec![bin_ret_post_jmp];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    common::print_gadget_strs(&gadget_strs);

    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop r12; pop r13; pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop r13; pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop rbp; pop r12; pop r13; pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop rbp; pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop rdi; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop rsi; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "pop rsp; pop r13; pop r14; pop r15; ret;"
    ));
}

#[test]
fn test_x64_adjacent_ret() {
    let bin_ret = common::get_raw_bin("bin_ret", &common::ADJACENT_RET_X64);
    let bins = vec![bin_ret];
    let gadgets = xgadget::find_gadgets(
        &bins,
        common::MAX_LEN,
        xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::IMM16,
    )
    .unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    common::print_gadget_strs(&gadget_strs);

    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x5dde1; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x5ddcb; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea eax, [rip+0x5ddcb]; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea eax, [rip+0x5dde1]; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rax, [rip+0x5ddcb]; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rax, [rip+0x5dde1]; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x8d48c300; add eax, 0x5ddcb; ret 0x1337;"
    ));
}

#[test]
fn test_x64_adjacent_call() {
    let bin_call = common::get_raw_bin("bin_call", &common::ADJACENT_CALL_X64);
    let bins = vec![bin_call];
    let gadgets = xgadget::find_gadgets(
        &bins,
        common::MAX_LEN,
        xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::IMM16,
    )
    .unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    common::print_gadget_strs(&gadget_strs);

    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add bh, bh; ror dword ptr [rax-0x73], cl; sbb eax, 0x5ddcb; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x48d3ff00; lea ebx, [rip+0x5ddcb]; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st, qword ptr [rip+0x48d3ff00]; lea ebx, [rip+0x5ddcb]; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ebx, [rip+0x5ddcb]; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ebx, [rip+0x5dde1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rbx, [rip+0x5ddcb]; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rbx, [rip+0x5dde1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope 0xffffffffffffffe2; add eax, 0x48d3ff00; lea ebx, [rip+0x5ddcb]; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "ror dword ptr [rax-0x73], cl; sbb eax, 0x5ddcb; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "sbb eax, 0x5ddcb; call qword ptr [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "sbb eax, 0x5dde1; call rbx;"
    ));
}

#[test]
fn test_x64_adjacent_jmp() {
    let bin_jmp = common::get_raw_bin("bin_jmp", &common::ADJACENT_JMP_X64);
    let bins = vec![bin_jmp];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    common::print_gadget_strs(&gadget_strs);

    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st, qword ptr [rip+0x48e1ff00]; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope 0xffffffffffffffe2; add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5ddcb; jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5dde1; jmp rcx;"
    ));
}

#[test]
fn test_jmp_rip() {
    let bin_misc_2 = common::get_raw_bin("misc_2", &common::MISC_2);
    let bins = vec![bin_misc_2];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    assert!(gadgets.len() == 0);
}
