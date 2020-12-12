mod common;

#[test]
fn test_x64_cross_variant_full_matches() {
    let bin_ret_jmp =
        common::get_raw_bin("bin_ret_jmp", &common::X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_ret_call = common::get_raw_bin(
        "bin_ret_call",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64,
    );
    let bins = vec![bin_ret_jmp, bin_ret_call];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    common::print_gadget_strs(&gadget_strs);

    // Common - in both common::ADJACENT_CALL_X64 and common::ADJACENT_JMP_X64
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

    // Negative tests for unique - common::ADJACENT_CALL_X64
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st0, qword ptr [rip+0x48e1ff00]; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope -0x21; add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5ddcb; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5dde1; jmp rcx;"
    ));

    // Negative tests for unique - common::ADJACENT_JMP_X64
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st0, qword ptr [rip+0x48e1ff00]; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5dde1]; jmp rcx;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope -0x21; add eax, 0x48e1ff00; lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5ddcb; jmp qword ptr [rcx];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5dde1; jmp rcx;"
    ));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_1() {
    let bin_ret_jmp =
        common::get_raw_bin("bin_ret_jmp", &common::X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_mix = common::get_raw_bin(
        "bin_mix",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64,
    );

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_jmp
    let bins = vec![bin_mix, bin_ret_jmp];

    // Full match against common::X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = common::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_jump (FULL) ", 175);
    common::print_gadget_strs(&gadget_strs_full_match);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "jmp qword ptr [rcx];"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop r14; pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop rsi; pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop rdi; ret;"
    ));

    // Partial match against common::X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = common::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_jump (PARTIAL) ", 175);
    common::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "jmp qword ptr [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rsi; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rdi; ret;"
    ));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_2() {
    let bin_ret_call = common::get_raw_bin(
        "bin_ret_call",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64,
    );
    let bin_mix = common::get_raw_bin(
        "bin_mix",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64,
    );

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_call
    let bins = vec![bin_mix, bin_ret_call];

    // Full match against common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = common::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call (FULL) ", 175);
    common::print_gadget_strs(&gadget_strs_full_match);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "lea rbx, [rip+0x5dde1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "call rbx;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop r14; pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop rsi; pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop r15; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "pop rdi; ret;"
    ));

    // Partial match against common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = common::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call (PARTIAL) ", 175);
    common::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "lea rbx, [rip+0x5dde1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_full_match,
        "call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rsi; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rdi; ret;"
    ));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_3() {
    let bin_ret_jmp =
        common::get_raw_bin("bin_ret_jmp", &common::X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_ret_call = common::get_raw_bin(
        "bin_ret_call",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64,
    );
    let bin_mix = common::get_raw_bin(
        "bin_mix",
        &common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64,
    );

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_call vs. ret_jmp
    let bins = vec![bin_mix, bin_ret_call, bin_ret_jmp];

    // Full match against common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = common::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call vs. ret_jmp (FULL) ", 175);
    common::print_gadget_strs(&gadget_strs_full_match);

    // Negative
    assert!(gadgets.is_empty());

    // Partial match against common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and common::X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = common::get_gadget_strs(&gadgets, false);
    println!(
        "\n{:#^1$}\n",
        " Mix vs. ret_call vs. ret_jmp (PARTIAL) ", 175
    );
    common::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r14; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rsi; pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop r15; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs_part_match,
        "pop rdi; ret;"
    ));
}
