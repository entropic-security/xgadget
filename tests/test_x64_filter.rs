mod common;

#[test]
fn test_x64_filter_stack_pivot() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let stack_pivot_gadgets = xgadget::filter_stack_pivot(&gadgets);
    let stack_pivot_gadget_strs = common::get_gadget_strs(&stack_pivot_gadgets, false);
    common::print_gadget_strs(&stack_pivot_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "pop rsp; ret;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "add rax, 0x08; jmp rax;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "mov rax, 0x1337; jmp [rax];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &stack_pivot_gadget_strs,
        "pop rax; jmp rax;"
    ));
}

#[test]
fn test_x64_filter_dispatcher() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let dispatcher_gadgets = xgadget::filter_dispatcher(&gadgets);
    let dispatcher_gadget_strs = common::get_gadget_strs(&dispatcher_gadgets, false);
    common::print_gadget_strs(&dispatcher_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "add rax, 0x8; jmp rax;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "pop rsp; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "mov rax, 0x1337; jmp [rax];"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &dispatcher_gadget_strs,
        "pop rax; jmp rax;"
    ));
}

#[test]
fn test_x64_filter_reg_pop_only() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let loader_gadgets = xgadget::filter_reg_pop_only(&gadgets);
    let loader_gadget_strs = common::get_gadget_strs(&loader_gadgets, false);
    common::print_gadget_strs(&loader_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "pop rsp; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "pop rax; jmp rax;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "pop r8; ret;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "add rax, 0x08; jmp rax;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &loader_gadget_strs,
        "mov rax, 0x1337; jmp [rax];"
    ));
}

#[test]
fn test_x64_filter_bad_bytes() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = common::get_gadget_strs(&gadgets, false);
    let good_bytes_gadgets =
        xgadget::filter_bad_addr_bytes(&gadgets, &[0x10, 0x14, 0x15, 0xc, 0xd]);
    let good_bytes_gadget_strs = common::get_gadget_strs(&good_bytes_gadgets, false);
    common::print_gadget_strs(&good_bytes_gadget_strs);

    // Positive
    assert!(!common::gadget_strs_contains_sub_str(
        &good_bytes_gadget_strs,
        "jmp rax;"
    ));

    // Negative
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp rax;"
    ));
}

#[test]
fn test_x64_filter_set_params() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let param_ctrl_gadgets =
        xgadget::filter_set_params(&gadgets, xgadget::binary::X64_ELF_PARAM_REGS);
    let param_ctrl_gadget_strs = common::get_gadget_strs(&param_ctrl_gadgets, false);
    common::print_gadget_strs(&param_ctrl_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "pop r8; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "mov rcx, rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "push rax; ret;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "jmp rax;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "pop rsp; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &param_ctrl_gadget_strs,
        "pop rax; jmp rax;"
    ));
}

#[test]
fn test_x64_filter_no_deref_1() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let no_deref_gadgets = xgadget::filter_no_deref(&gadgets, None);
    let no_deref_gadget_strs = common::get_gadget_strs(&no_deref_gadgets, false);
    common::print_gadget_strs(&no_deref_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "pop r8; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "mov rcx, rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "push rax; ret;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "mov rax, 0x1337; jmp qword ptr [rax];"
    ));
}

#[test]
fn test_x64_filter_no_deref_2() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let no_deref_gadgets = xgadget::filter_no_deref(&gadgets, Some(&[iced_x86::Register::RCX]));
    let no_deref_gadget_strs = common::get_gadget_strs(&no_deref_gadgets, false);
    common::print_gadget_strs(&no_deref_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "pop r8; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "mov rcx, rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "push rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &no_deref_gadget_strs,
        "mov rax, 0x1337; jmp qword ptr [rax];"
    ));
}

#[test]
fn test_x64_filter_regs_overwritten_1() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let param_ctrl_gadgets = xgadget::filter_regs_overwritten(&gadgets, None);
    let reg_ctrl_gadget_strs = common::get_gadget_strs(&param_ctrl_gadgets, false);
    common::print_gadget_strs(&reg_ctrl_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop r8; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "mov rcx, rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rsp; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rax; jmp rax;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "push rax; ret;"
    ));
}

#[test]
fn test_x64_filter_regs_overwritten_2() {
    let bin_filters = common::get_raw_bin("bin_filters", common::FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let param_ctrl_gadgets =
        xgadget::filter_regs_overwritten(&gadgets, Some(&[iced_x86::Register::RCX]));
    let reg_ctrl_gadget_strs = common::get_gadget_strs(&param_ctrl_gadgets, false);
    common::print_gadget_strs(&reg_ctrl_gadget_strs);

    // Positive
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "mov rcx, rax; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "mov ecx, eax; ret;"
    ));

    // Negative
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "push rax; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop r8; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rsp; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rax; pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rbx; ret;"
    ));
    assert!(!common::gadget_strs_contains_sub_str(
        &reg_ctrl_gadget_strs,
        "pop rax; jmp rax;"
    ));
}
