use std::error::Error;

mod common;

#[test]
fn test_x64_zydis_buffer() -> Result<(), Box<dyn Error>> {
    let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
    let decoder = zydis::Decoder::new(
        zydis::enums::MachineMode::LONG_64,
        zydis::enums::AddressWidth::_64,
    )
    .unwrap();
    let mut backing_buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut backing_buffer[..]);

    let mut instr_strs = Vec::new();
    for (instr, _) in decoder.instruction_iterator(&common::RET_AFTER_JNE_X64[..], 0) {
        formatter.format_instruction(&instr, &mut buffer, None, None)?;
        //instr_strs.push(buffer.as_str().unwrap()); // TODO (tnballo): debug why this doesn't work?
        instr_strs.push(format!("{}", buffer));
    }

    assert_eq!("mov rax, [rsp+0xB8]", instr_strs[0]);
    assert_eq!("xor rax, fs:[0x28]", instr_strs[1]);
    assert_eq!("jnz +0x1F6", instr_strs[2]);
    assert_eq!("add rsp, 0xC8", instr_strs[3]);
    assert_eq!("mov eax, r12d", instr_strs[4]);
    assert_eq!("pop rbx", instr_strs[5]);
    assert_eq!("pop rbp", instr_strs[6]);
    assert_eq!("pop r12", instr_strs[7]);
    assert_eq!("pop r13", instr_strs[8]);
    assert_eq!("pop r14", instr_strs[9]);
    assert_eq!("pop r15", instr_strs[10]);
    assert_eq!("ret", instr_strs[11]);

    instr_strs.clear();
    for (instr, _) in decoder.instruction_iterator(&common::ADJACENT_RET_X64[..], 0) {
        formatter.format_instruction(&instr, &mut buffer, None, None)?;
        instr_strs.push(format!("{}", buffer));
    }

    assert_eq!("lea rax, [rip+0x5DDE1]", instr_strs[0]);
    assert_eq!("ret", instr_strs[1]);
    assert_eq!("lea rax, [rip+0x5DDCB]", instr_strs[2]);
    assert_eq!("ret 0x1337", instr_strs[3]);

    Ok(())
}

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
        "add eax, 0x5DDE1; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x5DDCB; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea eax, [rip+0x5DDCB]; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea eax, [rip+0x5DDE1]; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rax, [rip+0x5DDCB]; ret 0x1337;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rax, [rip+0x5DDE1]; ret;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x8D48C300; add eax, 0x5DDCB; ret 0x1337;"
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
        "add bh, bh; ror dword ptr [rax-0x73], cl; sbb eax, 0x5DDCB; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "add eax, 0x48D3FF00; lea ebx, [rip+0x5DDCB]; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st0, qword ptr [rip+0x48D3FF00]; lea ebx, [rip+0x5DDCB]; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ebx, [rip+0x5DDCB]; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ebx, [rip+0x5DDE1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rbx, [rip+0x5DDCB]; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rbx, [rip+0x5DDE1]; call rbx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope -0x21; add eax, 0x48D3FF00; lea ebx, [rip+0x5DDCB]; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "ror dword ptr [rax-0x73], cl; sbb eax, 0x5DDCB; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "sbb eax, 0x5DDCB; call [rbx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "sbb eax, 0x5DDE1; call rbx;"
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
        "add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "fld st0, qword ptr [rip+0x48E1FF00]; lea ecx, [rip+0x5DDCB]; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5DDCB]; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea ecx, [rip+0x5DDE1]; jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5DDCB]; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "lea rcx, [rip+0x5DDE1]; jmp rcx;"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "loope -0x21; add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5DDCB; jmp [rcx];"
    ));
    assert!(common::gadget_strs_contains_sub_str(
        &gadget_strs,
        "or eax, 0x5DDE1; jmp rcx;"
    ));
}
