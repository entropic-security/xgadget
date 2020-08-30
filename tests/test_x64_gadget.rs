use std::error::Error;




mod test_utils;

// Test Data -----------------------------------------------------------------------------------------------------------

#[rustfmt::skip]
pub const RET_AFTER_JNE_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3                                                    // ret
];

#[rustfmt::skip]
pub const ADJACENT_RET_X64: &[u8] = &[
    0x48, 0x8d, 0x05, 0xe1, 0xdd, 0x05, 0x00,               // lea  rax,[rip+0x5DDE1]
    0xc3,                                                   // ret
    0x48, 0x8d, 0x05, 0xcb, 0xdd, 0x05, 0x00,               // lea  rax,[rip+0x5DDCB]
    0xc2, 0x37, 0x13                                        // ret 0x1337
];

#[rustfmt::skip]
pub const ADJACENT_CALL_X64: &[u8] = &[
    0x48, 0x8d, 0x1d, 0xe1, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDE1]
    0xff, 0xd3,                                             // call rbx
    0x48, 0x8d, 0x1d, 0xcb, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDCB]
    0xff, 0x13,                                             // call [rbx]
];

#[rustfmt::skip]
pub const ADJACENT_JMP_X64: &[u8] = &[
    0x48, 0x8d, 0x0d, 0xe1, 0xdd, 0x05, 0x00,               // lea rcx,[rip+0x5DDE1]
    0xff, 0xe1,                                             // jmp rcx
    0x48, 0x8d, 0x0d, 0xcb, 0xdd, 0x05, 0x00,               // lea rax,[rip+0x5DDCB]    // Intentionally unused rax
    0xff, 0x21,                                             // jmp [rcx]
];

#[rustfmt::skip]
pub const X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3,                                                   // ret
    0x48, 0x8d, 0x0d, 0xe1, 0xdd, 0x05, 0x00,               // lea rcx,[rip+0x5DDE1]
    0xff, 0xe1,                                             // jmp rcx
    0x48, 0x8d, 0x0d, 0xcb, 0xdd, 0x05, 0x00,               // lea rax,[rip+0x5DDCB]    // Intentionally unused rax
    0xff, 0x21,                                             // jmp [rcx]
];

#[rustfmt::skip]
pub const X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3,                                                   // ret
    0x48, 0x8d, 0x1d, 0xe1, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDE1]
    0xff, 0xd3,                                             // call rbx
    0x48, 0x8d, 0x1d, 0xcb, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDCB]
    0xff, 0x13,                                             // call [rbx]
];

#[rustfmt::skip]
pub const X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3,                                                   // ret - Partial match, X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x48, 0x8d, 0x1d, 0xe1, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDE1]
    0xff, 0xd3,                                             // call rbx  - Full match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    0x48, 0x8d, 0x1d, 0xcb, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDCB]
    0xff, 0x21,                                             // jmp [rcx] - Full match against X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
];

#[rustfmt::skip]
pub const FILTERS_X64: &[u8] = &[
    0x58,                                                   // pop rax
    0x5b,                                                   // pop rbx
    0xc3,                                                   // ret
    0x48, 0xc7, 0xc0, 0x37, 0x13, 0x00, 0x00,               // mov rax, 0x1337
    0xff, 0x20,                                             // jmp QWORD PTR [rax]
    0x48, 0x83, 0xc0, 0x08,                                 // add rax, 0x8
    0xff, 0xe0,                                             // jmp rax
    0x5c,                                                   // pop rsp
    0xc3,                                                   // ret
    0x58,                                                   // pop rax
    0xff, 0xe0,                                             // jmp rax
];

// Tests ---------------------------------------------------------------------------------------------------------------

pub const MAX_LEN: usize = 100;

#[test]
fn test_x64_zydis_buffer() -> Result<(),  Box<dyn Error>> {
    let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
    let decoder = zydis::Decoder::new(zydis::enums::MachineMode::LONG_64, zydis::enums::AddressWidth::_64).unwrap();
    let mut backing_buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut backing_buffer[..]);

    let mut instr_strs = Vec::new();
    for (instr, _) in decoder.instruction_iterator(&RET_AFTER_JNE_X64[..], 0) {
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
    for (instr, _) in decoder.instruction_iterator(&ADJACENT_RET_X64[..], 0) {
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
    let bin_ret_post_jmp = test_utils::get_raw_bin("bin_ret_post_jmp", &RET_AFTER_JNE_X64);
    let bins = vec![bin_ret_post_jmp];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = test_utils::get_gadget_strs(&gadgets, false);
    test_utils::print_gadget_strs(&gadget_strs);

    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r12; pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rbp; pop r12; pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rbp; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rdi; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rsi; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rsp; pop r13; pop r14; pop r15; ret;"));
}

#[test]
fn test_x64_adjacent_ret() {
    let bin_ret = test_utils::get_raw_bin("bin_ret", &ADJACENT_RET_X64);
    let bins = vec![bin_ret];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::IMM16).unwrap();
    let gadget_strs = test_utils::get_gadget_strs(&gadgets, false);
    test_utils::print_gadget_strs(&gadget_strs);

    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x5DDE1; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x5DDCB; ret 0x1337;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea eax, [rip+0x5DDCB]; ret 0x1337;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea eax, [rip+0x5DDE1]; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rax, [rip+0x5DDCB]; ret 0x1337;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rax, [rip+0x5DDE1]; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x8D48C300; add eax, 0x5DDCB; ret 0x1337;"));
}

#[test]
fn test_x64_adjacent_call() {

    let bin_call = test_utils::get_raw_bin("bin_call", &ADJACENT_CALL_X64);
    let bins = vec![bin_call];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::IMM16).unwrap();
    let gadget_strs = test_utils::get_gadget_strs(&gadgets, false);
    test_utils::print_gadget_strs(&gadget_strs);

    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add bh, bh; ror dword ptr [rax-0x73], cl; sbb eax, 0x5DDCB; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x48D3FF00; lea ebx, [rip+0x5DDCB]; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"fld st0, qword ptr [rip+0x48D3FF00]; lea ebx, [rip+0x5DDCB]; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ebx, [rip+0x5DDCB]; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ebx, [rip+0x5DDE1]; call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rbx, [rip+0x5DDCB]; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rbx, [rip+0x5DDE1]; call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"loope -0x21; add eax, 0x48D3FF00; lea ebx, [rip+0x5DDCB]; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"ror dword ptr [rax-0x73], cl; sbb eax, 0x5DDCB; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"sbb eax, 0x5DDCB; call [rbx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"sbb eax, 0x5DDE1; call rbx;"));
}

#[test]
fn test_x64_adjacent_jmp() {
    let bin_jmp = test_utils::get_raw_bin("bin_jmp", &ADJACENT_JMP_X64);
    let bins = vec![bin_jmp];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = test_utils::get_gadget_strs(&gadgets, false);
    test_utils::print_gadget_strs(&gadget_strs);

    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"fld st0, qword ptr [rip+0x48E1FF00]; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp rcx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"loope -0x21; add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDCB; jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDE1; jmp rcx;"));
}

#[test]
fn test_x64_cross_variant_full_matches() {
    let bin_ret_jmp = test_utils::get_raw_bin("bin_ret_jmp", &X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_ret_call = test_utils::get_raw_bin("bin_ret_call", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64);
    let bins = vec![bin_ret_jmp, bin_ret_call];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let gadget_strs = test_utils::get_gadget_strs(&gadgets, false);
    test_utils::print_gadget_strs(&gadget_strs);

    // Common - in both ADJACENT_CALL_X64 and ADJACENT_JMP_X64
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r12; pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rbp; pop r12; pop r13; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rbp; pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rdi; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rsi; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs,"pop rsp; pop r13; pop r14; pop r15; ret;"));

    // Negative tests for unique - ADJACENT_CALL_X64
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"fld st0, qword ptr [rip+0x48E1FF00]; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"loope -0x21; add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDCB; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDE1; jmp rcx;"));

    // Negative tests for unique - ADJACENT_JMP_X64
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"fld st0, qword ptr [rip+0x48E1FF00]; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea ecx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"lea rcx, [rip+0x5DDE1]; jmp rcx;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"loope -0x21; add eax, 0x48E1FF00; lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDCB; jmp [rcx];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs,"or eax, 0x5DDE1; jmp rcx;"));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_1() {
    let bin_ret_jmp = test_utils::get_raw_bin("bin_ret_jmp", &X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_mix = test_utils::get_raw_bin("bin_mix", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64);

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_jmp
    let bins = vec![bin_mix, bin_ret_jmp];

    // Full match against X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_jump (FULL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_full_match);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"jmp [rcx];"));

    // Negative
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop r14; pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop rsi; pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop rdi; ret;"));

    // Partial match against X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_jump (PARTIAL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"jmp [rcx];"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rsi; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rdi; ret;"));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_2() {
    let bin_ret_call = test_utils::get_raw_bin("bin_ret_call", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64);
    let bin_mix = test_utils::get_raw_bin("bin_mix", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64);

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_call
    let bins = vec![bin_mix, bin_ret_call];

    // Full match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call (FULL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_full_match);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"lea rbx, [rip+0x5DDE1]; call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"call rbx;"));

    // Negative
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop r14; pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop rsi; pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop r15; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"pop rdi; ret;"));

    // Partial match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call (PARTIAL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"lea rbx, [rip+0x5DDE1]; call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_full_match,"call rbx;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rsi; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rdi; ret;"));
}

#[test]
fn test_x64_cross_variant_full_and_partial_matches_3() {
    let bin_ret_jmp = test_utils::get_raw_bin("bin_ret_jmp", &X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_ret_call = test_utils::get_raw_bin("bin_ret_call", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64);
    let bin_mix = test_utils::get_raw_bin("bin_mix", &X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64);

    let full_match_only_config = xgadget::SearchConfig::DEFAULT;
    let full_part_match_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    // mix vs. ret_call vs. ret_jmp
    let bins = vec![bin_mix, bin_ret_call, bin_ret_jmp];

    // Full match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_match_only_config).unwrap();
    let gadget_strs_full_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call vs. ret_jmp (FULL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_full_match);

    // Negative
    assert!(gadgets.is_empty());

    // Partial match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_part_match_config).unwrap();
    let gadget_strs_part_match = test_utils::get_gadget_strs(&gadgets, false);
    println!("\n{:#^1$}\n", " Mix vs. ret_call vs. ret_jmp (PARTIAL) ", 175);
    test_utils::print_gadget_strs(&gadget_strs_part_match);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r14; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rsi; pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop r15; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&gadget_strs_part_match,"pop rdi; ret;"));
}

#[test]
fn test_x64_filter_stack_pivot() {
    let bin_filters = test_utils::get_raw_bin("bin_filters", &FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let stack_pivot_gadgets = xgadget::filter_stack_pivot(&gadgets);
    let stack_pivot_gadget_strs = test_utils::get_gadget_strs(&stack_pivot_gadgets, false);
    test_utils::print_gadget_strs(&stack_pivot_gadget_strs);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"pop rsp; ret;"));

    // Negative
    assert!(!test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"pop rax; pop rbx; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"pop rbx; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"add rax, 0x08; jmp rax;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"mov rax, 0x1337; jmp [rax];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&stack_pivot_gadget_strs,"pop rax; jmp rax;"));
}

#[test]
fn test_x64_filter_dispatcher() {
    let bin_filters = test_utils::get_raw_bin("bin_filters", &FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let dispatcher_gadgets = xgadget::filter_dispatcher(&gadgets);
    let dispatcher_gadget_strs = test_utils::get_gadget_strs(&dispatcher_gadgets, false);
    test_utils::print_gadget_strs(&dispatcher_gadget_strs);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"add rax, 0x08; jmp rax;"));

    // Negative
    assert!(!test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"pop rsp; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"pop rax; pop rbx; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"pop rbx; ret;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"mov rax, 0x1337; jmp [rax];"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&dispatcher_gadget_strs,"pop rax; jmp rax;"));
}

#[test]
fn test_x64_filter_stack_set_regs() {
    let bin_filters = test_utils::get_raw_bin("bin_filters", &FILTERS_X64);
    let bins = vec![bin_filters];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();
    let loader_gadgets = xgadget::filter_stack_set_regs(&gadgets);
    let loader_gadget_strs = test_utils::get_gadget_strs(&loader_gadgets, false);
    test_utils::print_gadget_strs(&loader_gadget_strs);

    // Positive
    assert!(test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"pop rsp; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"pop rax; pop rbx; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"pop rbx; ret;"));
    assert!(test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"pop rax; jmp rax;"));

    // Negative
    assert!(!test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"add rax, 0x08; jmp rax;"));
    assert!(!test_utils::gadget_strs_contains_sub_str(&loader_gadget_strs,"mov rax, 0x1337; jmp [rax];"));
}