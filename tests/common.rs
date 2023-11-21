use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[allow(dead_code)]
pub const MAX_LEN: usize = 100;

// Test Data (x64) -----------------------------------------------------------------------------------------------------

#[allow(dead_code)]
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

#[allow(dead_code)]
#[rustfmt::skip]
pub const ADJACENT_RET_X64: &[u8] = &[
    0x48, 0x8d, 0x05, 0xe1, 0xdd, 0x05, 0x00,               // lea  rax,[rip+0x5DDE1]
    0xc3,                                                   // ret
    0x48, 0x8d, 0x05, 0xcb, 0xdd, 0x05, 0x00,               // lea  rax,[rip+0x5DDCB]
    0xc2, 0x37, 0x13                                        // ret 0x1337
];

#[allow(dead_code)]
#[rustfmt::skip]
pub const ADJACENT_CALL_X64: &[u8] = &[
    0x48, 0x8d, 0x1d, 0xe1, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDE1]
    0xff, 0xd3,                                             // call rbx
    0x48, 0x8d, 0x1d, 0xcb, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDCB]
    0xff, 0x13,                                             // call [rbx]
];

#[allow(dead_code)]
#[rustfmt::skip]
pub const ADJACENT_JMP_X64: &[u8] = &[
    0x48, 0x8d, 0x0d, 0xe1, 0xdd, 0x05, 0x00,               // lea rcx,[rip+0x5DDE1]
    0xff, 0xe1,                                             // jmp rcx
    0x48, 0x8d, 0x0d, 0xcb, 0xdd, 0x05, 0x00,               // lea rax,[rip+0x5DDCB]    // Intentionally unused rax
    0xff, 0x21,                                             // jmp [rcx]
];

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    0x41, 0x58,                                             // pop r8
    0xc3,                                                   // ret
    0x48, 0x89, 0xc1,                                       // mov rcx, rax
    0xc3,                                                   // ret
    0x50,                                                   // push rax
    0xc3,                                                   // ret
];

#[allow(dead_code)]
#[rustfmt::skip]
pub const FILTERS_REG_NO_DEREF_AND_REG_WRITE: &[u8] = &[
    0x4c, 0x03, 0x07,                                       // add    r8,QWORD PTR [rdi]
    0x4c, 0x03, 0x06,                                       // add    r8,QWORD PTR [rsi]
    0x4c, 0x03, 0x02,                                       // add    r8,QWORD PTR [rdx]
    0x5e,                                                   // pop    rsi
    0x5f,                                                   // pop    rdi
    0xc3,                                                   // ret
];

// http://bodden.de/pubs/fbt+16pshape.pdf
#[allow(dead_code)]
#[rustfmt::skip]
pub const PSHAPE_PG_5_X64: &[u8] = &[
    0x48, 0x89, 0xe0,                                       // mov rax, rsp
    0x4c, 0x89, 0x48, 0x20,                                 // mov [rax+0x20], r9
    0x4c, 0x89, 0x40, 0x18,                                 // mov [rax+0x18], r8
    0x48, 0x89, 0x50, 0x10,                                 // mov [rax+0x10], rdx
    0x48, 0x89, 0x48, 0x08,                                 // mov [rax+0x8], rcx
    0x4c, 0x89, 0xc9,                                       // mov rcx, r9
    0x48, 0x8b, 0x01,                                       // mov rax, [rcx]
    0x48, 0xff, 0xc0,                                       // inc rax
    0x48, 0x89, 0x41, 0x08,                                 // mov [rcx+0x8], rax
    0x48, 0x8b, 0x41, 0x04,                                 // mov rax, [rcx+0x4]
    0x48, 0xff, 0xc0,                                       // inc rax
    0x48, 0x89, 0x41, 0x0c,                                 // mov [rcx+0x0C], rax
    0xc3,                                                   // ret
];

#[allow(dead_code)]
#[rustfmt::skip]
pub const MISC_1: &[u8] = &[
    0x87, 0x48, 0x1,                                        // xchg [rax+0x1], ecx
    0xf8,                                                   // clc
    0xff, 0xe0,                                             // jump rax
];

#[allow(dead_code)]
#[rustfmt::skip]
pub const MISC_2: &[u8] = &[
    0x48, 0xff, 0xc0,                                       // inc rax // TODO: remove this line
    0xff, 0x25, 0xbd, 0x66, 0x09, 0x00,                     // jmp qword ptr [rip+0x966bd]
];

// Test Utils ----------------------------------------------------------------------------------------------------------

#[allow(dead_code)]
pub fn decode_single_x64_instr(ip: u64, bytes: &[u8]) -> iced_x86::Instruction {
    let mut decoder = iced_x86::Decoder::new(64, bytes, iced_x86::DecoderOptions::NONE);
    decoder.set_ip(ip);

    decoder.decode()
}

#[allow(dead_code)]
pub fn get_raw_bin(name: &str, bytes: &[u8]) -> xgadget::Binary {
    let mut bin = xgadget::Binary::from_bytes(name, bytes).unwrap();
    assert_eq!(bin.format(), xgadget::Format::Raw);
    assert_eq!(bin.arch(), xgadget::Arch::X64); // Default unless caller updates
    bin.set_arch(xgadget::Arch::X64);

    bin
}

#[allow(dead_code)]
pub fn get_gadget_strs(gadgets: &[xgadget::Gadget], att_syntax: bool) -> Vec<String> {
    let mut strs = Vec::new();
    for (mut instr, addrs) in xgadget::fmt_gadget_str_list(gadgets, att_syntax) {
        instr.push(' ');
        strs.push(format!("{:-<150} {}", instr, addrs));
    }
    strs
}

#[allow(dead_code)]
pub fn print_gadget_strs(gadget_strs: &[String]) {
    println!("Found {} gadgets\n", gadget_strs.len());
    for s in gadget_strs {
        println!("{}", s);
    }
}

#[allow(dead_code)]
pub fn gadget_strs_contains_sub_str(gadget_strs: &[String], substring: &str) -> bool {
    for gs in gadget_strs {
        if std::str::from_utf8(&strip_ansi_escapes::strip(gs))
            .unwrap()
            .contains(substring)
        {
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

// Adapted from https://docs.rs/iced-x86/1.10.0/iced_x86/?search=#get-instruction-info-eg-readwritten-regsmem-control-flow-info-etc
// TODO: check against updated docs
#[allow(dead_code)]
pub fn dump_instr(instr: &iced_x86::Instruction) {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let op_code = instr.op_code();
    let info = info_factory.info(instr);
    let fpu_info = instr.fpu_stack_increment_info();
    println!("\n\tOpCode: {}", op_code.op_code_string());
    println!("\tInstruction: {}", op_code.instruction_string());
    println!("\tEncoding: {:?}", instr.encoding());
    println!("\tMnemonic: {:?}", instr.mnemonic());
    println!("\tCode: {:?}", instr.code());
    println!(
        "\tCpuidFeature: {}",
        instr
            .cpuid_features()
            .iter()
            .map(|&a| format!("{:?}", a))
            .collect::<Vec<String>>()
            .join(" and ")
    );
    println!("\tFlowControl: {:?}", instr.flow_control());

    if fpu_info.writes_top() {
        if fpu_info.increment() == 0 {
            println!("\tFPU TOP: the instruction overwrites TOP");
        } else {
            println!("\tFPU TOP inc: {}", fpu_info.increment());
        }
        println!(
            "\tFPU TOP cond write: {}",
            if fpu_info.conditional() {
                "true"
            } else {
                "false"
            }
        );
    }
    if instr.is_stack_instruction() {
        println!("\tSP Increment: {}", instr.stack_pointer_increment());
    }
    if instr.condition_code() != iced_x86::ConditionCode::None {
        println!("\tCondition code: {:?}", instr.condition_code());
    }
    if instr.rflags_read() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Read: {}", flags(instr.rflags_read()));
    }
    if instr.rflags_written() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Written: {}", flags(instr.rflags_written()));
    }
    if instr.rflags_cleared() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Cleared: {}", flags(instr.rflags_cleared()));
    }
    if instr.rflags_set() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Set: {}", flags(instr.rflags_set()));
    }
    if instr.rflags_undefined() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Undefined: {}", flags(instr.rflags_undefined()));
    }
    if instr.rflags_modified() != iced_x86::RflagsBits::NONE {
        println!("\tRFLAGS Modified: {}", flags(instr.rflags_modified()));
    }
    for i in 0..instr.op_count() {
        let op_kind = instr.try_op_kind(i).unwrap();
        if op_kind == iced_x86::OpKind::Memory {
            let size = instr.memory_size().size();
            if size != 0 {
                println!("\tMemory size: {}", size);
            }
            break;
        }
    }
    for i in 0..instr.op_count() {
        println!("\tOp{}Access: {:?}", i, info.try_op_access(i).unwrap());
    }
    for i in 0..op_code.op_count() {
        println!("\tOp{}: {:?}", i, op_code.try_op_kind(i).unwrap());
    }
    for reg_info in info.used_registers() {
        println!("\tUsed reg: {:?}", reg_info);
    }
    for mem_info in info.used_memory() {
        println!("\tUsed mem: {:?}", mem_info);
    }
}

fn flags(rf: u32) -> String {
    fn append(sb: &mut String, s: &str) {
        if !sb.is_empty() {
            sb.push_str(", ");
        }
        sb.push_str(s);
    }

    let mut sb = String::new();
    if (rf & iced_x86::RflagsBits::OF) != 0 {
        append(&mut sb, "OF");
    }
    if (rf & iced_x86::RflagsBits::SF) != 0 {
        append(&mut sb, "SF");
    }
    if (rf & iced_x86::RflagsBits::ZF) != 0 {
        append(&mut sb, "ZF");
    }
    if (rf & iced_x86::RflagsBits::AF) != 0 {
        append(&mut sb, "AF");
    }
    if (rf & iced_x86::RflagsBits::CF) != 0 {
        append(&mut sb, "CF");
    }
    if (rf & iced_x86::RflagsBits::PF) != 0 {
        append(&mut sb, "PF");
    }
    if (rf & iced_x86::RflagsBits::DF) != 0 {
        append(&mut sb, "DF");
    }
    if (rf & iced_x86::RflagsBits::IF) != 0 {
        append(&mut sb, "IF");
    }
    if (rf & iced_x86::RflagsBits::AC) != 0 {
        append(&mut sb, "AC");
    }
    if (rf & iced_x86::RflagsBits::UIF) != 0 {
        append(&mut sb, "UIF");
    }
    if sb.is_empty() {
        sb.push_str("<empty>");
    }
    sb
}
