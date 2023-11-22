// Argument Registers --------------------------------------------------------------------------------------------------

/// x64 ELF argument registers
#[rustfmt::skip]
pub static X64_ELF_PARAM_REGS: &[iced_x86::Register] = &[
    iced_x86::Register::RDI,
    iced_x86::Register::RSI,
    iced_x86::Register::RDX,
    iced_x86::Register::RCX,
    iced_x86::Register::R8,
    iced_x86::Register::R9,
];

/// x64 PE argument registers
#[rustfmt::skip]
pub static X64_PE_PARAM_REGS: &[iced_x86::Register] = &[
    iced_x86::Register::RCX,
    iced_x86::Register::RDX,
    iced_x86::Register::R8,
    iced_x86::Register::R9,
];

/// x64 Mach-O argument registers
#[rustfmt::skip]
pub static X64_MACHO_PARAM_REGS: &[iced_x86::Register] = &[
    iced_x86::Register::RDI,
    iced_x86::Register::RSI,
    iced_x86::Register::RDX,
    iced_x86::Register::RCX,
    iced_x86::Register::R8,
    iced_x86::Register::R9,
];

// Sub-register Mappings -----------------------------------------------------------------------------------------------

// TODO: shouldn't be necessary, see `test_xor_al_ch`
pub(crate) fn get_reg_family(reg: &iced_x86::Register) -> impl Iterator<Item = iced_x86::Register> {
    use iced_x86::Register as Reg;
    // See: https://upload.wikimedia.org/wikipedia/commons/3/3e/X86_64-registers.svg
    match reg {
        // RAX family
        Reg::RAX => vec![Reg::RAX, Reg::EAX, Reg::AX, Reg::AH, Reg::AL].into_iter(),
        Reg::EAX => vec![Reg::EAX, Reg::AX, Reg::AH, Reg::AL].into_iter(),
        Reg::AX => vec![Reg::AX, Reg::AH, Reg::AL].into_iter(),

        // RBX family
        Reg::RBX => vec![Reg::RBX, Reg::EBX, Reg::BX, Reg::BH, Reg::BL].into_iter(),
        Reg::EBX => vec![Reg::EBX, Reg::BX, Reg::BH, Reg::BL].into_iter(),
        Reg::BX => vec![Reg::BX, Reg::BH, Reg::BL].into_iter(),

        // RCX family
        Reg::RCX => vec![Reg::RCX, Reg::ECX, Reg::CX, Reg::CH, Reg::CL].into_iter(),
        Reg::ECX => vec![Reg::ECX, Reg::CX, Reg::CH, Reg::CL].into_iter(),
        Reg::CX => vec![Reg::CX, Reg::CH, Reg::CL].into_iter(),

        // RDX family
        Reg::RDX => vec![Reg::RDX, Reg::EDX, Reg::DX, Reg::DH, Reg::DL].into_iter(),
        Reg::EDX => vec![Reg::EDX, Reg::DX, Reg::DH, Reg::DL].into_iter(),
        Reg::DX => vec![Reg::DX, Reg::DH, Reg::DL].into_iter(),

        // RBP family
        Reg::RBP => vec![Reg::RBP, Reg::EBP, Reg::BP, Reg::BPL].into_iter(),
        Reg::EBP => vec![Reg::EBP, Reg::BP, Reg::BPL].into_iter(),
        Reg::BP => vec![Reg::BP, Reg::BPL].into_iter(),

        // TODO: RSL?
        // TODO: RDL?

        // RSP family
        Reg::RSP => vec![Reg::RSP, Reg::ESP, Reg::SP, Reg::SPL].into_iter(),
        Reg::ESP => vec![Reg::ESP, Reg::SP, Reg::SPL].into_iter(),
        Reg::SP => vec![Reg::SP, Reg::SPL].into_iter(),

        // R8 family
        Reg::R8 => vec![Reg::R8, Reg::R8D, Reg::R8W, Reg::R8L].into_iter(),
        Reg::R8D => vec![Reg::R8D, Reg::R8W, Reg::R8L].into_iter(),
        Reg::R8W => vec![Reg::R8W, Reg::R8L].into_iter(),

        // R9 family
        Reg::R9 => vec![Reg::R9, Reg::R9D, Reg::R9W, Reg::R9L].into_iter(),
        Reg::R9D => vec![Reg::R9D, Reg::R9W, Reg::R9L].into_iter(),
        Reg::R9W => vec![Reg::R9W, Reg::R9L].into_iter(),

        // R10 family
        Reg::R10 => vec![Reg::R10, Reg::R10D, Reg::R10W, Reg::R10L].into_iter(),
        Reg::R10D => vec![Reg::R10D, Reg::R10W, Reg::R10L].into_iter(),
        Reg::R10W => vec![Reg::R10W, Reg::R10L].into_iter(),

        // R11 family
        Reg::R11 => vec![Reg::R11, Reg::R11D, Reg::R11W, Reg::R11L].into_iter(),
        Reg::R11D => vec![Reg::R11D, Reg::R11W, Reg::R11L].into_iter(),
        Reg::R11W => vec![Reg::R11W, Reg::R11L].into_iter(),

        // R12 family
        Reg::R12 => vec![Reg::R12, Reg::R12D, Reg::R12W, Reg::R12L].into_iter(),
        Reg::R12D => vec![Reg::R12D, Reg::R12W, Reg::R12L].into_iter(),
        Reg::R12W => vec![Reg::R12W, Reg::R12L].into_iter(),

        // R13 family
        Reg::R13 => vec![Reg::R13, Reg::R13D, Reg::R13W, Reg::R13L].into_iter(),
        Reg::R13D => vec![Reg::R13D, Reg::R13W, Reg::R13L].into_iter(),
        Reg::R13W => vec![Reg::R13W, Reg::R13L].into_iter(),

        // R14 family
        Reg::R14 => vec![Reg::R14, Reg::R14D, Reg::R14W, Reg::R14L].into_iter(),
        Reg::R14D => vec![Reg::R14D, Reg::R14W, Reg::R14L].into_iter(),
        Reg::R14W => vec![Reg::R14W, Reg::R14L].into_iter(),

        // R15 family
        Reg::R15 => vec![Reg::R15, Reg::R15D, Reg::R15W, Reg::R15L].into_iter(),
        Reg::R15D => vec![Reg::R15D, Reg::R15W, Reg::R15L].into_iter(),
        Reg::R15W => vec![Reg::R15W, Reg::R15L].into_iter(),

        // RIP family
        Reg::RIP => vec![Reg::RIP, Reg::EIP].into_iter(),

        // No family relation
        _ => vec![*reg].into_iter(),
    }
}
