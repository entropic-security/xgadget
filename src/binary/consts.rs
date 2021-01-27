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
