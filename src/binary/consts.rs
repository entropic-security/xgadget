// Supported register counts -------------------------------------------------------------------------------------------

/// Total number of named registers
pub const ICED_X86_REG_TOTAL: usize = 256;
/// Total number of unique named registers
pub const ICED_X86_REG_TOTAL_UNIQUE: usize = 248;

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

// Test-only -----------------------------------------------------------------------------------------------------------

// TODO: currently unused
#[cfg(test)]
pub const CARGO_TEST_DEFAULT_STACK_LIMIT_BYTES: usize = 2_097_152;
