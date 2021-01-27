use std::str::FromStr;

/// Architecture
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Arch {
    Unknown = 0,
    X8086 = 16,
    X86 = 32,
    X64 = 64,
}

impl Arch {
    /// Arch -> bitness
    pub fn bits(&self) -> u32 {
        *self as u32
    }
}

impl FromStr for Arch {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Arch::Unknown),
            "x8086" => Ok(Arch::X8086),
            "x86" => Ok(Arch::X86),
            "x64" => Ok(Arch::X64),
            _ => Err("Could not parse architecture string to enum"),
        }
    }
}
