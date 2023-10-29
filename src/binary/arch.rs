use core::{fmt, str::FromStr};

use crate::error::Error;

/// Architecture
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Arch {
    /// Unknown architecture
    Unknown = 0,
    /// 8086 (16-bit x86)
    X8086 = 16,
    /// x86 (32-bit x86)
    X86 = 32,
    /// x64 (32-bit x86)
    X64 = 64,
}

impl Arch {
    /// Arch -> bitness
    pub fn bits(&self) -> u32 {
        *self as u32
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                Arch::Unknown => "unknown",
                Arch::X8086 => "x8086",
                Arch::X86 => "x86",
                Arch::X64 => "x64",
            }
        )
    }
}

impl FromStr for Arch {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Arch::Unknown),
            "x8086" => Ok(Arch::X8086),
            "x86" => Ok(Arch::X86),
            "x64" => Ok(Arch::X64),
            _ => Err(Error::UnsupportedArch),
        }
    }
}
