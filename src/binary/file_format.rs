use core::str::FromStr;

use crate::error::Error;

/// File format
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Format {
    Unknown,
    ELF,
    PE,
    MachO,
    Raw,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Format::Unknown),
            "elf" => Ok(Format::ELF),
            "pe" => Ok(Format::PE),
            "macho" => Ok(Format::MachO),
            "raw" => Ok(Format::Raw),
            _ => Err(Error::UnsupportedFileFormat),
        }
    }
}
