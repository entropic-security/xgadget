use std::str::FromStr;

/// File format
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Format {
    Unknown,
    ELF,
    PE,
    Raw,
}

impl FromStr for Format {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Format::Unknown),
            "elf" => Ok(Format::ELF),
            "pe" => Ok(Format::PE),
            "raw" => Ok(Format::Raw),
            _ => Err("Could not parse format string to enum"),
        }
    }
}
