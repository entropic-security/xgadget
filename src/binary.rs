use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use rayon::prelude::*;
use rustc_hash::FxHashSet;

// Segment -------------------------------------------------------------------------------------------------------------

/// A single executable segment
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Segment {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

impl Segment {
    /// Constructor
    pub fn new(addr: u64, bytes: Vec<u8>) -> Segment {
        Segment { addr, bytes }
    }

    /// Check if contains address
    pub fn contains(&self, addr: u64) -> bool {
        (self.addr <= addr) && (addr < (self.addr + self.bytes.len() as u64))
    }

    /// Get offsets of byte occurrences
    pub fn get_matching_offsets(&self, vals: &[u8]) -> Vec<usize> {
        self.bytes
            .par_iter()
            .enumerate()
            .filter(|&(_, b)| vals.contains(b))
            .map(|(i, _)| i)
            .collect()
    }
}

// Binary --------------------------------------------------------------------------------------------------------------

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

/// Architecture
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Arch {
    Unknown,
    X8086,
    X86,
    X64,
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

/// File format agnostic binary
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Binary {
    pub name: String,
    pub format: Format,
    pub arch: Arch,
    pub entry: u64,
    pub segments: FxHashSet<Segment>,
}

impl Binary {
    // Binary Public API -----------------------------------------------------------------------------------------------

    /// Byte slice -> Binary
    pub fn from_bytes(name: &str, bytes: &[u8]) -> Result<Binary, Box<dyn Error>> {
        Binary::priv_from_buf(name, bytes)
    }

    /// Path str -> Binary
    pub fn from_path_str(path: &str) -> Result<Binary, Box<dyn Error>> {
        let name = Path::new(path).file_name().ok_or("No filename.")?;
        let name_str = name.to_str().ok_or("Failed filename decode.")?;
        let bytes = fs::read(path)?;

        Binary::priv_from_buf(name_str, &bytes)
    }

    // Binary Private API ----------------------------------------------------------------------------------------------

    // Construction helper
    fn priv_new() -> Binary {
        Binary {
            name: String::from("None"),
            format: Format::Unknown,
            arch: Arch::Unknown,
            entry: 0,
            segments: FxHashSet::default(),
        }
    }

    fn priv_from_buf(name: &str, bytes: &[u8]) -> Result<Binary, Box<dyn Error>> {
        match goblin::Object::parse(&bytes)? {
            goblin::Object::Elf(elf) => Binary::from_elf(name, &bytes, &elf),
            goblin::Object::PE(pe) => Binary::from_pe(name, &bytes, &pe),
            goblin::Object::Unknown(_) => Ok(Binary::from_raw(name, bytes)),
            _ => Err("Unsupported file format!".into()),
        }
    }

    // ELF file -> Binary
    fn from_elf(
        name: &str,
        bytes: &[u8],
        elf: &goblin::elf::Elf,
    ) -> Result<Binary, Box<dyn Error>> {
        let mut bin = Binary::priv_new();

        bin.name = name.to_string();
        bin.entry = elf.entry;
        bin.format = Format::ELF;

        // Architecture
        bin.arch = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => Arch::X64,
            goblin::elf::header::EM_386 => Arch::X86,
            _ => {
                return Err("Unsupported architecture!".into());
            }
        };

        // Executable segments
        for prog_hdr in elf
            .program_headers
            .iter()
            .filter(|&p| (p.p_flags & goblin::elf::program_header::PF_X) != 0)
        {
            let start_offset = prog_hdr.p_offset as usize;
            let end_offset = start_offset + prog_hdr.p_filesz as usize;

            bin.segments.insert(Segment::new(
                prog_hdr.p_vaddr,
                bytes[start_offset..end_offset].to_vec(),
            ));
        }

        bin.remove_sub_segs();
        Ok(bin)
    }

    // PE file -> Binary
    fn from_pe(name: &str, bytes: &[u8], pe: &goblin::pe::PE) -> Result<Binary, Box<dyn Error>> {
        let mut bin = Binary::priv_new();

        bin.name = name.to_string();
        bin.entry = pe.entry as u64;
        bin.format = Format::PE;

        // Architecture
        bin.arch = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X64,
            goblin::pe::header::COFF_MACHINE_X86 => Arch::X86,
            _ => {
                return Err("Unsupported architecture!".into());
            }
        };

        // Executable segments
        for sec_tab in pe.sections.iter().filter(|&p| {
            (p.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE) != 0
        }) {
            let start_offset = sec_tab.pointer_to_raw_data as usize;
            let end_offset = start_offset + sec_tab.size_of_raw_data as usize;

            bin.segments.insert(Segment::new(
                sec_tab.virtual_address as u64 + pe.image_base as u64,
                bytes[start_offset..end_offset].to_vec(),
            ));
        }

        bin.remove_sub_segs();
        Ok(bin)
    }

    // Raw bytes -> Binary, Unknown arch to be updated by caller
    fn from_raw(name: &str, bytes: &[u8]) -> Binary {
        let mut bin = Binary::priv_new();

        bin.name = name.to_string();
        bin.entry = 0;
        bin.format = Format::Raw;

        bin.segments.insert(Segment::new(0, bytes[..].to_vec()));

        bin
    }

    // Remove any segment that's completely contained in another
    // We don't want to waste time decoding an unnecessary duplicate
    fn remove_sub_segs(&mut self) {
        let mut sub_segs = Vec::new();

        for seg in &self.segments {
            let mut local_sub_segs = self
                .segments
                .iter()
                .cloned()
                .filter(|s| (s.addr == seg.addr) && (s.bytes.len() < seg.bytes.len()))
                .collect();

            sub_segs.append(&mut local_sub_segs);
        }

        for s in sub_segs {
            self.segments.remove(&s);
        }
    }
}

// Summary print
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\'{}\': {:?}-{:?}, entry 0x{:016x}, {}/{} executable bytes/segments",
            self.name,
            self.format,
            self.arch,
            self.entry,
            self.segments
                .iter()
                .fold(0, |bytes, seg| bytes + seg.bytes.len()),
            self.segments.len(),
        )
    }
}
