use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use colored::Colorize;
use rustc_hash::FxHashSet as HashSet;

use super::arch::Arch;
use super::consts::*;
use super::file_format::Format;
use super::segment::Segment;

// Binary --------------------------------------------------------------------------------------------------------------

/// File format agnostic binary
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Binary {
    name: String,
    format: Format,
    arch: Arch,
    entry: u64,
    param_regs: Option<&'static [iced_x86::Register]>,
    segments: HashSet<Segment>,
    color_display: bool,
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

    /// Get name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get format
    pub fn format(&self) -> Format {
        self.format
    }

    /// Get arch
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Set arch
    pub fn set_arch(&mut self, arch: Arch) {
        self.arch = arch
    }

    /// Get entry point
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Get param registers
    pub fn param_regs(&self) -> &Option<&'static [iced_x86::Register]> {
        &self.param_regs
    }

    /// Get segments
    pub fn segments(&self) -> &HashSet<Segment> {
        &self.segments
    }

    /// Binary -> bitness
    pub fn bits(&self) -> u32 {
        self.arch.bits()
    }

    /// Enable/disable colored `Display`
    pub fn set_color_display(&mut self, enable: bool) {
        self.color_display = enable;
    }

    // Binary Private API ----------------------------------------------------------------------------------------------

    // Construction helper
    fn priv_new() -> Binary {
        Binary {
            name: String::from("None"),
            format: Format::Unknown,
            arch: Arch::Unknown,
            entry: 0,
            param_regs: None,
            segments: HashSet::default(),
            color_display: true,
        }
    }

    // Bytes -> Binary
    fn priv_from_buf(name: &str, bytes: &[u8]) -> Result<Binary, Box<dyn Error>> {
        match goblin::Object::parse(&bytes) {
            Ok(obj) => match obj {
                goblin::Object::Unknown(_) => Ok(Binary::from_raw(name, bytes)),
                goblin::Object::Elf(elf) => Binary::from_elf(name, &bytes, &elf),
                goblin::Object::PE(pe) => Binary::from_pe(name, &bytes, &pe),
                _ => Err("Unsupported file format!".into()),
            },
            _ => Ok(Binary::from_raw(name, bytes)),
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

        // Argument registers
        if bin.arch == Arch::X64 {
            bin.param_regs = Some(X64_ELF_PARAM_REGS);
        }

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

        // Argument registers
        if bin.arch == Arch::X64 {
            bin.param_regs = Some(X64_PE_PARAM_REGS);
        }

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
        let color_punctuation = |s: &str| {
            if self.color_display {
                s.bright_magenta()
            } else {
                s.normal()
            }
        };

        let seg_cnt = self.segments.len();

        let bytes = self
            .segments
            .iter()
            .fold(0, |bytes, seg| bytes + seg.bytes.len());

        let single_quote = color_punctuation("'");
        let forward_slash = color_punctuation("/");
        let dash = color_punctuation("-");
        let colon = color_punctuation(":");
        let comma = color_punctuation(",");

        write!(
            f,
            "{}{}{}{} {}{}{}{} {} entry{} {}{}{} executable bytes{}segments",
            single_quote,
            {
                match self.color_display {
                    true => self.name.cyan(),
                    false => self.name.normal(),
                }
            },
            single_quote,
            colon,
            {
                match self.color_display {
                    true => format!("{:?}", self.format).yellow(),
                    false => format!("{:?}", self.format).normal(),
                }
            },
            dash,
            {
                match self.color_display {
                    true => format!("{:?}", self.arch).yellow(),
                    false => format!("{:?}", self.arch).normal(),
                }
            },
            comma,
            {
                match self.color_display {
                    true => format!("{:#016x}", self.entry).green(),
                    false => format!("{:#016x}", self.entry).normal(),
                }
            },
            comma,
            {
                match self.color_display {
                    true => format!("{}", bytes).bright_blue(),
                    false => format!("{}", bytes).normal(),
                }
            },
            forward_slash,
            {
                match self.color_display {
                    true => format!("{}", seg_cnt).bright_blue(),
                    false => format!("{}", seg_cnt).normal(),
                }
            },
            forward_slash,
        )
    }
}

// Misc Helpers --------------------------------------------------------------------------------------------------------

/// Get set union of all parameter registers for a list of binaries
pub fn get_all_param_regs(bins: &[Binary]) -> Vec<iced_x86::Register> {
    let mut param_regs = HashSet::default();

    for b in bins {
        if let Some(regs) = b.param_regs {
            for reg in regs {
                param_regs.insert(*reg);
            }
        }
    }

    param_regs.into_iter().collect()
}
