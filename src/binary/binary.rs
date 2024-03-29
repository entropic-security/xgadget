use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use colored::Colorize;
use rustc_hash::FxHashSet as HashSet;

use super::{arch::Arch, consts::*, file_format::Format, segment::Segment};
use crate::error::Error;

// Binary --------------------------------------------------------------------------------------------------------------

/// File format agnostic binary
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Binary {
    name: String,
    path: Option<PathBuf>,
    format: Format,
    arch: Arch,
    entry: u64,
    param_regs: Option<&'static [iced_x86::Register]>,
    segments: HashSet<Segment>,
}

impl Binary {
    // Binary Public API -----------------------------------------------------------------------------------------------

    /// Byte slice -> Binary
    pub fn from_bytes(name: &str, bytes: &[u8]) -> Result<Binary, Error> {
        Binary::priv_from_buf(name, None, bytes)
    }

    /// Path str -> Binary
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Binary, Error> {
        let name = path
            .as_ref()
            .file_name()
            .ok_or(Error::NoFileName)?
            .to_str()
            .ok_or(Error::NoFileName)?;

        let bytes = fs::read(path.as_ref())?;

        Binary::priv_from_buf(name, Some(path.as_ref()), &bytes)
    }

    /// Get name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get path
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
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

    // Binary Private API ----------------------------------------------------------------------------------------------

    // Bytes -> Binary
    fn priv_from_buf(name: &str, path: Option<&Path>, bytes: &[u8]) -> Result<Binary, Error> {
        match goblin::Object::parse(bytes) {
            Ok(obj) => match obj {
                goblin::Object::Elf(elf) => Binary::from_elf(name, path, bytes, &elf),
                goblin::Object::PE(pe) => Binary::from_pe(name, path, bytes, &pe),
                goblin::Object::Mach(mach) => Binary::from_mach(name, path, bytes, &mach),
                goblin::Object::Unknown(_) => Ok(Binary::from_raw(name, bytes)),
                _ => Err(Error::UnsupportedFileFormat),
            },
            _ => Ok(Binary::from_raw(name, bytes)),
        }
    }

    // ELF file -> Binary
    fn from_elf(
        name: &str,
        path: Option<&Path>,
        bytes: &[u8],
        elf: &goblin::elf::Elf,
    ) -> Result<Binary, Error> {
        let mut bin = Binary {
            name: name.to_string(),
            path: path.map(PathBuf::from),
            entry: elf.entry,
            format: Format::ELF,
            arch: match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => Arch::X64,
                goblin::elf::header::EM_386 => Arch::X86,
                _ => {
                    return Err(Error::UnsupportedArch);
                }
            },
            ..Default::default()
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
    fn from_pe(
        name: &str,
        path: Option<&Path>,
        bytes: &[u8],
        pe: &goblin::pe::PE,
    ) -> Result<Binary, Error> {
        let mut bin = Binary {
            name: name.to_string(),
            path: path.map(PathBuf::from),
            entry: pe.entry as u64,
            format: Format::PE,
            arch: match pe.header.coff_header.machine {
                goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X64,
                goblin::pe::header::COFF_MACHINE_X86 => Arch::X86,
                _ => {
                    return Err(Error::UnsupportedArch);
                }
            },
            ..Default::default()
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

    // Mach-O file -> Binary
    fn from_mach(
        name: &str,
        path: Option<&Path>,
        bytes: &[u8],
        mach: &goblin::mach::Mach,
    ) -> Result<Binary, Error> {
        let mut bin = Binary::default();

        // Handle Mach-O and Multi-Architecture variants
        let temp_macho: goblin::mach::MachO;
        let macho = match mach {
            goblin::mach::Mach::Binary(binary) => binary,
            goblin::mach::Mach::Fat(fat) => {
                temp_macho = get_supported_macho(fat)?;
                &temp_macho
            }
        };

        bin.name = name.to_string();
        bin.path = path.map(PathBuf::from);
        bin.entry = macho.entry;
        bin.format = Format::MachO;

        // Architecture
        bin.arch = match macho.header.cputype() {
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Arch::X64,
            goblin::mach::constants::cputype::CPU_TYPE_I386 => Arch::X86,
            _ => {
                return Err(Error::UnsupportedArch);
            }
        };

        // Argument registers
        if bin.arch == Arch::X64 {
            bin.param_regs = Some(X64_MACHO_PARAM_REGS);
        }

        // Executable segments
        for section in macho
            .segments
            .sections()
            .flatten()
            .filter_map(|sec| sec.ok())
            .map(|sec| sec.0)
            .filter(|sec| (sec.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS) != 0)
        {
            let start_offset = section.offset as usize;
            let end_offset = start_offset + section.size as usize;

            bin.segments.insert(Segment::new(
                section.addr,
                bytes[start_offset..end_offset].to_vec(),
            ));
        }

        bin.remove_sub_segs();
        Ok(bin)
    }

    // Raw bytes -> Binary
    //
    // ### WARNING:
    //
    // This defaults `arch` to [Arch::X64], caller must update if incorrect.
    fn from_raw(name: &str, bytes: &[u8]) -> Binary {
        let mut bin = Binary {
            name: name.to_string(),
            format: Format::Raw,
            arch: Arch::X64,
            ..Default::default()
        };

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
                .filter(|&s| (s.addr == seg.addr) && (s.bytes.len() < seg.bytes.len()))
                .cloned()
                .collect();

            sub_segs.append(&mut local_sub_segs);
        }

        for s in sub_segs {
            self.segments.remove(&s);
        }
    }
}

impl Default for Binary {
    fn default() -> Self {
        Binary {
            name: String::from("unknown"),
            path: None,
            format: Format::Unknown,
            arch: Arch::Unknown,
            entry: 0,
            param_regs: None,
            segments: HashSet::default(),
        }
    }
}

// Summary print
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let color_punctuation = |s: &str| s.bold().bright_magenta();

        let num_fmt = |n: usize| {
            #[cfg(feature = "cli-bin")]
            {
                use num_format::{Locale, ToFormattedString};
                n.to_formatted_string(&Locale::en)
            }

            #[cfg(not(feature = "cli-bin"))]
            {
                n.to_string()
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
        let open_bracket = color_punctuation("[");
        let close_bracket = color_punctuation("]");
        let colon = color_punctuation(":");
        let pipe = color_punctuation("|");

        write!(
            f,
            "{} name{} {}{}{} {} fmt{}arch{} {}{}{} {} entry{} {} {} exec bytes{}segments{} {}{}{} {}",
            open_bracket,
            colon,
            single_quote,
            self.name.cyan(),
            single_quote,
            pipe,
            dash,
            colon,
            format!("{:?}", self.format).yellow(),
            dash,
            format!("{:?}", self.arch).yellow(),
            pipe,
            colon,
            format!("{:#016x}", self.entry).green(),
            pipe,
            forward_slash,
            colon,
            num_fmt(bytes).to_string().bright_blue(),
            forward_slash,
            num_fmt(seg_cnt).to_string().bright_blue(),
            close_bracket,
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

#[doc(hidden)]
pub fn get_supported_macho<'a>(
    fat: &'a goblin::mach::MultiArch,
) -> Result<goblin::mach::MachO<'a>, Error> {
    fat.find(|arch| {
        (arch.as_ref().unwrap().cputype() == goblin::mach::constants::cputype::CPU_TYPE_X86_64)
            || (arch.as_ref().unwrap().cputype() == goblin::mach::constants::cputype::CPU_TYPE_I386)
    })
    .ok_or(Error::UnsupportedArch)?
    // Don't expose goblin-internal errors
    .map_err(|_| Error::UnsupportedArch)
    .and_then(|single_arch| match single_arch {
        goblin::mach::SingleArch::MachO(macho) => Ok(macho),
        _ => Err(Error::UnsupportedArch),
    })
}
