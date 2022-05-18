use colored::Colorize;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
struct Import {
    name: String,
    source: String,
    attrs: Vec<String>,
    no_color: bool,
}

impl Import {
    // Construction helper
    fn priv_new() -> Import {
        Import {
            name: String::from("None"),
            source: String::from("None"),
            attrs: vec![],
            no_color: false,
        }
    }

    fn from_elf(
        elf: &goblin::elf::Elf,
        sym_idx: &usize,
        sym: &goblin::elf::sym::Sym,
        no_color: bool,
    ) -> Import {
        fn get_symbol_version_string(elf: &goblin::elf::Elf, sym_idx: &usize) -> Option<String> {
            let vers_data = elf.versym.as_ref()?.get_at(*sym_idx)?.vs_val;

            if vers_data == 0 {
                return Some("local".to_string());
            }

            if let Some(needed) = elf
                .verneed
                .as_ref()?
                .iter()
                .find(|v| v.iter().any(|f| f.vna_other == vers_data))
            {
                if let Some(version) = needed.iter().find(|f| f.vna_other == vers_data) {
                    let need_str = elf.dynstrtab.get_at(needed.vn_file)?;
                    let vers_str = elf.dynstrtab.get_at(version.vna_name)?;
                    return Some(format!("{}, {} ({})", need_str, vers_str, vers_data));
                }
            }

            None
        }

        let get_symbol_type = |val: u8| match val {
            goblin::elf::sym::STT_NOTYPE => "NOTYPE".to_string(),
            goblin::elf::sym::STT_OBJECT => "OBJECT".to_string(),
            goblin::elf::sym::STT_FUNC => "FUNC".to_string(),
            goblin::elf::sym::STT_SECTION => "SECTION".to_string(),
            goblin::elf::sym::STT_FILE => "FILE".to_string(),
            goblin::elf::sym::STT_COMMON => "COMMON".to_string(),
            goblin::elf::sym::STT_TLS => "TLS".to_string(),
            _ => val.to_string(),
        };

        let get_symbol_binding = |val: u8| match val {
            goblin::elf::sym::STB_LOCAL => "LOCAL".to_string(),
            goblin::elf::sym::STB_GLOBAL => "GLOBAL".to_string(),
            goblin::elf::sym::STB_WEAK => "WEAK".to_string(),
            _ => val.to_string(),
        };

        let get_symbol_visibility = |val: u8| match val {
            goblin::elf::sym::STV_DEFAULT => "DEFAULT".to_string(),
            goblin::elf::sym::STV_INTERNAL => "INTERNAL".to_string(),
            goblin::elf::sym::STV_HIDDEN => "HIDDEN".to_string(),
            goblin::elf::sym::STV_PROTECTED => "PROTECTED".to_string(),
            _ => val.to_string(),
        };

        let get_symbol_index_type = |val: usize| match val {
            0 => "UND".to_string(),
            0xfff1 => "ABS".to_string(),
            0xfff2 => "COM".to_string(),
            _ => val.to_string(),
        };

        let mut imp = Import::priv_new();

        imp.name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(s) => s.to_string(),
            None => "".to_string(),
        };

        imp.source = get_symbol_version_string(&elf, sym_idx)
            .unwrap_or_else(|| "Unable to parse source".to_string());

        imp.attrs = vec![
            get_symbol_type(sym.st_type()),
            get_symbol_binding(sym.st_bind()),
            get_symbol_visibility(sym.st_visibility()),
            get_symbol_index_type(sym.st_shndx),
        ];

        imp.no_color = no_color;

        imp
    }

    fn from_pe(import: &goblin::pe::import::Import, no_color: bool) -> Import {
        let mut imp = Import::priv_new();

        imp.name = import.name.to_string();
        imp.source = import.dll.to_string();

        let offset = format!("0x{:08x}", import.offset);
        let rva = format!("0x{:08x}", import.rva);

        imp.attrs = vec![import.ordinal.to_string(), offset, rva];

        imp.no_color = no_color;

        imp
    }

    fn from_macho(import: &goblin::mach::imports::Import, no_color: bool) -> Import {
        let mut imp = Import::priv_new();

        imp.name = import.name.to_string();
        imp.source = import.dylib.to_string();

        let offset = format!("0x{:08x}", import.offset);
        let address = format!("0x{:08x}", import.address);
        let seq_offset = format!("0x{:08x}", import.start_of_sequence_offset);

        imp.attrs = vec![
            import.is_lazy.to_string(),
            offset,
            address,
            import.addend.to_string(),
            import.is_weak.to_string(),
            seq_offset,
        ];

        imp.no_color = no_color;

        imp
    }
}

impl fmt::Display for Import {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let color_punctuation = |s: &str| {
            if self.no_color {
                s.normal()
            } else {
                s.bright_magenta()
            }
        };

        let single_quote = color_punctuation("'");
        let colon = color_punctuation(":");

        write!(
            f,
            "{}{}{}{}  {}  {}",
            single_quote,
            {
                match self.no_color {
                    true => format!("{}", self.name).normal(),
                    false => format!("{}", self.name).yellow(),
                }
            },
            single_quote,
            colon,
            {
                match self.no_color {
                    true => format!("{}", self.source).normal(),
                    false => format!("{}", self.source).green(),
                }
            },
            format!("{:?}", self.attrs).normal(),
        )
    }
}

pub fn dump_elf_imports(elf: &goblin::elf::Elf, no_color: bool) {
    println!("Imported symbols:");
    println!("  'name': library, version (version number) [type, binding, visibility, ndx]");
    for (sym_idx, sym) in elf.dynsyms.into_iter().enumerate() {
        if sym.is_import() {
            println!("  {}", Import::from_elf(elf, &sym_idx, &sym, no_color));
        }
    }
}

pub fn dump_pe_imports(pe: &goblin::pe::PE, no_color: bool) {
    println!("Imports:");
    println!("  'name': dll [ordinal, offset, rva]");
    for import in pe.imports.iter().as_ref() {
        println!("  {}", Import::from_pe(import, no_color));
    }
}

pub fn dump_macho_imports(macho: &goblin::mach::MachO, no_color: bool) {
    println!("Imports:");
    println!("  'name': dylib [is lazily evaluated?, offset, address, addend, is weak?, start of sequence offset]");
    for import in macho.imports().expect("Error parsing imports") {
        println!("  {}", Import::from_macho(&import, no_color));
    }
}
