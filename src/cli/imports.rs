use colored::Colorize;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
struct Symbol {
    name: String,
    source: String,
    attrs: Vec<String>,
    no_color: bool,
}

impl Symbol {
    // Construction helper
    fn priv_new() -> Symbol {
        Symbol {
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
    ) -> Symbol {
        fn get_symbol_version_string(elf: &goblin::elf::Elf, sym_idx: &usize) -> Option<String> {
            let vers_data = &elf.versym.as_ref()?.get_at(*sym_idx)?.vs_val;

            let (need_str, vers_str) = if let Some(needed) = elf
                .verneed
                .as_ref()?
                .iter()
                .find(|v| v.iter().any(|f| f.vna_other == *vers_data))
            {
                if let Some(version) = needed.iter().find(|f| f.vna_other == *vers_data) {
                    (
                        elf.dynstrtab.get_at(needed.vn_file)?,
                        elf.dynstrtab.get_at(version.vna_name)?,
                    )
                } else {
                    return Some("".to_string());
                }
            } else {
                return Some("".to_string());
            };

            Some(format!("{}, {} ({})", need_str, vers_str, vers_data))
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

        let mut symbol = Symbol::priv_new();

        symbol.name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(s) => s.to_string(),
            None => "".to_string(),
        };

        symbol.source = get_symbol_version_string(&elf, &sym_idx)
            .unwrap_or_else(|| "Unable to parse source".to_string());

        symbol.attrs = vec![
            get_symbol_type(sym.st_type()),
            get_symbol_binding(sym.st_bind()),
            get_symbol_visibility(sym.st_visibility()),
            get_symbol_index_type(sym.st_shndx),
        ];

        symbol.no_color = no_color;

        symbol
    }
}

impl fmt::Display for Symbol {
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
            "{}{}{}{} {} {}",
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
            let symbol = Symbol::from_elf(elf, &sym_idx, &sym, no_color);

            println!("  {}", symbol);
        }
    }
}
