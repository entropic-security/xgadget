use colored::Colorize;
use std::fmt;

#[derive(Default, Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
struct Import {
    name: String,
    source: String,
    address: u64,
    attrs: Vec<String>,
    no_color: bool,
}

impl Import {
    fn from_elf(
        elf: &goblin::elf::Elf,
        sym: &goblin::elf::Sym,
        reloc: &goblin::elf::Reloc,
        no_color: bool,
    ) -> Import {
        let mut imp = Import::default();

        imp.name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(s) => s.to_string(),
            None => "".to_string(),
        };

        imp.source = get_elf_symbol_version_string(&elf, reloc.r_sym)
            .unwrap_or_else(|| "Unable to parse source".to_string());

        imp.address = reloc.r_offset;

        let symbol_r_type = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => get_symbol_r_type_64(reloc.r_type),
            goblin::elf::header::EM_386 => get_symbol_r_type_32(reloc.r_type),
            _ => reloc.r_type.to_string(),
        };

        // ELF attributes: reloc type, .plt address, symbol index, value, addend (if available)
        imp.attrs = vec![
            symbol_r_type,
            match get_plt_address(elf, &reloc) {
                Some(a) => format!("{:#x}", a),
                None => "".to_string(),
            },
            reloc.r_sym.to_string(),
            format!("{:#x}", sym.st_value),
        ];

        if let Some(addend) = reloc.r_addend {
            imp.attrs.push(addend.to_string())
        }

        imp.no_color = no_color;

        imp
    }

    fn from_pe(import: &goblin::pe::import::Import, no_color: bool) -> Import {
        let mut imp = Import::default();

        imp.name = import.name.to_string();
        imp.source = import.dll.to_string();
        imp.address = import.rva as u64;

        let offset = format!("{:#x}", import.offset);

        // PE attributes: ordinal, offset
        imp.attrs = vec![import.ordinal.to_string(), offset];

        imp.no_color = no_color;

        imp
    }

    fn from_macho(import: goblin::mach::imports::Import, no_color: bool) -> Import {
        let mut imp = Import::default();

        imp.name = import.name.to_string();
        imp.source = import.dylib.to_string();
        imp.address = import.address;

        let offset = format!("{:#x}", import.offset);
        let seq_offset = format!("{:#x}", import.start_of_sequence_offset);

        // Mach-O attributes: offset, start of sequence offset, addend, lazily evaluated?, weak?
        imp.attrs = vec![
            offset,
            seq_offset,
            import.addend.to_string(),
            import.is_lazy.to_string(),
            import.is_weak.to_string(),
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
            "{}{}{}{}  {}  {}  {}",
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
            {
                match self.no_color {
                    true => format!("{:#x}", self.address).normal(),
                    false => format!("{:#x}", self.address).red(),
                }
            },
            format!("{:?}", self.attrs).normal(),
        )
    }
}

// Dump Functions -----------------------------------------------------------------------------------------------------

pub fn dump_elf_imports(elf: &goblin::elf::Elf, no_color: bool) {
    // collect PLT relocations
    let mut plt_imports = Vec::new();
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            plt_imports.push(Import::from_elf(elf, &sym, &reloc, no_color));
        }
    }
    plt_imports.sort();

    // collect dynamic relocations
    let mut dyn_imports = Vec::new();
    if elf.dynamic.as_ref().unwrap().info.pltrel == goblin::elf::dynamic::DT_RELA {
        for reloc in elf.dynrelas.iter() {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                dyn_imports.push(Import::from_elf(elf, &sym, &reloc, no_color));
            }
        }
    } else {
        for reloc in elf.dynrels.iter() {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                dyn_imports.push(Import::from_elf(elf, &sym, &reloc, no_color));
            }
        }
    }
    dyn_imports.sort();

    // pretty print collected imports
    let blank_string = "".to_string(); // there has to be a better way to do this
    println!("Procedural Linkage Table (PLT) symbols:");
    println!(
        "{:25} {:25} {:18}  {:20} {:18}  {:5} {}",
        "Name",
        "Source, Version",
        "Address",
        "Reloc type",
        ".plt Address",
        "Idx",
        {
            match elf.dynamic.as_ref().unwrap().info.pltrel {
                goblin::elf::dynamic::DT_RELA => "Addend",
                _ => "",
            }
        },
    );
    for imp in plt_imports {
        println!(
            "{:25} {:25} {:18}  {:20} {:18}  {:5} {}",
            {
                match no_color {
                    true => format!("{}", imp.name).normal(),
                    false => format!("{}", imp.name).yellow(),
                }
            },
            {
                match no_color {
                    true => format!("{}", imp.source).normal(),
                    false => format!("{}", imp.source).green(),
                }
            },
            {
                match no_color {
                    true => format!("{:#x}", imp.address).normal(),
                    false => format!("{:#x}", imp.address).red(),
                }
            },
            imp.attrs.get(0).unwrap_or(&blank_string),
            {
                match no_color {
                    true => format!("{}", imp.attrs.get(1).unwrap_or(&blank_string)).normal(),
                    false => format!("{}", imp.attrs.get(1).unwrap_or(&blank_string)).cyan(),
                }
            },
            imp.attrs.get(2).unwrap_or(&blank_string),
            imp.attrs.get(4).unwrap_or(&blank_string),
        );
    }

    println!("\nOther dynamic symbols:");
    println!(
        "{:25} {:25} {:18}  {:20} {:18}  {:5} {}",
        "Name",
        "Source, Version",
        "Address",
        "Reloc type",
        "Value",
        "Idx",
        {
            match elf.dynamic.as_ref().unwrap().info.pltrel {
                goblin::elf::dynamic::DT_RELA => "Addend",
                _ => "",
            }
        },
    );
    for imp in dyn_imports {
        println!(
            "{:25} {:25} {:18}  {:20} {:18}  {:5} {}",
            {
                match no_color {
                    true => format!("{}", imp.name).normal(),
                    false => format!("{}", imp.name).yellow(),
                }
            },
            {
                match no_color {
                    true => format!("{}", imp.source).normal(),
                    false => format!("{}", imp.source).green(),
                }
            },
            {
                match no_color {
                    true => format!("{:#x}", imp.address).normal(),
                    false => format!("{:#x}", imp.address).red(),
                }
            },
            imp.attrs.get(0).unwrap_or(&blank_string),
            {
                match no_color {
                    true => format!("{}", imp.attrs.get(3).unwrap_or(&blank_string)).normal(),
                    false => format!("{}", imp.attrs.get(3).unwrap_or(&blank_string)).cyan(),
                }
            },
            imp.attrs.get(2).unwrap_or(&blank_string),
            imp.attrs.get(4).unwrap_or(&blank_string),
        );
    }
}

pub fn dump_pe_imports(pe: &goblin::pe::PE, no_color: bool) {
    // collect imports
    let mut imports = Vec::new();
    for import in pe.imports.iter().as_ref() {
        imports.push(Import::from_pe(import, no_color));
    }
    imports.sort();

    // pretty print imports
    let blank_string = "".to_string(); // there has to be a better way to do this
    println!("Imports:");
    println!(
        "{:35} {:20} {:18} {:5} {:18}",
        "Name", "DLL", "Rel Virt Addr", "Ord.", "Offset",
    );
    for imp in imports {
        println!(
            "{:35} {:20} {:18} {:5} {:18}",
            {
                match no_color {
                    true => format!("{}", imp.name).normal(),
                    false => format!("{}", imp.name).yellow(),
                }
            },
            {
                match no_color {
                    true => format!("{}", imp.source).normal(),
                    false => format!("{}", imp.source).green(),
                }
            },
            {
                match no_color {
                    true => format!("{:#x}", imp.address).normal(),
                    false => format!("{:#x}", imp.address).red(),
                }
            },
            imp.attrs.get(0).unwrap_or(&blank_string),
            {
                match no_color {
                    true => format!("{}", imp.attrs.get(1).unwrap_or(&blank_string)).normal(),
                    false => format!("{}", imp.attrs.get(1).unwrap_or(&blank_string)).cyan(),
                }
            },
        );
    }
}

pub fn dump_macho_imports(macho: &goblin::mach::MachO, no_color: bool) {
    // collect imports
    let mut imports = Vec::new();
    for import in macho.imports().expect("Error parsing imports") {
        imports.push(Import::from_macho(import, no_color));
    }
    imports.sort();

    // pretty print imports
    let blank_string = "".to_string(); // there has to be a better way to do this
    println!("Imports:");
    println!(
        "{:25} {:30} {:18} {:18} {:10} {:7} {:5} {:5}",
        "Name", "Dylib", "Address", "Offset", "Seq. Off.", "Addend", "Lazy?", "Weak?",
    );
    for imp in imports {
        println!(
            "{:25} {:30} {:18} {:18} {:10} {:7} {:5} {:5}",
            {
                match no_color {
                    true => format!("{}", imp.name).normal(),
                    false => format!("{}", imp.name).yellow(),
                }
            },
            {
                match no_color {
                    true => format!("{}", imp.source).normal(),
                    false => format!("{}", imp.source).green(),
                }
            },
            {
                match no_color {
                    true => format!("{:#x}", imp.address).normal(),
                    false => format!("{:#x}", imp.address).red(),
                }
            },
            {
                match no_color {
                    true => format!("{}", imp.attrs.get(0).unwrap_or(&blank_string)).normal(),
                    false => format!("{}", imp.attrs.get(0).unwrap_or(&blank_string)).cyan(),
                }
            },
            imp.attrs.get(1).unwrap_or(&blank_string),
            imp.attrs.get(2).unwrap_or(&blank_string),
            imp.attrs.get(3).unwrap_or(&blank_string),
            imp.attrs.get(4).unwrap_or(&blank_string),
        );
    }
}

// ELF Helper Functions -----------------------------------------------------------------------------------------------

fn get_elf_symbol_version_string(elf: &goblin::elf::Elf, sym_idx: usize) -> Option<String> {
    let versym = elf.versym.as_ref()?.get_at(sym_idx)?;

    if versym.is_local() {
        return Some("local".to_string());
    } else if versym.is_global() {
        return Some("global".to_string());
    } else if let Some(needed) = elf
        .verneed
        .as_ref()?
        .iter()
        .find(|v| v.iter().any(|f| f.vna_other == versym.version()))
    {
        if let Some(version) = needed.iter().find(|f| f.vna_other == versym.version()) {
            let need_str = elf.dynstrtab.get_at(needed.vn_file)?;
            let vers_str = elf.dynstrtab.get_at(version.vna_name)?;
            return Some(format!("{}, {}", need_str, vers_str));
        }
    }

    None
}

fn get_plt_address(elf: &goblin::elf::Elf, reloc: &goblin::elf::Reloc) -> Option<u64> {
    // only handle JUMP_SLOT relocations
    if reloc.r_type == goblin::elf::reloc::R_X86_64_JUMP_SLOT {
        let reloc_idx = elf.pltrelocs.iter().position(|r| r == *reloc)?;
        let plt_stub_len = 16;
        let offset = (reloc_idx as u64 + 1) * plt_stub_len;

        let plt_base = &elf
            .section_headers
            .iter()
            .find(|s| elf.shdr_strtab.get_at(s.sh_name).unwrap().eq(".plt"))?
            .sh_addr;

        return Some(plt_base + offset);
    }

    None
}

fn get_symbol_r_type_64(sym_type: u32) -> String {
    match sym_type {
        goblin::elf::reloc::R_X86_64_NONE => "R_X86_64_NONE".to_string(),
        goblin::elf::reloc::R_X86_64_64 => "R_X86_64_64".to_string(),
        goblin::elf::reloc::R_X86_64_PC32 => "R_X86_64_PC32".to_string(),
        goblin::elf::reloc::R_X86_64_GOT32 => "R_X86_64_GOT32".to_string(),
        goblin::elf::reloc::R_X86_64_PLT32 => "R_X86_64_PLT32".to_string(),
        goblin::elf::reloc::R_X86_64_COPY => "R_X86_64_COPY".to_string(),
        goblin::elf::reloc::R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT".to_string(),
        goblin::elf::reloc::R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT".to_string(),
        goblin::elf::reloc::R_X86_64_RELATIVE => "R_X86_64_RELATIVE".to_string(),
        goblin::elf::reloc::R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL".to_string(),
        goblin::elf::reloc::R_X86_64_32 => "R_X86_64_32".to_string(),
        goblin::elf::reloc::R_X86_64_32S => "R_X86_64_32S".to_string(),
        goblin::elf::reloc::R_X86_64_16 => "R_X86_64_16".to_string(),
        goblin::elf::reloc::R_X86_64_PC16 => "R_X86_64_PC16".to_string(),
        goblin::elf::reloc::R_X86_64_8 => "R_X86_64_8".to_string(),
        goblin::elf::reloc::R_X86_64_PC8 => "R_X86_64_PC8".to_string(),
        goblin::elf::reloc::R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64".to_string(),
        goblin::elf::reloc::R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64".to_string(),
        goblin::elf::reloc::R_X86_64_TPOFF64 => "R_X86_64_TPOFF64".to_string(),
        goblin::elf::reloc::R_X86_64_TLSGD => "R_X86_64_TLSGD".to_string(),
        goblin::elf::reloc::R_X86_64_TLSLD => "R_X86_64_TLSLD".to_string(),
        goblin::elf::reloc::R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32".to_string(),
        goblin::elf::reloc::R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF".to_string(),
        goblin::elf::reloc::R_X86_64_TPOFF32 => "R_X86_64_TPOFF32".to_string(),
        goblin::elf::reloc::R_X86_64_PC64 => "R_X86_64_PC64".to_string(),
        goblin::elf::reloc::R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64".to_string(),
        goblin::elf::reloc::R_X86_64_GOTPC32 => "R_X86_64_GOTPC32".to_string(),
        goblin::elf::reloc::R_X86_64_SIZE32 => "R_X86_64_SIZE32".to_string(),
        goblin::elf::reloc::R_X86_64_SIZE64 => "R_X86_64_SIZE64".to_string(),
        goblin::elf::reloc::R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC".to_string(),
        goblin::elf::reloc::R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL".to_string(),
        goblin::elf::reloc::R_X86_64_TLSDESC => "R_X86_64_TLSDESC".to_string(),
        goblin::elf::reloc::R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE".to_string(),
        _ => sym_type.to_string(),
    }
}

fn get_symbol_r_type_32(sym_type: u32) -> String {
    match sym_type {
        goblin::elf::reloc::R_386_8 => "R_386_8".to_string(),
        goblin::elf::reloc::R_386_16 => "R_386_16".to_string(),
        goblin::elf::reloc::R_386_32 => "R_386_32".to_string(),
        goblin::elf::reloc::R_386_32PLT => "R_386_32PLT".to_string(),
        goblin::elf::reloc::R_386_COPY => "R_386_COPY".to_string(),
        goblin::elf::reloc::R_386_GLOB_DAT => "R_386_GLOB_DAT".to_string(),
        goblin::elf::reloc::R_386_GOT32 => "R_386_GOT32".to_string(),
        goblin::elf::reloc::R_386_GOT32X => "R_386_GOT32X".to_string(),
        goblin::elf::reloc::R_386_GOTOFF => "R_386_GOTOFF".to_string(),
        goblin::elf::reloc::R_386_GOTPC => "R_386_GOTPC".to_string(),
        goblin::elf::reloc::R_386_IRELATIVE => "R_386_IRELATIVE".to_string(),
        goblin::elf::reloc::R_386_JMP_SLOT => "R_386_JMP_SLOT".to_string(),
        goblin::elf::reloc::R_386_NONE => "R_386_NONE".to_string(),
        goblin::elf::reloc::R_386_NUM => "R_386_NUM".to_string(),
        goblin::elf::reloc::R_386_PC8 => "R_386_PC8".to_string(),
        goblin::elf::reloc::R_386_PC16 => "R_386_PC16".to_string(),
        goblin::elf::reloc::R_386_PC32 => "R_386_PC32".to_string(),
        goblin::elf::reloc::R_386_PLT32 => "R_386_PLT32".to_string(),
        goblin::elf::reloc::R_386_RELATIVE => "R_386_RELATIVE".to_string(),
        goblin::elf::reloc::R_386_SIZE32 => "R_386_SIZE32".to_string(),
        goblin::elf::reloc::R_386_TLS_DESC => "R_386_TLS_DESC".to_string(),
        goblin::elf::reloc::R_386_TLS_DESC_CALL => "R_386_TLS_DESC_CALL".to_string(),
        goblin::elf::reloc::R_386_TLS_DTPMOD32 => "R_386_TLS_DTPMOD32".to_string(),
        goblin::elf::reloc::R_386_TLS_DTPOFF32 => "R_386_TLS_DTPOFF32".to_string(),
        goblin::elf::reloc::R_386_TLS_GD => "R_386_TLS_GD".to_string(),
        goblin::elf::reloc::R_386_TLS_GD_32 => "R_386_TLS_GD_32".to_string(),
        goblin::elf::reloc::R_386_TLS_GD_CALL => "R_386_TLS_GD_CALL".to_string(),
        goblin::elf::reloc::R_386_TLS_GD_POP => "R_386_TLS_GD_POP".to_string(),
        goblin::elf::reloc::R_386_TLS_GD_PUSH => "R_386_TLS_GD_PUSH".to_string(),
        goblin::elf::reloc::R_386_TLS_GOTDESC => "R_386_TLS_GOTDESC".to_string(),
        goblin::elf::reloc::R_386_TLS_GOTIE => "R_386_TLS_GOTIE".to_string(),
        goblin::elf::reloc::R_386_TLS_IE => "R_386_TLS_IE".to_string(),
        goblin::elf::reloc::R_386_TLS_IE_32 => "R_386_TLS_IE_32".to_string(),
        goblin::elf::reloc::R_386_TLS_LDM => "R_386_TLS_LDM".to_string(),
        goblin::elf::reloc::R_386_TLS_LDM_32 => "R_386_TLS_LDM_32".to_string(),
        goblin::elf::reloc::R_386_TLS_LDM_CALL => "R_386_TLS_LDM_CALL".to_string(),
        goblin::elf::reloc::R_386_TLS_LDM_POP => "R_386_TLS_LDM_POP".to_string(),
        goblin::elf::reloc::R_386_TLS_LDM_PUSH => "R_386_TLS_LDM_PUSH".to_string(),
        goblin::elf::reloc::R_386_TLS_LDO_32 => "R_386_TLS_LDO_32".to_string(),
        goblin::elf::reloc::R_386_TLS_LE => "R_386_TLS_LE".to_string(),
        goblin::elf::reloc::R_386_TLS_LE_32 => "R_386_TLS_LE_32".to_string(),
        goblin::elf::reloc::R_386_TLS_TPOFF => "R_386_TLS_TPOFF".to_string(),
        goblin::elf::reloc::R_386_TLS_TPOFF32 => "R_386_TLS_TPOFF32".to_string(),
        _ => sym_type.to_string(),
    }
}
