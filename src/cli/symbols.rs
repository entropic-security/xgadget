use std::{cmp, fmt};

use colored::Colorize;

#[derive(Default, Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
struct Import {
    name: String,
    source: String,
    address: u64,
    attrs: Vec<String>,
}

impl Import {
    fn from_elf(
        elf: &goblin::elf::Elf,
        sym: &goblin::elf::Sym,
        reloc: &goblin::elf::Reloc,
    ) -> Import {
        let mut imp = Import {
            name: match elf.dynstrtab.get_at(sym.st_name) {
                Some(s) => s.to_string(),
                None => "".to_string(),
            },
            source: get_elf_symbol_version_string(elf, reloc.r_sym)
                .unwrap_or_else(|| "Unable to parse source".to_string()),
            address: reloc.r_offset,
            ..Default::default()
        };

        imp.source = get_elf_symbol_version_string(elf, reloc.r_sym)
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
            match get_plt_address(elf, reloc) {
                Some(a) => format!("{:#x}", a),
                None => "".to_string(),
            },
            reloc.r_sym.to_string(),
            format!("{:#x}", sym.st_value),
        ];

        if let Some(addend) = reloc.r_addend {
            imp.attrs.push(addend.to_string())
        }

        imp
    }

    fn from_pe(import: &goblin::pe::import::Import) -> Import {
        let mut imp = Import {
            name: import.name.to_string(),
            source: import.dll.to_string(),
            address: import.rva as u64,
            ..Default::default()
        };

        let offset = format!("{:#x}", import.offset);

        // PE attributes: ordinal, offset
        imp.attrs = vec![import.ordinal.to_string(), offset];

        imp
    }

    fn from_macho(import: goblin::mach::imports::Import) -> Import {
        let mut imp = Import {
            name: import.name.to_string(),
            source: import.dylib.to_string(),
            address: import.address,
            ..Default::default()
        };

        let offset = format!("{:#x}", import.offset);
        let seq_offset = format!("{:#x}", import.start_of_sequence_offset);

        // Mach-O attributes: start of sequence offset, offset, addend, lazily evaluated?, weak?
        imp.attrs = vec![
            seq_offset,
            offset,
            import.addend.to_string(),
            import.is_lazy.to_string(),
            import.is_weak.to_string(),
        ];

        imp
    }

    fn get_print_vec(&self) -> Vec<String> {
        let mut print_vec = vec![
            format!("{:}", self.name),
            format!("{:}", self.source),
            format!("{:#x}", self.address),
        ];
        let mut attrs = self.attrs.clone();
        print_vec.append(&mut attrs);

        print_vec
    }
}

impl fmt::Display for Import {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let color_punctuation = |s: &str| s.bright_magenta();

        let single_quote = color_punctuation("'");
        let colon = color_punctuation(":");
        let comma = color_punctuation(",");

        write!(
            f,
            "{}{}{}{}  {}{}  address: {}{}  attributes: {}",
            single_quote,
            self.name.to_string().yellow(),
            single_quote,
            colon,
            self.source.to_string().green(),
            comma,
            format!("{:#x}", self.address).red(),
            comma,
            format!("{:?}", self.attrs).normal(),
        )
    }
}

// Dump Functions -----------------------------------------------------------------------------------------------------

pub fn dump_elf_imports(elf: &goblin::elf::Elf) {
    // determine if relocations include an addend
    let rela = if let Some(dynamic) = elf.dynamic.as_ref() {
        dynamic.info.pltrel == goblin::elf::dynamic::DT_RELA
    } else {
        false
    };

    // column headers for ELF imports
    let headers = vec![
        "Name",
        "Source, Version",
        "Address",
        "Reloc type",
        ".plt Addr",
        "Idx",
        "Value",
        {
            match rela {
                true => "Addend",
                false => "",
            }
        },
    ];
    // initialize column width vec based on header length
    let mut col_width = vec![0; headers.len()];
    for (idx, header) in headers.iter().enumerate() {
        col_width[idx] = header.len();
    }

    // collect PLT relocations
    let mut plt_imports = Vec::new();
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            let print_vec = Import::from_elf(elf, &sym, &reloc).get_print_vec();
            // update column width to match longest string in column
            for (idx, print_str) in print_vec.iter().enumerate() {
                col_width[idx] = cmp::max(col_width[idx], print_str.len());
            }

            plt_imports.push(print_vec);
        }
    }

    // print collected PLT relocations
    println!("Procedural Linkage Table (PLT) symbols:");
    print_imports(&headers, plt_imports, &col_width);

    // re-initialize column width vec
    for (idx, header) in headers.iter().enumerate() {
        col_width[idx] = header.len();
    }

    // collect dynamic relocations
    let mut dyn_imports = Vec::new();
    if rela {
        for reloc in elf.dynrelas.iter() {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                let print_vec = Import::from_elf(elf, &sym, &reloc).get_print_vec();
                // update column width to match longest string in column
                for (idx, print_str) in print_vec.iter().enumerate() {
                    col_width[idx] = cmp::max(col_width[idx], print_str.len());
                }

                dyn_imports.push(print_vec);
            }
        }
    } else {
        for reloc in elf.dynrels.iter() {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                let print_vec = Import::from_elf(elf, &sym, &reloc).get_print_vec();
                // update column width to match longest string in column
                for (idx, print_str) in print_vec.iter().enumerate() {
                    col_width[idx] = cmp::max(col_width[idx], print_str.len());
                }

                dyn_imports.push(print_vec);
            }
        }
    }

    // print collected dynamic relocations
    println!("\nOther dynamic symbols:");
    print_imports(&headers, dyn_imports, &col_width);
}

pub fn dump_pe_imports(pe: &goblin::pe::PE) {
    // column headers for PE imports
    let headers = vec!["Name", "DLL", "Rel Virt Addr", "Ord", "Offset"];
    // initialize column width vec based on header length
    let mut col_width = vec![0; headers.len()];
    for (idx, header) in headers.iter().enumerate() {
        col_width[idx] = header.len();
    }

    // collect imports
    let mut imports = Vec::new();
    for import in pe.imports.iter().as_ref() {
        let print_vec = Import::from_pe(import).get_print_vec();
        // update column width to match longest string in column
        for (idx, print_str) in print_vec.iter().enumerate() {
            col_width[idx] = cmp::max(col_width[idx], print_str.len());
        }

        imports.push(print_vec);
    }

    // print collected imports
    println!("Imports:");
    print_imports(&headers, imports, &col_width);
}

pub fn dump_macho_imports(macho: &goblin::mach::MachO) {
    // column headers for Mach-O imports
    let headers = vec![
        "Name",
        "Dylib",
        "Address",
        "Seq. Off.",
        "Offset",
        "Addend",
        "Lazy?",
        "Weak?",
    ];
    // initialize column width vec based on header length
    let mut col_width = vec![0; headers.len()];
    for (idx, header) in headers.iter().enumerate() {
        col_width[idx] = header.len();
    }

    // collect imports
    let mut imports = Vec::new();
    for import in macho.imports().expect("Error parsing imports") {
        let print_vec = Import::from_macho(import).get_print_vec();
        // update column width to match longest string in column
        for (idx, print_str) in print_vec.iter().enumerate() {
            col_width[idx] = cmp::max(col_width[idx], print_str.len());
        }

        imports.push(print_vec);
    }

    // print collected imports
    println!("Imports:");
    print_imports(&headers, imports, &col_width);
}

fn print_imports(headers: &[&str], mut imports: Vec<Vec<String>>, col_width: &[usize]) {
    imports.sort();

    print!("\t");
    for (idx, hdr) in headers.iter().enumerate() {
        let width = col_width[idx];
        print!("{:width$}  ", hdr);
    }
    println!();

    for import in imports {
        print!("\t");
        for (idx, print_str) in import.iter().enumerate() {
            let width = col_width[idx];

            match idx {
                0 => print!("{:width$}  ", print_str.yellow()),
                1 => print!("{:width$}  ", print_str.green()),
                2 => print!("{:width$}  ", print_str.red()),
                4 => print!("{:width$}  ", print_str.cyan()),
                _ => print!("{:width$}  ", print_str),
            }
        }
        println!();
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
            .find(|s| {
                elf.shdr_strtab
                    .get_at(s.sh_name)
                    .unwrap_or("err")
                    .eq(".plt")
            })?
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
