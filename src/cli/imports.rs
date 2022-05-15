use std::collections::HashMap;

pub fn elf_imports(elf: &goblin::elf::Elf) {
    let mut vers_map = HashMap::new();

    if let Some(verneed) = &elf.verneed {
        for need_file in verneed.iter() {
            for need_ver in need_file.iter() {
                vers_map.insert(
                    need_ver.vna_other,
                    elf.dynstrtab.get_at(need_ver.vna_name).unwrap_or(""),
                );
            }
        }
    }

    println!("   Num:    Value  Size Type    Bind   Vis      Ndx Name");

    for (sym_idx, sym) in elf.dynsyms.into_iter().enumerate() {
        if sym.is_import() {
            print!("{:>6}: {:08} {:>5} ", sym_idx, sym.st_value, sym.st_size,);
            print!("{:<7} ", get_symbol_type(&sym.st_type()));
            print!("{:<6} ", get_symbol_binding(&sym.st_bind()));
            print!("{:<8} ", get_symbol_visibility(&sym.st_visibility()));
            print!("{:<3} ", get_symbol_index_type(&sym.st_shndx));
            print!("{} ", elf.dynstrtab.get_at(sym.st_name).unwrap_or(""));
                        println!(
                            "{}",
                            get_symbol_version_string(&elf, &vers_map, &sym_idx)
                                .unwrap_or_else(|| "".to_string())
                        );
        }
    }
}

fn get_symbol_type(sym_type: &u8) -> String {
    match *sym_type {
        goblin::elf::sym::STT_NOTYPE => "NOTYPE".to_string(),
        goblin::elf::sym::STT_OBJECT => "OBJECT".to_string(),
        goblin::elf::sym::STT_FUNC => "FUNC".to_string(),
        goblin::elf::sym::STT_SECTION => "SECTION".to_string(),
        goblin::elf::sym::STT_FILE => "FILE".to_string(),
        goblin::elf::sym::STT_COMMON => "COMMON".to_string(),
        goblin::elf::sym::STT_TLS => "TLS".to_string(),
        _ => sym_type.to_string(),
    }
}

fn get_symbol_binding(sym_bind: &u8) -> String {
    match *sym_bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL".to_string(),
        goblin::elf::sym::STB_GLOBAL => "GLOBAL".to_string(),
        goblin::elf::sym::STB_WEAK => "WEAK".to_string(),
        _ => sym_bind.to_string(),
    }
}

fn get_symbol_visibility(sym_vis: &u8) -> String {
    match *sym_vis {
        goblin::elf::sym::STV_DEFAULT => "DEFAULT".to_string(),
        goblin::elf::sym::STV_INTERNAL => "INTERNAL".to_string(),
        goblin::elf::sym::STV_HIDDEN => "HIDDEN".to_string(),
        goblin::elf::sym::STV_PROTECTED => "PROTECTED".to_string(),
        _ => sym_vis.to_string(),
    }
}

fn get_symbol_index_type(sym_type: &usize) -> String {
    match *sym_type {
        0 => "UND".to_string(),
        0xfff1 => "ABS".to_string(),
        0xfff2 => "COM".to_string(),
        _ => sym_type.to_string(),
    }
}

fn get_symbol_version_string(
    elf: &goblin::elf::Elf,
    vers_map: &HashMap<u16, &str>,
    sym_idx: &usize,
) -> Option<String> {
    let vers_data = &elf.versym.as_ref()?.get_at(*sym_idx)?.vs_val;
    let vers_string = vers_map.get(vers_data)?;

    Some(format!("@ {} ({})", vers_string, vers_data))
}