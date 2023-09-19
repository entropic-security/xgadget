//! This module provides a multi-line, optional-color alternative to checksec's single line print.
use std::fmt;

use checksec::{colorize_bool, elf, macho, pe};
use checksec_goblin::Object;
use colored::Colorize;

pub enum CustomCheckSecResults {
    Elf(elf::CheckSecResults),
    Pe(pe::CheckSecResults),
    MachO(macho::CheckSecResults),
}

pub struct CustomCheckSecResultsDisplay {
    results: CustomCheckSecResults,
    no_color: bool,
}

impl CustomCheckSecResultsDisplay {
    pub fn new(bytes: &[u8], path: &str, no_color: bool) -> Self {
        let results = match Object::parse(bytes).unwrap() {
            Object::Elf(elf) => CustomCheckSecResults::Elf(elf::CheckSecResults::parse(&elf)),
            Object::PE(pe) => {
                let mm_buf =
                    unsafe { memmap::Mmap::map(&std::fs::File::open(path).unwrap()).unwrap() };
                CustomCheckSecResults::Pe(pe::CheckSecResults::parse(&pe, &mm_buf))
            }
            Object::Mach(mach) => match mach {
                checksec_goblin::mach::Mach::Binary(macho) => {
                    CustomCheckSecResults::MachO(macho::CheckSecResults::parse(&macho))
                }
                _ => panic!("Checksec supports only single-arch Mach-O!"),
            },
            _ => panic!("Only ELF, PE, and Mach-O checksec currently supported!"),
        };

        Self { results, no_color }
    }
}

impl fmt::Display for CustomCheckSecResultsDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let results_fmt = match &self.results {
            // Custom ELF string format
            // https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/elf.rs#L149
            CustomCheckSecResults::Elf(elf) => {
                format!(
                    "\tCanary: {}\n\tCFI: {}\n\tSafeStack: {}\n\tFortify: {}\n\tFortified: {:2}\n\t\
                    NX: {}\n\tPIE: {}\n\tRelro: {}\n\tRPATH: {}\n\tRUNPATH: {}",
                    colorize_bool!(elf.canary),
                    colorize_bool!(elf.clang_cfi),
                    colorize_bool!(elf.clang_safestack),
                    colorize_bool!(elf.fortify),
                    elf.fortified,
                    colorize_bool!(elf.nx),
                    elf.pie,
                    elf.relro,
                    elf.rpath,
                    elf.runpath
                )
            }
            // Custom PE string format
            // https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/pe.rs#L355
            CustomCheckSecResults::Pe(pe) => {
                format!(
                    "\tASLR: {}\n\tAuthenticode: {}\n\tCFG: {}\n\tCLR: {}\n\tDEP: {}\n\t\
                    Dynamic Base: {}\n\tForce Integrity: {}\n\tGS: {}\n\t\
                    High Entropy VA: {}\n\tIsolation: {}\n\tRFG: {}\n\tSafeSEH: {}\n\tSEH: {}",
                    pe.aslr,
                    colorize_bool!(pe.authenticode),
                    colorize_bool!(pe.cfg),
                    colorize_bool!(pe.clr),
                    colorize_bool!(pe.dep),
                    colorize_bool!(pe.dynamic_base),
                    colorize_bool!(pe.force_integrity),
                    colorize_bool!(pe.gs),
                    colorize_bool!(pe.high_entropy_va),
                    colorize_bool!(pe.isolation),
                    colorize_bool!(pe.rfg),
                    colorize_bool!(pe.safeseh),
                    colorize_bool!(pe.seh)
                )
            }
            // Custom Mach-O string format
            // https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/macho.rs#L82
            CustomCheckSecResults::MachO(macho) => {
                format!(
                    "\tARC: {}\n\tCanary: {}\n\tCode Signature: {}\n\tEncryption: {}\n\t\
                    Fortify: {}\n\tFortified {:2}\n\tNX Heap: {}\n\t\
                    NX Stack: {}\n\tPIE: {}\n\tRestrict: {}\n\tRPath: {}",
                    colorize_bool!(macho.arc),
                    colorize_bool!(macho.canary),
                    colorize_bool!(macho.code_signature),
                    colorize_bool!(macho.encrypted),
                    colorize_bool!(macho.fortify),
                    macho.fortified,
                    colorize_bool!(macho.nx_heap),
                    colorize_bool!(macho.nx_stack),
                    colorize_bool!(macho.pie),
                    colorize_bool!(macho.restrict),
                    colorize_bool!(macho.rpath)
                )
            }
        };

        match self.no_color {
            true => write!(
                f,
                "\t{}",
                &std::str::from_utf8(&strip_ansi_escapes::strip(results_fmt))
                    .unwrap()
                    .replace('\n', "\n\t")
            ),
            false => write!(f, "{}", results_fmt),
        }
    }
}
