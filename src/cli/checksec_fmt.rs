use std::fmt;

use checksec::{
    colorize_bool, elf::ElfCheckSecResults, macho::MachOCheckSecResults, pe::PECheckSecResults,
};
use colored::Colorize;

// This file provides a multi-line, optional-color alternative to checksec's single line print.

// Manual color removal
fn remove_color(results: &str) -> String {
    let stripped_bytes = strip_ansi_escapes::strip(&results).unwrap();
    let mut stripped_string = "\t".to_owned();
    stripped_string.push_str(
        &std::str::from_utf8(&stripped_bytes)
            .unwrap()
            .replace('\n', "\n\t"),
    );
    stripped_string
}

// ELF results new type
pub struct CustomElfCheckSecResults {
    pub results: ElfCheckSecResults,
    pub no_color: bool,
}

// Custom ELF string format
// https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/elf.rs#L149
impl fmt::Display for CustomElfCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let results = format!(
            "\tCanary: {}\n\tCFI: {}\n\tSafeStack: {}\n\tFortify: {}\n\tFortified: {:2}\n\t\
            NX: {}\n\tPIE: {}\n\tRelro: {}\n\tRPATH: {}\n\tRUNPATH: {}",
            colorize_bool!(self.results.canary),
            colorize_bool!(self.results.clang_cfi),
            colorize_bool!(self.results.clang_safestack),
            colorize_bool!(self.results.fortify),
            self.results.fortified,
            colorize_bool!(self.results.nx),
            self.results.pie,
            self.results.relro,
            self.results.rpath,
            self.results.runpath
        );

        match self.no_color {
            true => write!(f, "{}", remove_color(&results)),
            false => write!(f, "{}", results),
        }
    }
}

// PE results new type
pub struct CustomPeCheckSecResults {
    pub results: PECheckSecResults,
    pub no_color: bool,
}

// Custom PE string format
// https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/pe.rs#L355
impl fmt::Display for CustomPeCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let results = format!(
            "\tASLR: {}\n\tAuthenticode: {}\n\tCFG: {}\n\tCLR: {}\n\tDEP: {}\n\t\
            Dynamic Base: {}\n\tForce Integrity: {}\n\tGS: {}\n\t\
            High Entropy VA: {}\n\tIsolation: {}\n\tRFG: {}\n\tSafeSEH: {}\n\tSEH: {}",
            self.results.aslr,
            colorize_bool!(self.results.authenticode),
            colorize_bool!(self.results.cfg),
            colorize_bool!(self.results.clr),
            colorize_bool!(self.results.dep),
            colorize_bool!(self.results.dynamic_base),
            colorize_bool!(self.results.force_integrity),
            colorize_bool!(self.results.gs),
            colorize_bool!(self.results.high_entropy_va),
            colorize_bool!(self.results.isolation),
            colorize_bool!(self.results.rfg),
            colorize_bool!(self.results.safeseh),
            colorize_bool!(self.results.seh)
        );

        match self.no_color {
            true => write!(f, "{}", remove_color(&results)),
            false => write!(f, "{}", results),
        }
    }
}

// Mach-O results new type
pub struct CustomMachOCheckSecResults {
    pub results: MachOCheckSecResults,
    pub no_color: bool,
}

// Custom Mach-O string format
// https://github.com/etke/checksec.rs/blob/0ad2d5fbcd4dd0c3c37e7773301ccb017c2d33c9/src/macho.rs#L82
impl fmt::Display for CustomMachOCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let results = format!(
            // TODO: enable once Mach-O fortify support lands on crates.io
            /*
            "\tARC: {}\n\tCanary: {}\n\tCode Signature: {}\n\tEncryption: {}\n\t\
            Fortify: {}\n\tFortified {:2}\n\tNX Heap: {}\n\t\
            NX Stack: {}\n\tPIE: {}\n\tRestrict: {}\n\tRPath: {}",
            */
            "\tARC: {}\n\tCanary: {}\n\tCode Signature: {}\n\tEncryption: {}\n\t\
            NX Heap: {}\n\t\
            NX Stack: {}\n\tPIE: {}\n\tRestrict: {}\n\tRPath: {}",
            colorize_bool!(self.results.arc),
            colorize_bool!(self.results.canary),
            colorize_bool!(self.results.code_signature),
            colorize_bool!(self.results.encrypted),
            //colorize_bool!(self.results.fortify),
            //self.results.fortified,
            colorize_bool!(self.results.nx_heap),
            colorize_bool!(self.results.nx_stack),
            colorize_bool!(self.results.pie),
            colorize_bool!(self.results.restrict),
            colorize_bool!(self.results.rpath)
        );

        match self.no_color {
            true => write!(f, "{}", remove_color(&results)),
            false => write!(f, "{}", results),
        }
    }
}
