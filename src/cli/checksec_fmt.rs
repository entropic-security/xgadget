use std::fmt;

use checksec::colorize_bool;
use checksec::elf::ElfCheckSecResults;
use checksec::pe::PECheckSecResults;
use colored::Colorize;

// This file provides a multi-line alternative to checksec's single line print
// Unfortunately, coloring is a compile-time option for the checksec crate and not a run-time one,
// so this output doesn't respect the --no-color flag.

pub struct CustomElfCheckSecResults(pub ElfCheckSecResults);

// Custom ELF string format
// https://github.com/etke/checksec.rs/blob/3ef5573ac400c5d4aa5cd63cfcaab7db53f08b02/src/elf.rs#L133
impl fmt::Display for CustomElfCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\tCanary: {}\n\tCFI: {}\n\tSafeStack: {}\n\tFortify: {}\n\tFortified: {}\n\t\
            NX: {}\n\tPIE: {}\n\tRelro: {}\n\tRPATH: {}\n\tRUNPATH: {}",
            colorize_bool!(self.0.canary),
            colorize_bool!(self.0.clang_cfi),
            colorize_bool!(self.0.clang_safestack),
            colorize_bool!(self.0.fortify),
            self.0.fortified,
            colorize_bool!(self.0.nx),
            self.0.pie,
            self.0.relro,
            self.0.rpath,
            self.0.runpath
        )
    }
}

pub struct CustomPeCheckSecResults(pub PECheckSecResults);

// Custom PE string format
// https://github.com/etke/checksec.rs/blob/3ef5573ac400c5d4aa5cd63cfcaab7db53f08b02/src/pe.rs#L339
impl fmt::Display for CustomPeCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\tASLR: {}\n\tAuthenticode: {}\n\tCFG: {}\n\tCLR: {}\n\tDEP: {}\n\t\
            Dynamic Base: {}\n\tForce Integrity: {}\n\tGS: {}\n\t\
            High Entropy VA: {}\n\tIsolation: {}\n\tRFG: {}\n\tSafeSEH: {}\n\tSEH: {}",
            self.0.aslr,
            colorize_bool!(self.0.authenticode),
            colorize_bool!(self.0.cfg),
            colorize_bool!(self.0.clr),
            colorize_bool!(self.0.dep),
            colorize_bool!(self.0.dynamic_base),
            colorize_bool!(self.0.force_integrity),
            colorize_bool!(self.0.gs),
            colorize_bool!(self.0.high_entropy_va),
            colorize_bool!(self.0.isolation),
            colorize_bool!(self.0.rfg),
            colorize_bool!(self.0.safeseh),
            colorize_bool!(self.0.seh)
        )
    }
}
