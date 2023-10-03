use std::{fmt, fs, time};

use clap::{
    builder::{styling::AnsiColor, Styles},
    Parser,
};
use colored::Colorize;
use goblin::Object;
use lazy_static::lazy_static;
use num_format::{Locale, ToFormattedString};

use super::checksec_fmt::CustomCheckSecResultsDisplay;
use super::imports;

// Global CLI metadata -------------------------------------------------------------------------------------------------

lazy_static! {
    static ref VERSION_STR: String = format!("v{}", clap::crate_version!());
}

lazy_static! {
    static ref ABOUT_STR: String = format!(
        "{} v{}\n\n{}\t{}\n{}\t{} logical, {} physical",
        clap::crate_name!().cyan(),
        clap::crate_version!(),
        "About:".to_string().bright_magenta(),
        clap::crate_description!(),
        "Cores:".to_string().bright_magenta(),
        num_cpus::get().to_string().red(),
        num_cpus::get_physical().to_string().red(),
    );
}

lazy_static! {
    static ref CMD_COLOR: Styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .valid(AnsiColor::Green.on_default())
        .error(AnsiColor::Red.on_default())
        .invalid(AnsiColor::Red.on_default())
        .literal(AnsiColor::Cyan.on_default())
        .placeholder(AnsiColor::BrightBlue.on_default());
}

// Arg parse -----------------------------------------------------------------------------------------------------------

enum SummaryItemType {
    Header,
    Data,
    Separator,
}

#[derive(Parser, Debug)]
#[command(
    name = clap::crate_name!(),
    version = VERSION_STR.as_str(),
    about = ABOUT_STR.as_str(),
    term_width = 150,
    styles = CMD_COLOR.clone(),
)]
pub(crate) struct CLIOpts {
    /// 1+ binaries to gadget search. If > 1: gadgets common to all
    #[arg(required = true, num_args = 1.., value_name = "FILE(S)")]
    pub(crate) bin_paths: Vec<String>,

    /// For raw (no header) files: specify arch ('x8086', 'x86', or 'x64')
    #[arg(short, long, default_value = "x64", value_name = "ARCH")]
    pub(crate) arch: xgadget::Arch,

    /// Display gadgets using AT&T syntax [default: Intel syntax]
    #[arg(short = 't', long)]
    pub(crate) att: bool,

    /// Don't color output [default: color output]
    #[arg(short, long)]
    pub(crate) no_color: bool,

    /// Print in terminal-wide format [default: only used for partial match search]
    #[arg(short, long)]
    pub(crate) extended_fmt: bool,

    /// Gadgets up to LEN instrs long. If 0: all gadgets, any length
    #[arg(
        short = 'l',
        long,
        required = false,
        default_value = "5",
        value_name = "LEN"
    )]
    pub(crate) max_len: usize,

    /// Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
    #[arg(short, long)]
    pub(crate) rop: bool,

    /// Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
    #[arg(short, long, conflicts_with = "rop")]
    pub(crate) jop: bool,

    /// Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
    #[arg(short, long, conflicts_with = "jop")]
    pub(crate) sys: bool,

    /// Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
    #[arg(long, conflicts_with = "jop")]
    pub(crate) inc_imm16: bool,

    /// Include gadgets containing a call [default: don't include]
    #[arg(long)]
    pub(crate) inc_call: bool,

    /// Include cross-variant partial matches [default: full matches only]
    #[arg(short = 'm', long)]
    pub(crate) partial_match: bool,

    /// Filter to gadgets that write the stack ptr [default: all]
    #[arg(short = 'p', long)]
    pub(crate) stack_pivot: bool,

    /// Filter to potential JOP 'dispatcher' gadgets [default: all]
    #[arg(short, long, conflicts_with_all = &["rop", "stack_pivot"])]
    pub(crate) dispatcher: bool,

    /// Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all]
    #[arg(long, conflicts_with = "dispatcher")]
    pub(crate) reg_pop: bool,

    /// Filter to gadgets that don't deref any regs or a specific reg [default: all]
    #[arg(long, value_name = "OPT_REG")]
    pub(crate) no_deref: Option<Option<String>>,

    /// Filter to gadgets that control any reg or a specific reg [default: all]
    #[arg(long, value_name = "OPT_REG")]
    pub(crate) reg_ctrl: Option<Option<String>>,

    /// Filter to gadgets that control function parameters [default: all]
    #[arg(long)]
    pub(crate) param_ctrl: bool,

    /// Filter to gadgets whose addrs don't contain given bytes [default: all]
    #[arg(short, long, num_args = 1.., value_name = "BYTE(S)")]
    pub(crate) bad_bytes: Vec<String>,

    /// Filter to gadgets matching a regular expression
    #[arg(short = 'f', long = "regex_filter", value_name = "EXPR")]
    pub(crate) usr_regex: Option<String>,

    /// Run checksec on the 1+ binaries instead of gadget search
    #[arg(short, long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "inc_imm16", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "fess", "imports"
    ])]
    pub(crate) check_sec: bool,

    // TODO: conflict list gen by removal
    /// Compute Fast Exploit Similarity Score (FESS) table for 2+ binaries
    #[arg(long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "inc_imm16", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "check_sec", "imports"
    ])]
    pub(crate) fess: bool,

    /// List the imported symbols in the binary
    #[arg(long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "inc_imm16", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "check_sec", "fess"
    ])]
    pub(crate) imports: bool,
}

impl CLIOpts {
    // User flags -> Search config bitfield
    pub(crate) fn get_search_config(&self) -> xgadget::SearchConfig {
        let mut search_config = xgadget::SearchConfig::DEFAULT;

        // Add to default
        if self.partial_match {
            search_config |= xgadget::SearchConfig::PART;
        }
        if self.inc_imm16 {
            search_config |= xgadget::SearchConfig::IMM16;
        }
        if self.inc_call {
            search_config |= xgadget::SearchConfig::CALL;
        }

        // Subtract from default
        if self.rop {
            assert!(
                search_config.intersects(xgadget::SearchConfig::JOP | xgadget::SearchConfig::SYS)
            );
            search_config = search_config - xgadget::SearchConfig::JOP - xgadget::SearchConfig::SYS;
        }
        if self.jop {
            assert!(
                search_config.intersects(xgadget::SearchConfig::ROP | xgadget::SearchConfig::SYS)
            );
            search_config = search_config - xgadget::SearchConfig::ROP - xgadget::SearchConfig::SYS;
        }
        if self.sys {
            assert!(
                search_config.intersects(xgadget::SearchConfig::ROP | xgadget::SearchConfig::JOP)
            );
            search_config = search_config - xgadget::SearchConfig::ROP - xgadget::SearchConfig::JOP;
        }

        search_config
    }

    // Helper for computing FESS on requested binaries
    pub(crate) fn run_fess(&self, bins: &[xgadget::Binary]) {
        if bins.len() < 2 {
            panic!("--fess flag requires 2+ binaries!");
        }

        println!(
            "\n{}",
            xgadget::fess::gen_fess_tbl(
                bins,
                self.max_len,
                self.get_search_config(),
                !self.no_color
            )
            .unwrap()
        );
    }

    // Helper for running checksec on requested binaries
    pub(crate) fn run_checksec(&self) {
        for path in &self.bin_paths {
            println!(
                "\n{}:",
                self.fmt_summary_item(path.to_string(), SummaryItemType::Data)
            );
            let buf = fs::read(path).unwrap();
            println!(
                "{}",
                CustomCheckSecResultsDisplay::new(&buf, path, self.no_color)
            );
        }
    }

    // Helper for printing imports from requested binaries
    pub(crate) fn run_imports(&self, bins: &[xgadget::Binary]) {
        for (idx, path) in self.bin_paths.iter().enumerate() {
            println!(
                "\nTARGET {} - {} \n",
                {
                    match self.no_color {
                        true => format!("{}", idx).normal(),
                        false => format!("{}", idx).red(),
                    }
                },
                bins[idx]
            );

            // Binaries get reparsed here. This could be eliminated by adding symbol data
            // to the Binary struct
            let buf = fs::read(path).unwrap();
            match Object::parse(&buf).unwrap() {
                Object::Elf(elf) => imports::dump_elf_imports(&elf, self.no_color),
                Object::PE(pe) => imports::dump_pe_imports(&pe, self.no_color),
                Object::Mach(mach) => match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        imports::dump_macho_imports(&macho, self.no_color)
                    }
                    goblin::mach::Mach::Fat(fat) => {
                        let macho = xgadget::get_supported_macho(&fat).unwrap();
                        imports::dump_macho_imports(&macho, self.no_color)
                    }
                },
                _ => panic!("Only ELF, PE, and Mach-O binaries currently supported!"),
            }
        }
    }

    pub(crate) fn fmt_perf_result(
        &self,
        bin_cnt: usize,
        found_cnt: usize,
        start_time: time::Instant,
        run_time: time::Duration,
    ) -> String {
        let pipe_sep = self.fmt_summary_item("|".to_string(), SummaryItemType::Separator);
        format!(
            "{} {} {}: {} {pipe_sep} search_time: {} {pipe_sep} print_time: {} {}",
            { self.fmt_summary_item("RESULT".to_string(), SummaryItemType::Header) },
            self.fmt_summary_item("[".to_string(), SummaryItemType::Separator),
            {
                if bin_cnt > 1 {
                    "unique_x_variant_gadgets".to_string()
                } else {
                    "unique_gadgets".to_string()
                }
            },
            self.fmt_summary_item(
                found_cnt.to_formatted_string(&Locale::en),
                SummaryItemType::Data
            ),
            { self.fmt_summary_item(format!("{:?}", run_time), SummaryItemType::Data) },
            {
                self.fmt_summary_item(
                    format!("{:?}", start_time.elapsed() - run_time),
                    SummaryItemType::Data,
                )
            },
            self.fmt_summary_item("]".to_string(), SummaryItemType::Separator),
        )
    }

    // Helper for summary print
    fn fmt_summary_item(&self, item: String, ty: SummaryItemType) -> colored::ColoredString {
        match self.no_color {
            true => item.trim().normal(),
            false => match ty {
                SummaryItemType::Header => item.trim().red(),
                SummaryItemType::Data => item.trim().bright_blue(),
                SummaryItemType::Separator => item.trim().bright_magenta(),
            },
        }
    }
}

impl fmt::Display for CLIOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pipe_sep = self.fmt_summary_item("|".to_string(), SummaryItemType::Separator);
        write!(
            f,
            "{} {} search: {} {pipe_sep} x_match: {} {pipe_sep} max_len: {} {pipe_sep} syntax: {} {pipe_sep} regex_filter: {} {}",
            { self.fmt_summary_item("CONFIG".to_string(), SummaryItemType::Header) },
            self.fmt_summary_item("[".to_string(), SummaryItemType::Separator),
            {
                let mut search_mode = String::from("ROP-JOP-SYS (default)");
                if self.rop {
                    search_mode = String::from("ROP-only");
                };
                if self.jop {
                    search_mode = String::from("JOP-only");
                };
                if self.sys {
                    search_mode = String::from("SYS-only");
                };
                if self.stack_pivot {
                    search_mode = String::from("Stack-pivot-only");
                };
                if self.dispatcher {
                    search_mode = String::from("Dispatcher-only");
                };
                if self.reg_pop {
                    search_mode = String::from("Register-pop-only");
                };
                if self.param_ctrl {
                    search_mode = String::from("Param-ctrl-only");
                };
                if let Some(opt_reg) = &self.reg_ctrl {
                    match opt_reg {
                        Some(reg) => {
                            search_mode = format!("Reg-ctrl-{}-only", reg.to_lowercase());
                        }
                        None => {
                            search_mode = String::from("Reg-ctrl-only");
                        }
                    }
                };
                if let Some(opt_reg) = &self.no_deref {
                    match opt_reg {
                        Some(reg) => {
                            search_mode = format!("No-deref-{}-only", reg.to_lowercase());
                        }
                        None => {
                            search_mode = String::from("No-deref-only");
                        }
                    }
                };
                self.fmt_summary_item(search_mode, SummaryItemType::Data)
            },
            {
                let x_match = if self.bin_paths.len() == 1 {
                    "none"
                } else if self.partial_match {
                    "full-and-partial"
                } else {
                    "full"
                };

                self.fmt_summary_item(x_match.to_string(), SummaryItemType::Data)
            },
            { self.fmt_summary_item(format!("{}", self.max_len), SummaryItemType::Data) },
            {
                let syntax = if self.att { "AT&T" } else { "Intel" };

                self.fmt_summary_item(syntax.to_string(), SummaryItemType::Data)
            },
            {
                let regex = if self.usr_regex.is_some() {
                    format!("\'{}\'", self.usr_regex.clone().unwrap())
                } else {
                    String::from("none")
                };

                self.fmt_summary_item(regex, SummaryItemType::Data)
            },
            "]".to_string().bright_magenta(),
        )
    }
}
