use std::fmt;
use std::fs;

use checksec::elf::ElfCheckSecResults;
use checksec::pe::PECheckSecResults;
use colored::Colorize;
use goblin::Object;
use structopt::StructOpt;

use super::checksec_fmt::{CustomElfCheckSecResults, CustomPeCheckSecResults};

lazy_static! {
    static ref ABOUT_STR: String = format!(
        "\nAbout:\t{}\nCores:\t{} logical, {} physical",
        structopt::clap::crate_description!(),
        num_cpus::get(),
        num_cpus::get_physical(),
    );
}

lazy_static! {
    static ref VERSION_STR: String = format!("v{}", structopt::clap::crate_version!());
}

#[derive(StructOpt, Debug)]
#[structopt(name = "xgadget", version = VERSION_STR.as_str(), about = ABOUT_STR.as_str())]
pub(crate) struct CLIOpts {
    /// 1+ binaries to gadget search. If > 1: gadgets common to all
    #[structopt(required = true, min_values = 1, value_name = "FILE(S)")]
    pub(crate) bin_paths: Vec<String>,

    /// For raw (no header) files: specify arch ('x8086', 'x86', or 'x64')
    #[structopt(short, long, default_value = "x64", value_name = "ARCH")]
    pub(crate) arch: xgadget::Arch,

    /// Display gadgets using AT&T syntax [default: Intel syntax]
    #[structopt(short = "t", long)]
    pub(crate) att: bool,

    /// Don't color output, useful for UNIX piping [default: color output]
    #[structopt(short, long)]
    pub(crate) no_color: bool,

    /// Print in terminal-wide format [default: only used for partial match search]
    #[structopt(short, long)]
    pub(crate) extended_fmt: bool,

    /// Gadgets up to LEN instrs long. If 0: all gadgets, any length
    #[structopt(
        short = "l",
        long,
        required = false,
        default_value = "5",
        value_name = "LEN"
    )]
    pub(crate) max_len: usize,

    /// Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long)]
    pub(crate) rop: bool,

    /// Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long, conflicts_with = "rop")]
    pub(crate) jop: bool,

    /// Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long, conflicts_with = "jop")]
    pub(crate) sys: bool,

    /// Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
    #[structopt(long, conflicts_with = "jop")]
    pub(crate) inc_imm16: bool,

    /// Include gadgets containing a call [default: don't include]
    #[structopt(long)]
    pub(crate) inc_call: bool,

    /// Include cross-variant partial matches [default: full matches only]
    #[structopt(short = "m", long)]
    pub(crate) partial_match: bool,

    /// Filter to gadgets that write the stack ptr [default: all gadgets]
    #[structopt(short = "p", long)]
    pub(crate) stack_pivot: bool,

    /// Filter to potential JOP 'dispatcher' gadgets [default: all gadgets]
    #[structopt(short, long, conflicts_with_all = &["rop", "stack_pivot"])]
    pub(crate) dispatcher: bool,

    /// Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all gadgets]
    #[structopt(long, conflicts_with = "dispatcher")]
    pub(crate) reg_pop: bool,

    /// Filter to gadgets that don't deref any regs or a specific reg [default: all gadgets]
    #[structopt(long, value_name = "OPT_REG")]
    pub(crate) no_deref: Option<Option<String>>,

    /// Filter to gadgets that control any reg or a specific reg [default: all gadgets]
    #[structopt(long, value_name = "OPT_REG")]
    pub(crate) reg_ctrl: Option<Option<String>>,

    /// Filter to gadgets that control function parameters [default: all gadgets]
    #[structopt(long)]
    pub(crate) param_ctrl: bool,

    /// Filter to gadgets whose addrs don't contain given bytes [default: all gadgets]
    #[structopt(short, long, min_values = 1, value_name = "BYTE(S)")]
    pub(crate) bad_bytes: Vec<String>,

    /// Filter to gadgets matching a regular expression
    #[structopt(short = "f", long = "regex-filter", value_name = "EXPR")]
    pub(crate) usr_regex: Option<String>,

    /// Run checksec on the 1+ binaries instead of gadget search
    #[structopt(short, long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "imm16", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex"
    ])]
    // TODO: Custom short name (e.g. "-m" for "--partial-match" not tagged as conflict) - why?
    pub(crate) check_sec: bool,
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

    // Helper for summary print
    pub(crate) fn fmt_summary_item(&self, item: String, is_hdr: bool) -> colored::ColoredString {
        let hdr = |s: String| {
            if self.no_color {
                s.trim().normal()
            } else {
                s.trim().bright_magenta()
            }
        };

        let param = |s: String| {
            if self.no_color {
                s.trim().normal()
            } else {
                s.trim().bright_blue()
            }
        };

        match is_hdr {
            true => hdr(item),
            false => param(item),
        }
    }

    // Helper for running checksec on requested binaries
    pub(crate) fn run_checksec(&self) {
        for path in &self.bin_paths {
            println!("\n{}:", self.fmt_summary_item(path.to_string(), false));
            let buf = fs::read(path).unwrap();
            match Object::parse(&buf).unwrap() {
                Object::Elf(elf) => {
                    println!(
                        "{}",
                        CustomElfCheckSecResults(ElfCheckSecResults::parse(&elf))
                    );
                }
                Object::PE(pe) => {
                    let mm_buf =
                        unsafe { memmap::Mmap::map(&fs::File::open(path).unwrap()).unwrap() };
                    println!(
                        "{}",
                        CustomPeCheckSecResults(PECheckSecResults::parse(&pe, &mm_buf))
                    );
                }
                _ => panic!("Only ELF and PE checksec currently supported!"),
            }
        }
    }
}

impl fmt::Display for CLIOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [ search: {}, x_match: {}, max_len: {}, syntax: {}, regex_filter: {} ]",
            { self.fmt_summary_item("CONFIG".to_string(), true) },
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
                self.fmt_summary_item(search_mode, false)
            },
            {
                let x_match = if self.bin_paths.len() == 1 {
                    "none"
                } else if self.partial_match {
                    "full-and-partial"
                } else {
                    "full"
                };

                self.fmt_summary_item(x_match.to_string(), false)
            },
            { self.fmt_summary_item(format!("{}", self.max_len), false) },
            {
                let syntax = if self.att { "AT&T" } else { "Intel" };

                self.fmt_summary_item(syntax.to_string(), false)
            },
            {
                let regex = if self.usr_regex.is_some() {
                    format!("\'{}\'", self.usr_regex.clone().unwrap())
                } else {
                    String::from("none")
                };

                self.fmt_summary_item(regex, false)
            },
        )
    }
}
