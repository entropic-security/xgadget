use std::fmt;
use std::fs;
use std::time::Instant;

use checksec::elf::ElfCheckSecResults;
use checksec::pe::PECheckSecResults;
use colored::Colorize;
use goblin::Object;
use rayon::prelude::*;
use regex::Regex;
use structopt::StructOpt;

mod checksec_fmt;
use checksec_fmt::{CustomElfCheckSecResults, CustomPeCheckSecResults};

#[macro_use]
extern crate lazy_static;

// CLI State -----------------------------------------------------------------------------------------------------------

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
struct CLIOpts {
    /// 1+ binaries to gadget search. If > 1: gadgets common to all
    #[structopt(required = true, min_values = 1, value_name = "FILE(S)")]
    bin_paths: Vec<String>,

    /// For raw (no header) files: specify arch ('x8086', 'x86', or 'x64')
    #[structopt(short, long, default_value = "x64", value_name = "ARCH")]
    arch: xgadget::Arch,

    /// Display gadgets using AT&T syntax [default: Intel syntax]
    #[structopt(short = "t", long)]
    att: bool,

    /// Don't color output, useful for UNIX piping [default: color output]
    #[structopt(short, long)]
    no_color: bool,

    /// Print in terminal-wide format [default: only used for partial match search]
    #[structopt(short, long)]
    extended_fmt: bool,

    /// Gadgets up to LEN instrs long. If 0: all gadgets, any length
    #[structopt(
        short = "l",
        long,
        required = false,
        default_value = "5",
        value_name = "LEN"
    )]
    max_len: usize,

    /// Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long)]
    rop: bool,

    /// Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long, conflicts_with = "rop")]
    jop: bool,

    /// Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
    #[structopt(short, long, conflicts_with = "jop")]
    sys: bool,

    /// Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
    #[structopt(long, conflicts_with = "jop")]
    inc_imm16: bool,

    /// Include gadgets containing a call [default: don't include]
    #[structopt(long)]
    inc_call: bool,

    /// Include cross-variant partial matches [default: full matches only]
    #[structopt(short = "m", long)]
    partial_match: bool,

    /// Filter to gadgets that write the stack ptr [default: all gadgets]
    #[structopt(short = "p", long)]
    stack_pivot: bool,

    /// Filter to potential JOP 'dispatcher' gadgets [default: all gadgets]
    #[structopt(short, long, conflicts_with_all = &["rop", "stack_pivot"])]
    dispatcher: bool,

    /// Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all gadgets]
    #[structopt(short = "w", long, conflicts_with = "dispatcher")]
    reg_write: bool,

    /// Filter to gadgets that don't dereference registers
    #[structopt(long)]
    no_deref: bool,

    /// Filter to gadgets whose addrs don't contain given bytes [default: all gadgets]
    #[structopt(short, long, min_values = 1, value_name = "BYTE(S)")]
    bad_bytes: Vec<String>,

    /// Filter to gadgets matching a regular expression
    #[structopt(short = "f", long = "regex-filter", value_name = "EXPR")]
    usr_regex: Option<String>,

    /// Run checksec on the 1+ binaries instead of gadget search
    #[structopt(short, long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "imm16", "partial_match",
        "stack_pivot", "dispatcher", "reg_write", "usr_regex"
    ])] // TODO: Custom short name (e.g. "-m" for "--partial-match" not tagged as conflict)
    check_sec: bool,
}

impl CLIOpts {
    // User flags -> Search config bitfield
    fn get_search_config(&self) -> xgadget::SearchConfig {
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

    // If partial match or extended format flag, addr(s) right of instr(s), else addr left of instr(s)
    fn fmt_gadget_output(&self, addrs: String, instrs: String, term_width: usize) -> String {
        let plaintext_instrs_len = strip_ansi_escapes::strip(&instrs).unwrap().len();
        let plaintext_addrs_len = strip_ansi_escapes::strip(&addrs).unwrap().len();
        let content_len = plaintext_instrs_len + plaintext_addrs_len;
        let mut output = instrs;

        if self.extended_fmt || self.partial_match {
            if term_width > content_len {
                let padding = (0..(term_width - 1 - content_len))
                    .map(|_| "-")
                    .collect::<String>();

                if self.no_color {
                    output.push_str(&padding);
                } else {
                    output.push_str(&format!("{}", padding.bright_magenta()));
                    //output.push_str(&padding.bright_magenta()); // TODO: why doesn't this color, bug?
                }
            }

            output.push_str(&format!(" {}", addrs));
        } else {
            let addr_no_bracket = &addrs[1..(addrs.len() - 1)].trim();
            output = format!("{}{} {}", addr_no_bracket, ":".bright_magenta(), output);
        }

        output
    }

    // Helper for summary print
    fn fmt_summary_item(&self, item: String, is_hdr: bool) -> colored::ColoredString {
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
    fn run_checksec(&self) {
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
                let mut search_mode = String::from("");
                if self.rop {
                    search_mode = format!("{} {}", search_mode, "ROP-only")
                };
                if self.jop {
                    search_mode = format!("{} {}", search_mode, "JOP-only")
                };
                if self.sys {
                    search_mode = format!("{} {}", search_mode, "SYS-only")
                };
                if self.stack_pivot {
                    search_mode = format!("{} {}", search_mode, "Stack-pivot-only")
                };
                if self.dispatcher {
                    search_mode = format!("{} {}", search_mode, "Dispatcher-only")
                };
                if self.reg_write {
                    search_mode = format!("{} {}", search_mode, "Register-pop-only")
                };
                if search_mode.is_empty() {
                    search_mode = String::from("ROP-JOP-SYS (default)")
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

// CLI Runner ----------------------------------------------------------------------------------------------------------

fn main() {
    let cli = CLIOpts::from_args();

    let mut filter_matches = 0;
    let filter_regex = Regex::new(
        &cli.usr_regex
            .clone()
            .unwrap_or_else(|| "unused_but_initialized".to_string())
            .trim(),
    )
    .unwrap();

    // Checksec requested ----------------------------------------------------------------------------------------------

    if cli.check_sec {
        cli.run_checksec();
        std::process::exit(0);
    }

    // Process 1+ files ------------------------------------------------------------------------------------------------

    // File paths -> Binaries
    let bins: Vec<xgadget::Binary> = cli
        .bin_paths
        .par_iter()
        .map(|path| xgadget::Binary::from_path_str(&path).unwrap())
        .map(|mut binary| {
            if binary.arch == xgadget::Arch::Unknown {
                binary.arch = cli.arch;
                assert!(
                    binary.arch != xgadget::Arch::Unknown,
                    "Please set \'--arch\' to \'x8086\' (16-bit), \'x86\' (32-bit), or \'x64\' (64-bit)"
                );
            }
            binary
        })
        .collect();

    for (i, bin) in bins.iter().enumerate() {
        println!("TARGET {} - {} ", i, bin);
    }

    // Search ----------------------------------------------------------------------------------------------------------

    let start_time = Instant::now();
    let mut gadgets = xgadget::find_gadgets(&bins, cli.max_len, cli.get_search_config()).unwrap();

    if cli.stack_pivot {
        gadgets = xgadget::filter_stack_pivot(&gadgets);
    }

    if cli.dispatcher {
        gadgets = xgadget::filter_dispatcher(&gadgets);
    }

    if cli.reg_write {
        gadgets = xgadget::filter_stack_set_regs(&gadgets);
    }

    if cli.no_deref {
        gadgets = xgadget::filter_no_deref(&gadgets);
    }

    if !cli.bad_bytes.is_empty() {
        let bytes = cli
            .bad_bytes
            .iter()
            .map(|s| s.trim_start_matches("0x"))
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect::<Vec<u8>>();

        gadgets = xgadget::filter_bad_addr_bytes(&gadgets, bytes.as_slice());
    }

    let run_time = start_time.elapsed();

    // Print Gadgets ---------------------------------------------------------------------------------------------------

    let term_width: usize = match term_size::dimensions() {
        Some((w, _)) => w,
        None => 0,
    };

    println!();
    for (instrs, addrs) in xgadget::str_fmt_gadgets(&gadgets, cli.att, !cli.no_color) {
        let plaintext_instrs_bytes = strip_ansi_escapes::strip(&instrs).unwrap();
        let plaintext_instrs_str = std::str::from_utf8(&plaintext_instrs_bytes).unwrap();

        if (cli.usr_regex.is_none()) || filter_regex.is_match(plaintext_instrs_str) {
            println!("{}", cli.fmt_gadget_output(addrs, instrs, term_width));
            if cli.usr_regex.is_some() {
                filter_matches += 1;
            }
        }
    }

    // Print Summary ---------------------------------------------------------------------------------------------------

    println!("\n{}", cli);
    println!(
        "{} [ {}: {}, search_time: {}, print_time: {} ]",
        { cli.fmt_summary_item("RESULT".to_string(), true) },
        {
            if bins.len() > 1 {
                "unique_x_variant_gadgets".to_string()
            } else {
                "unique_gadgets".to_string()
            }
        },
        {
            let found_cnt = if cli.usr_regex.is_some() {
                filter_matches.to_string()
            } else {
                gadgets.len().to_string()
            };

            cli.fmt_summary_item(found_cnt, false)
        },
        { cli.fmt_summary_item(format!("{:?}", run_time), false) },
        { cli.fmt_summary_item(format!("{:?}", start_time.elapsed() - run_time), false) }
    );
}
