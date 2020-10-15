use std::time::Instant;

use colored::Colorize;
use rayon::prelude::*;
use regex::Regex;
use structopt::StructOpt;

#[macro_use]
extern crate lazy_static;

// CLI State -----------------------------------------------------------------------------------------------------------

lazy_static! {
    static ref ABOUT_STR: String = format!(
        "\nAbout:\t{}\nCPUs:\t{} logical, {} physical",
        structopt::clap::crate_description!(),
        num_cpus::get(),
        num_cpus::get_physical(),
    );
}

lazy_static! {
    static ref VERSION_STR: String = format!("v{}", structopt::clap::crate_version!());
}

lazy_static! {
    static ref TERM_WIDTH: usize = match term_size::dimensions() {
        Some((w, _)) => w,
        None => 0,
    };
}

#[derive(StructOpt, Debug)]
#[structopt(name = "xgadget", version = VERSION_STR.as_str(), about = ABOUT_STR.as_str())]
struct CLIOpts {
    /// 1+ binaries to gadget search. If > 1: gadgets common to all
    #[structopt(required = true, min_values = 1, value_name = "FILE(S)")]
    bin_paths: Vec<String>,

    /// For raw (no header) files: assume x86 (32-bit) [default: assumes x64 (64-bit)]
    #[structopt(short, long)]
    x86: bool,

    /// For raw (no header) files: assume 8086 (16-bit) [default: assumes x64 (64-bit)]
    #[structopt(short = "8", long = "8086", conflicts_with = "x86")]
    x8086: bool,

    /// Display gadgets using AT&T syntax [default: Intel syntax]
    #[structopt(short = "t", long)]
    att: bool,

    /// Don't color output, useful for UNIX piping [default: color output]
    #[structopt(short, long)]
    no_color: bool,

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
    #[structopt(short, long, conflicts_with = "jop")]
    imm16: bool,

    /// Include cross-variant partial matches [default: full matches only]
    #[structopt(short = "m", long)]
    partial_match: bool,

    /// Filter to gadgets that write the stack ptr [default: all gadgets]
    #[structopt(short = "p", long)]
    stack_pivot: bool,

    /// Filter to potential JOP 'dispatcher' gadgets [default: all gadgets]
    #[structopt(short, long, conflicts_with = "stack_pivot")]
    dispatcher: bool,

    /// Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all gadgets]
    #[structopt(short = "c", long, conflicts_with = "dispatcher")]
    reg_ctrl: bool,

    /// Filter to gadgets matching a regular expression
    #[structopt(short = "f", long = "regex-filter", value_name = "EXPR")]
    usr_regex: Option<String>,
}

impl CLIOpts {
    // TODO: switch to --arch flag and enum!
    // User flag -> bin.arch for raw files (no headers)
    fn set_arch_raw(&self, mut bin: xgadget::Binary) -> xgadget::Binary {
        if bin.arch == xgadget::Arch::Unknown {
            assert!(!(self.x8086 && self.x86));
            if self.x8086 {
                bin.arch = xgadget::Arch::X8086;
            } else if self.x86 {
                bin.arch = xgadget::Arch::X86;
            } else {
                bin.arch = xgadget::Arch::X64;
            }
        }

        bin
    }

    // User flags -> Search config bitfield
    fn get_search_config(&self) -> xgadget::SearchConfig {
        let mut search_config = xgadget::SearchConfig::DEFAULT;

        // Add to default
        if self.partial_match {
            search_config |= xgadget::SearchConfig::PART;
        }
        if self.imm16 {
            search_config |= xgadget::SearchConfig::IMM16;
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

    // TODO: flag -e, --extended-fmt
    // If partial match, addr(s) right of instr(s), else addr left of instr(s)
    fn fmt_gadget_output(&self, addrs: String, instrs: String) -> String {
        let mut output;
        let plaintext_instrs_len = strip_ansi_escapes::strip(&instrs).unwrap().len();
        let plaintext_addrs_len = strip_ansi_escapes::strip(&addrs).unwrap().len();
        let content_len = plaintext_instrs_len + plaintext_addrs_len;
        let term_width = *TERM_WIDTH;

        if self.partial_match {
            output = format!("{}", instrs);

            if term_width > content_len {
                let padding = (0..(term_width - 1 - content_len))
                    .map(|_| "-")
                    .collect::<String>();
                output.push_str(&format!("{}", padding.bright_magenta()));
                //output.push_str(&padding.bright_magenta()); // TODO: why doesn't this color, bug?
            }

            output.push_str(&format!(" {}", addrs));
        } else {
            let addr_no_bracket = &addrs[1..(addrs.len() - 1)].trim();
            output = format!("{}{} {}", addr_no_bracket, ":".bright_magenta(), instrs);
        }

        output
    }
}

impl std::fmt::Display for CLIOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = |s: String| {
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

        write!(
            f,
            "{} [ search: {}, x_match: {}, max_len: {}, syntax: {}, regex_filter: {} ]",
            { header("SUMMARY".to_string()) },
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
                if self.reg_ctrl {
                    search_mode = format!("{} {}", search_mode, "Register-control-only")
                };
                if search_mode.is_empty() {
                    search_mode = String::from("ROP-JOP-SYS (default)")
                };

                param(search_mode)
            },
            {
                let x_match = if self.bin_paths.len() == 1 {
                    "none"
                } else if self.partial_match {
                    "full-and-partial"
                } else {
                    "full"
                };

                param(x_match.to_string())
            },
            { param(format!("{}", self.max_len)) },
            {
                let syntax = if self.att { "AT&T" } else { "Intel" };

                param(syntax.to_string())
            },
            {
                let regex = if self.usr_regex.is_some() {
                    format!("\'{}\'", self.usr_regex.clone().unwrap())
                } else {
                    String::from("none")
                };

                param(regex)
            },
        )
    }
}

// CLI Runner ----------------------------------------------------------------------------------------------------------

fn main() {
    let cli = CLIOpts::from_args();

    #[allow(clippy::trivial_regex)]
    let mut filter_regex = Regex::new("unused_but_initialized").unwrap();
    let mut filter_matches = 0;
    if cli.usr_regex.is_some() {
        filter_regex = Regex::new(cli.usr_regex.clone().unwrap().trim()).unwrap();
    }

    // Process 1+ files ------------------------------------------------------------------------------------------------

    // File paths -> Binaries
    let bins: Vec<xgadget::Binary> = cli
        .bin_paths
        .par_iter()
        .map(|path| xgadget::Binary::from_path_str(&path).unwrap())
        .map(|binary| cli.set_arch_raw(binary))
        .collect();

    for (i, bin) in bins.iter().enumerate() {
        println!("TARGET {} - {} ", i, bin);
    }

    // Search ----------------------------------------------------------------------------------------------------------

    let start_time = Instant::now();
    // TO
    let mut gadgets = xgadget::find_gadgets(&bins, cli.max_len, cli.get_search_config()).unwrap();

    if cli.stack_pivot {
        gadgets = xgadget::filter_stack_pivot(&gadgets);
    }

    if cli.dispatcher {
        gadgets = xgadget::filter_dispatcher(&gadgets);
    }

    if cli.reg_ctrl {
        gadgets = xgadget::filter_stack_set_regs(&gadgets);
    }

    let run_time = start_time.elapsed();

    // Print Gadgets ---------------------------------------------------------------------------------------------------

    println!();
    for (instrs, addrs) in xgadget::str_fmt_gadgets(&gadgets, cli.att, !cli.no_color).unwrap() {
        let plaintext_instrs_bytes = strip_ansi_escapes::strip(&instrs).unwrap();
        let plaintext_instrs_str = std::str::from_utf8(&plaintext_instrs_bytes).unwrap();

        if (cli.usr_regex.is_none()) || filter_regex.is_match(plaintext_instrs_str) {
            println!("{}", cli.fmt_gadget_output(addrs, instrs));
            if cli.usr_regex.is_some() {
                filter_matches += 1;
            }
        }
    }

    // Print Summary ---------------------------------------------------------------------------------------------------

    // TODO: change format to match summary Display trait
    println!("\n{}", cli);
    if bins.len() > 1 {
        println!(
            "{:.<40} {:?}",
            "Unique cross-variant gadgets found ",
            gadgets.len()
        );
    } else {
        println!(
            "{:.<40} {:?}",
            "Unique gadgets found ",
            if cli.usr_regex.is_some() {
                filter_matches
            } else {
                gadgets.len()
            }
        );
    }

    println!("{:.<40} {:?}", "Search/filter time ", run_time);
    println!(
        "{:.<40} {:?}",
        "Print time ",
        start_time.elapsed() - run_time
    );
}
