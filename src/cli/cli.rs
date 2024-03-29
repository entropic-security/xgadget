use std::{fmt, fs, time};

use clap::{Args, Parser};
use colored::{ColoredString, Colorize};
use goblin::Object;
use num_format::{Locale, ToFormattedString};
use rayon::prelude::*;
use rustc_hash::FxHashSet as HashSet;

use super::{checksec_fmt::CustomCheckSecResults, symbols};
use crate::{str_fmt::*, Gadget};

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
    next_line_help = false,
)]
pub(crate) struct CLIOpts {
    // Internal state --------------------------------------------------------------------------------------------------

    // Set via `Self::parse_binaries`
    // `CLIOpts` shouldn't re-{read,parse} binaries from `self.bin_paths` to `Display` this info
    #[arg(skip)]
    pub(crate) processed_arches: HashSet<xgadget::Arch>,

    // Parsed args -----------------------------------------------------------------------------------------------------
    #[arg(help = HELP_BIN_PATHS.as_str(), required = true, num_args = 1.., value_name = "FILE(S)")]
    pub(crate) bin_paths: Vec<String>,

    #[arg(help = HELP_ROP.as_str(), short, long)]
    pub(crate) rop: bool,

    #[arg(help = HELP_JOP.as_str(), short, long, conflicts_with = "rop")]
    pub(crate) jop: bool,

    #[arg(help = HELP_SYS.as_str(), short, long, conflicts_with = "jop")]
    pub(crate) sys: bool,

    #[arg(
        help = HELP_MAX_LEN.as_str(),
        short = 'l',
        long,
        required = false,
        default_value = "5",
        value_name = "LEN",
        env = "XGADGET_LEN"
    )]
    pub(crate) max_len: usize,

    #[arg(help = HELP_ALL.as_str(), long)]
    pub(crate) all: bool,

    #[arg(help = HELP_USER_REGEX.as_str(), short = 'f', long = "regex-filter", value_name = "EXPR")]
    pub(crate) usr_regex: Option<String>,

    #[command(flatten)]
    pub(crate) reg: ArgGroupRegSensitve,

    #[arg(help = HELP_PARAM_CTRL.as_str(), long)]
    pub(crate) param_ctrl: bool,

    #[arg(help = HELP_STACK_PIVOT.as_str(), short = 'p', long)]
    pub(crate) stack_pivot: bool,

    #[arg(help = HELP_DISPATCHER.as_str(), short, long, conflicts_with_all = &["rop", "stack_pivot"])]
    pub(crate) dispatcher: bool,

    #[arg(help = HELP_PARTIAL_MACH.as_str(), short = 'm', long)]
    pub(crate) partial_match: bool,

    #[arg(help = HELP_ARCH.as_str(), short, long, default_value = "x64", value_name = "ARCH", env = "XGADGET_ARCH")]
    pub(crate) arch: xgadget::Arch,

    #[arg(help = HELP_BAD_BYTES.as_str(), short, long, num_args = 1.., value_name = "BYTE(S)")]
    pub(crate) bad_bytes: Vec<String>,

    #[arg(help = HELP_CHECKSEC.as_str(), short, long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "fess", "symbols"
    ])]
    pub(crate) check_sec: bool,

    // TODO: conflict list gen by removal
    #[arg(help = HELP_FESS.as_str(), long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "check_sec", "symbols"
    ])]
    pub(crate) fess: bool,

    #[arg(help = HELP_SYMBOLS.as_str(), long, conflicts_with_all = &[
        "arch", "att", "extended_fmt", "max_len",
        "rop", "jop", "sys", "partial_match",
        "stack_pivot", "dispatcher", "reg_pop", "usr_regex", "check_sec", "fess"
    ])]
    pub(crate) symbols: bool,

    #[arg(help = HELP_ATT.as_str(), short = 't', long)]
    pub(crate) att: bool,

    #[arg(help = HELP_EXTENDED_FMT.as_str(), short, long)]
    pub(crate) extended_fmt: bool,
}

#[derive(Args, Debug)]
#[group(id = "Register Sensitive")]
pub(crate) struct ArgGroupRegSensitve {
    // Behavior filters ------------------------------------------------------------------------------------------------
    #[arg(help = HELP_REG_OVERWRITE.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_overwrite: Vec<String>,

    #[arg(help = HELP_REG_MEM_WRITE.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_mem_write: Vec<String>,

    #[arg(help = HELP_REG_NO_WRITE.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_no_write: Vec<String>,

    #[arg(help = HELP_REG_READ.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_read: Vec<String>,

    #[arg(help = HELP_REG_MEM_READ.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_mem_read: Vec<String>,

    #[arg(help = HELP_REG_NO_READ.as_str(), long, num_args = 0.., value_name = "OPT_REG(S)")]
    pub(crate) reg_no_read: Vec<String>,

    // Modifiers -------------------------------------------------------------------------------------------------------
    #[arg(help = HELP_REG_POP.as_str(), long, conflicts_with = "dispatcher")]
    pub(crate) reg_pop: bool,

    #[arg(help = HELP_REG_ONLY.as_str(), long)]
    pub(crate) reg_only: bool,
}

impl CLIOpts {
    // CLI Crate API ---------------------------------------------------------------------------------------------------

    // Parse input binaries.
    // This has the important side-effect of updating data used for `Display`.
    pub(crate) fn parse_binaries(&mut self) -> Vec<xgadget::Binary> {
        let bins: Vec<xgadget::Binary> = self.bin_paths
            .par_iter()
            .map(|path| xgadget::Binary::from_path(path).unwrap())
            .map(|mut binary| {
                if binary.arch() == xgadget::Arch::Unknown {
                    binary.set_arch(self.arch); // Set user value if cannot auto-determine
                    assert!(
                        binary.arch() != xgadget::Arch::Unknown,
                        "Please set \'--arch\' to \'x8086\' (16-bit), \'x86\' (32-bit), or \'x64\' (64-bit). \
                        It couldn't be determined automatically."
                    );
                }
                binary
            })
            .collect();

        self.processed_arches = bins.iter().map(|b| b.arch()).collect::<HashSet<_>>();

        bins
    }

    // User flags -> Search config bitfield
    pub(crate) fn get_search_config(&self) -> xgadget::SearchConfig {
        let mut search_config = xgadget::SearchConfig::default();

        // Add to default
        if self.partial_match {
            search_config |= xgadget::SearchConfig::PART;
        }
        if self.all {
            search_config |= xgadget::SearchConfig::ALL;
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
    pub(crate) fn run_fess(&self, bins: &[xgadget::Binary]) -> usize {
        if bins.len() < 2 {
            panic!("\'--fess\' flag requires 2+ binaries!");
        }

        let (tbl, cnt) =
            xgadget::fess::gen_fess_tbl(bins, self.max_len, self.get_search_config()).unwrap();
        println!("\n{}\n", tbl);

        cnt
    }

    // Helper for running checksec on requested binaries
    pub(crate) fn run_checksec(&self, bins: &[xgadget::Binary]) {
        for bin in bins {
            if let Some((path, Some(path_str))) = bin.path().map(|p| (p, p.as_os_str().to_str())) {
                println!(
                    "\n{}\n\t{}:",
                    self.fmt_summary_item(&path.display().to_string(), SummaryItemType::Data),
                    bin,
                );
                let buf = fs::read(path).unwrap();

                for res in CustomCheckSecResults::new(&buf, path_str) {
                    print!("{}\n\n", res);
                }

                debug_assert!(self
                    .bin_paths
                    .iter()
                    .map(std::path::PathBuf::from)
                    .collect::<Vec<_>>()
                    .contains(&std::path::PathBuf::from(path)));
            }
        }
    }

    // Helper for printing imports from requested binaries
    pub(crate) fn run_symbols(&self, bins: &[xgadget::Binary]) {
        for (idx, path) in self.bin_paths.iter().enumerate() {
            println!("\nTARGET {} - {} \n", format!("{}", idx).red(), bins[idx]);

            // Binaries get reparsed here. This could be eliminated by adding symbol data
            // to the Binary struct
            let buf = fs::read(path).unwrap();
            match Object::parse(&buf).unwrap() {
                // TODO: update imports to remove no-color
                Object::Elf(elf) => symbols::dump_elf_imports(&elf),
                Object::PE(pe) => symbols::dump_pe_imports(&pe),
                Object::Mach(mach) => match mach {
                    goblin::mach::Mach::Binary(macho) => symbols::dump_macho_imports(&macho),
                    goblin::mach::Mach::Fat(fat) => {
                        let macho = xgadget::get_supported_macho(&fat).unwrap();
                        symbols::dump_macho_imports(&macho)
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
        let pipe_sep = self.fmt_summary_item("|", SummaryItemType::Separator);
        let colon = self.fmt_summary_item(":", SummaryItemType::Separator);
        format!(
            "{} {} {}{colon} {} {pipe_sep} search_time{colon} \
            {} {pipe_sep} print_time{colon} {} {}",
            { self.fmt_summary_item("RESULT", SummaryItemType::Header) },
            self.fmt_summary_item("[", SummaryItemType::Separator),
            {
                if bin_cnt > 1 {
                    "unique_x_variant_gadgets"
                } else {
                    "unique_gadgets"
                }
            },
            self.fmt_summary_item(
                &found_cnt.to_formatted_string(&Locale::en),
                SummaryItemType::Data
            ),
            { self.fmt_summary_item(&format!("{:?}", run_time), SummaryItemType::Data) },
            {
                self.fmt_summary_item(
                    &format!("{:?}", start_time.elapsed() - run_time),
                    SummaryItemType::Data,
                )
            },
            self.fmt_summary_item("]", SummaryItemType::Separator),
        )
    }

    // CLI Private API -------------------------------------------------------------------------------------------------

    // Helper for summary print
    fn fmt_summary_item(&self, item: &str, ty: SummaryItemType) -> colored::ColoredString {
        match ty {
            SummaryItemType::Header => item.trim().bold().red(),
            SummaryItemType::Data => item.trim().bold().bright_blue(),
            SummaryItemType::Separator => item.trim().bold().bright_magenta(),
        }
    }
}

impl fmt::Display for CLIOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pipe_sep = self.fmt_summary_item("|", SummaryItemType::Separator);
        let comma_sep = self.fmt_summary_item(",", SummaryItemType::Separator);
        let colon = self.fmt_summary_item(":", SummaryItemType::Separator);
        write!(
            f,
            "{} {} arch{colon} {} {pipe_sep} search{colon} {} {pipe_sep} max_len{colon} \
            {} {pipe_sep} syntax{colon} {} {pipe_sep} regex{colon} {} {pipe_sep} x_match{colon} {} {}",
            { self.fmt_summary_item("CONFIG", SummaryItemType::Header) },
            self.fmt_summary_item("[", SummaryItemType::Separator),
            {
                if !self.processed_arches.is_empty() {
                    cli_rule_fmt(
                        &self.processed_arches.iter().map(|a| format!("{}", a))
                            .collect::<Vec<_>>()
                            .join(&comma_sep),
                        false,
                        false,
                    )
                } else {
                    self.fmt_summary_item("undetermined", SummaryItemType::Data).to_string()
                }
            },
            {
                let mut search_mode = if !self.rop && !self.jop && !self.sys {
                    vec!["ROP", "JOP", "SYS"] // Default search config
                } else {
                    Vec::new()
                };

                if self.rop {
                    search_mode.push("ROP");
                };
                if self.jop {
                    search_mode.push("JOP");
                };
                if self.sys {
                    search_mode.push("SYS");
                };
                if self.stack_pivot {
                    search_mode.push("Stack-pivot");
                };
                if self.dispatcher {
                    search_mode.push("Dispatcher");
                };
                if self.reg.reg_pop {
                    search_mode.push("Reg-pop");
                };
                if self.reg.reg_only {
                    search_mode.push("Reg-only");
                };
                if self.param_ctrl {
                    search_mode.push("Param-ctrl");
                };
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_OVERWRITE_FLAG, &self.reg.reg_overwrite, "Reg-overwrite", &comma_sep);
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_MEM_WRITE_FLAG, &self.reg.reg_mem_write, "Reg-mem-write", &comma_sep);
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_NO_WRITE_FLAG, &self.reg.reg_no_write, "Reg-no-write", &comma_sep);
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_READ_FLAG, &self.reg.reg_read, "Reg-read", &comma_sep);
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_MEM_READ_FLAG, &self.reg.reg_mem_read, "Reg-mem-read", &comma_sep);
                fmt_append_reg_sensitive_flag(&mut search_mode, REG_NO_READ_FLAG, &self.reg.reg_no_read, "Reg-no-read", &comma_sep);
                cli_rule_fmt(
                    &self.fmt_summary_item(&search_mode.join(&comma_sep), SummaryItemType::Data),
                    false,
                    false
                ).bold()
            },
            { self.fmt_summary_item(&format!("{}", self.max_len), SummaryItemType::Data) },
            {
                let syntax = if self.att { "AT&T" } else { "Intel" };

                self.fmt_summary_item(syntax, SummaryItemType::Data)
            },
            {
                let regex = if self.usr_regex.is_some() {
                    format!("\'{}\'", self.usr_regex.clone().unwrap())
                } else {
                    String::from("none")
                };

                self.fmt_summary_item(&regex, SummaryItemType::Data)
            },
            {
                let x_match = if self.bin_paths.len() == 1 {
                    "none"
                } else if self.partial_match || self.fess {
                    "full-and-partial"
                } else {
                    "full"
                };

                self.fmt_summary_item(x_match, SummaryItemType::Data)
            },
            "]".bright_magenta(),
        )
    }
}

// Dirty Hacks ---------------------------------------------------------------------------------------------------------

// XXX: We hardcode these to support modifying runtime behavior on presence or absence
pub(crate) const REG_OVERWRITE_FLAG: &str = "--reg-overwrite";
pub(crate) const REG_MEM_WRITE_FLAG: &str = "--reg-mem-write";
pub(crate) const REG_NO_WRITE_FLAG: &str = "--reg-no-write";
pub(crate) const REG_READ_FLAG: &str = "--reg-read";
pub(crate) const REG_MEM_READ_FLAG: &str = "--reg-mem-read";
pub(crate) const REG_NO_READ_FLAG: &str = "--reg-no-read";

// Runtime reflection, underpins register behavior flag functionality.
// XXX: more idiomatic alternative with `clap`?
pub(crate) fn is_env_resident(clap_args: &[&str]) -> bool {
    std::env::args_os().any(|a| {
        if let Ok(arg_str) = a.into_string() {
            if clap_args.contains(&arg_str.as_str()) {
                return true;
            }
        }
        false
    })
}

// Helper for reg-sensitive flags that follow the same pattern
pub(crate) fn filter_reg_sensitive_flag<'a, P>(
    gadgets: P,
    flag_literal: &str,
    flag_reg_args: &[String],
    filter_func: impl Fn(P, Option<&[iced_x86::Register]>) -> P,
) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    if is_env_resident(&[flag_literal]) {
        let regs = flag_reg_args
            .iter()
            .map(|r| str_to_reg(r).unwrap_or_else(|| panic!("Invalid register: {:?}", r)))
            .collect::<Vec<_>>();

        if regs.is_empty() {
            filter_func(gadgets, None)
        } else {
            filter_func(gadgets, Some(&regs))
        }
    } else {
        gadgets
    }
}

// Helper for search config display append
fn fmt_append_reg_sensitive_flag<'a>(
    search_mode: &mut Vec<&'a str>,
    flag_literal: &str,
    flag_reg_args: &[String],
    flag_display: &'a str,
    sep: &ColoredString,
) {
    if is_env_resident(&[flag_literal]) {
        if !flag_reg_args.is_empty() {
            // Note: leak on rare case to avoid alloc on common case
            search_mode.push(Box::leak(
                format!(
                    "{}-{{{}}}",
                    flag_display,
                    flag_reg_args
                        .iter()
                        .map(|r| r.to_lowercase())
                        .collect::<Vec<_>>()
                        .join(sep)
                )
                .into_boxed_str(),
            ));
        } else {
            search_mode.push(flag_display);
        }
    };
}
