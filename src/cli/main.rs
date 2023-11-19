use std::time::Instant;

use clap::Parser;
use color_eyre::eyre::Result;
use colored::Colorize;
use rayon::prelude::*;
use regex::Regex;

// Internal deps -------------------------------------------------------------------------------------------------------

mod str_fmt;
use str_fmt::{str_to_reg, STR_REG_MAP};

mod cli;
use cli::{is_env_resident, CLIOpts, REG_NO_READ_FLAG, REG_OVERWRITE_FLAG};

mod checksec_fmt;

mod imports;

// Driver --------------------------------------------------------------------------------------------------------------

fn main() -> Result<()> {
    color_eyre::install()?;
    lazy_static::initialize(&STR_REG_MAP);

    let mut cli = CLIOpts::parse();

    let mut filter_matches = 0;
    let filter_regex = cli.usr_regex.clone().map(|r| Regex::new(&r).unwrap());

    // Process 1+ files ------------------------------------------------------------------------------------------------

    assert!(
        cli.arch != xgadget::Arch::Unknown,
        "Please set \'--arch\' to \'x8086\' (16-bit), \'x86\' (32-bit), or \'x64\' (64-bit). \
        \'unknown\' is for library use only."
    );

    // File paths -> Binaries
    let bins = cli.parse_binaries();

    // Checksec requested ----------------------------------------------------------------------------------------------

    if cli.check_sec {
        cli.run_checksec(&bins);
        std::process::exit(0);
    }

    // Imports requested -----------------------------------------------------------------------------------------------

    if cli.imports {
        cli.run_imports(&bins);
        std::process::exit(0);
    }

    // Print targets ---------------------------------------------------------------------------------------------------

    for (i, bin) in bins.iter().enumerate() {
        println!("TARGET {} - {} ", format!("{}", i).red(), bin);
    }

    // FESS requested --------------------------------------------------------------------------------------------------

    if cli.fess {
        let start_time = Instant::now();
        let found_cnt = cli.run_fess(&bins);
        let run_time = start_time.elapsed();
        println!(
            "{}\n{}",
            cli,
            cli.fmt_perf_result(bins.len(), found_cnt, start_time, run_time)
        );
        std::process::exit(0);
    }

    // Search ----------------------------------------------------------------------------------------------------------

    let start_time = Instant::now();
    let mut gadgets = xgadget::find_gadgets(&bins, cli.max_len, cli.get_search_config()).unwrap();

    if cli.stack_pivot {
        gadgets = xgadget::filter_stack_pivot(gadgets);
    }

    if cli.dispatcher {
        gadgets = xgadget::filter_dispatcher(gadgets);
    }

    if cli.reg_pop {
        gadgets = xgadget::filter_reg_pop_only(gadgets);
    }

    if is_env_resident(&[REG_OVERWRITE_FLAG]) {
        let regs = cli
            .reg_overwrite
            .iter()
            .map(|r| str_to_reg(r).unwrap_or_else(|| panic!("Invalid register: {:?}", r)))
            .collect::<Vec<_>>();

        if regs.is_empty() {
            gadgets = xgadget::filter_regs_overwritten(gadgets, None);
        } else {
            gadgets = xgadget::filter_regs_overwritten(gadgets, Some(&regs))
        }
    }

    if is_env_resident(&[REG_NO_READ_FLAG]) {
        let regs = cli
            .reg_no_read
            .iter()
            .map(|r| str_to_reg(r).unwrap_or_else(|| panic!("Invalid register: {:?}", r)))
            .collect::<Vec<_>>();

        if regs.is_empty() {
            gadgets = xgadget::filter_regs_not_read(gadgets, None);
        } else {
            gadgets = xgadget::filter_regs_not_read(gadgets, Some(&regs))
        }
    }

    if cli.param_ctrl {
        let param_regs = xgadget::get_all_param_regs(&bins);
        gadgets = xgadget::filter_set_params(gadgets, &param_regs);
    }

    if !cli.bad_bytes.is_empty() {
        let bytes = cli
            .bad_bytes
            .iter()
            .map(|s| s.trim_start_matches("0x"))
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect::<Vec<u8>>();

        gadgets = xgadget::filter_bad_addr_bytes(gadgets, bytes.as_slice());
    }

    let run_time = start_time.elapsed();

    // Print Gadgets ---------------------------------------------------------------------------------------------------

    let gadgets_and_strs: Vec<(xgadget::Gadget, String)> = gadgets
        .into_par_iter()
        .map(|g| (g.fmt_for_filter(cli.att), g))
        .map(|(s, g)| (g, s))
        .collect();

    let mut filtered_gadgets: Vec<(xgadget::Gadget, String)> = gadgets_and_strs
        .into_iter()
        .filter(|(_, s)| match &filter_regex {
            Some(r) => match r.is_match(s) {
                true => {
                    filter_matches += 1;
                    true
                }
                false => false,
            },
            None => true,
        })
        .collect();

    filtered_gadgets.sort_unstable_by(|(_, s1), (_, s2)| s1.cmp(s2));

    let printable_gadgets: Vec<xgadget::Gadget> =
        filtered_gadgets.into_iter().map(|(g, _)| g).collect();

    let mut term_width: usize = match term_size::dimensions() {
        Some((w, _)) => w,
        None => 0,
    };

    // Account for extra chars in our fmt string
    if term_width >= 5 {
        term_width -= 5;
    }

    let gadget_strs: Vec<String> = printable_gadgets
        .par_iter()
        .filter_map(|g| g.fmt(cli.att))
        .map(|(instrs, addrs)| {
            // If partial match or extended format flag, addr(s) right of instr(s), else addr left of instr(s)
            match cli.extended_fmt || cli.partial_match {
                true => {
                    let content_len = instrs.len() + addrs.len();
                    match term_width > content_len {
                        true => {
                            let padding = (0..(term_width - content_len))
                                .map(|_| "-")
                                .collect::<String>()
                                .bright_magenta();
                            format!("{}{} [ {} ]", instrs, padding, addrs)
                        }
                        false => {
                            format!("{} [ {} ]", instrs, addrs)
                        }
                    }
                }
                false => format!("{}{} {}", addrs, ":".bright_magenta(), instrs),
            }
        })
        .collect();

    println!();
    for s in gadget_strs {
        println!("{}", s);
    }

    // Print Summary ---------------------------------------------------------------------------------------------------

    let found_cnt = match filter_regex {
        Some(_) => filter_matches,
        None => printable_gadgets.len(),
    };

    println!(
        "\n{}\n{}",
        cli,
        cli.fmt_perf_result(bins.len(), found_cnt, start_time, run_time)
    );

    Ok(())
}
