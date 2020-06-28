use std::time::Instant;

use rayon::prelude::*;
use colored::Colorize;

// TODO (tnballo): Clean this up with StructOpt, instead of clap (or maybe wait until StructOpt is merged into clap)
fn main() {

    // CLI -------------------------------------------------------------------------------------------------------------

    // Query the metal
    let logical_cpu_cnt = num_cpus::get();
    let physical_cpu_cnt = num_cpus::get_physical();
    let args = clap::App::new("xgadget")
        .version(format!("v{}", clap::crate_version!()).as_str())
        .about(format!("\nAbout:\t{}\nCPUs:\t{} logical, {} physical",
            clap::crate_description!(),
            logical_cpu_cnt,
            physical_cpu_cnt
        ).as_str())
        .arg(clap::Arg::with_name("bins")
            .required(true)
            .takes_value(true)
            .min_values(1)
            .value_name("FILE(S)")
            .help("1+ binaries to gadget search. If > 1: gadgets common to all")
        )
        .arg(clap::Arg::with_name("x86")
            .short("x")
            .long("x86")
            .required(false)
            .help("For raw (no header) files: assume x86 (32-bit) [default: assumes x64 (64-bit)]")
        )
        .arg(clap::Arg::with_name("8086")
            .short("8")
            .long("8086")
            .required(false)
            .conflicts_with("x86")
            .help("For raw (no header) files: assume 8086 (16-bit) [default: assumes x64 (64-bit)]")
        )
        .arg(clap::Arg::with_name("att")
            .short("t")
            .long("att")
            .required(false)
            .help("Display gadgets using AT&T syntax [default: Intel syntax]")
        )
        .arg(clap::Arg::with_name("nocolor")
            .short("c")
            .long("no-color")
            .required(false)
            .help("Don't color output, useful for UNIX piping [default: color output]")
        )
        .arg(clap::Arg::with_name("len")
            .short("l")
            .long("max-len")
            .required(false)
            .takes_value(true)
            .default_value("5")
            .value_name("LEN")
            .help("Gadgets up to LEN instrs long. If 0: all gadgets, any length")
        )
        .arg(clap::Arg::with_name("rop")
            .short("r")
            .long("--rop")
            .required(false)
            .help("Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]")
        )
        .arg(clap::Arg::with_name("jop")
            .short("j")
            .long("--jop")
            .required(false)
            .conflicts_with("rop")
            .help("Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]")
        )
        .arg(clap::Arg::with_name("sys")
            .short("s")
            .long("--sys")
            .required(false)
            .conflicts_with("jop")
            .help("Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]")
        )
        .arg(clap::Arg::with_name("imm16")
            .short("i")
            .long("--imm16")
            .required(false)
            .conflicts_with("jop")
            .help("Include \'{ret, ret far} imm16\' (e.g. add to stack ptr) [default: don't include]")
        )
        .arg(clap::Arg::with_name("part")
            .short("m")
            .long("--partial-match")
            .required(false)
            .help("Include cross-variant partial matches [default: full matches only]")
        )
        .arg(clap::Arg::with_name("pivot")
            .short("p")
            .long("--stack-pivot")
            .required(false)
            .help("Filter to gadgets that write the stack ptr [default: all gadgets]")
        )
        .arg(clap::Arg::with_name("dispatch")
            .short("d")
            .long("--dispatcher")
            .required(false)
            .conflicts_with("pivot")
            .help("Filter to potential JOP \'dispatcher\' gadgets [default: all gadgets]")
        )
        .arg(clap::Arg::with_name("filter")
            .short("f")
            .long("--str-filter")
            .takes_value(true)
            .value_name("STR")
            .required(false)
            .help("Filter to gadgets containing a substring")
        )
        .get_matches();

    // User-specified settings -----------------------------------------------------------------------------------------

    let att_syntax = args.is_present("att");
    let color = !args.is_present("nocolor");
    let mut search_conf = xgadget::SearchConfig::DEFAULT;
    if args.is_present("part") {
        search_conf |= xgadget::SearchConfig::PART;
    }
    if args.is_present("imm16") {
        search_conf |= xgadget::SearchConfig::IMM16;
    }
    if args.is_present("rop") {
        assert!(search_conf.intersects(xgadget::SearchConfig::JOP | xgadget::SearchConfig::SYS));
        search_conf = search_conf - xgadget::SearchConfig::JOP - xgadget::SearchConfig::SYS;
    }
    if args.is_present("jop") {
        assert!(search_conf.intersects(xgadget::SearchConfig::ROP | xgadget::SearchConfig::SYS));
        search_conf = search_conf - xgadget::SearchConfig::ROP - xgadget::SearchConfig::SYS;
    }
    if args.is_present("sys") {
        assert!(search_conf.intersects(xgadget::SearchConfig::ROP | xgadget::SearchConfig::JOP));
        search_conf = search_conf - xgadget::SearchConfig::ROP - xgadget::SearchConfig::JOP;
    }

    // Process 1+ files ------------------------------------------------------------------------------------------------

    if let Some(paths) = args.values_of("bins") {
        let bin_paths: Vec<&str> = paths.collect();
        let max_gadget_len = args.value_of("len").unwrap().trim().parse().unwrap();

        // Files -> Binaries
        let bins: Vec<xgadget::Binary> = bin_paths.par_iter()
            .map(|&path| xgadget::Binary::from_path_str(path).unwrap())
            .map(|binary| set_arch_raw(binary, args.is_present("8086"), args.is_present("x86")))
            .collect();



        for (i, bin) in bins.iter().enumerate() {
            println!("TARGET {} - {} ", i, bin);
        }

        // Search -------------------------------------------------------------------------------------------------------

        let start_time = Instant::now();
        let mut gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_conf).unwrap();

        if args.is_present("pivot") {
            gadgets = xgadget::filter_stack_pivot(&gadgets);
        } else if args.is_present("dispatch") {
            gadgets = xgadget::filter_dispatcher(&gadgets);
        }

        let run_time = start_time.elapsed();

        // Print Results -----------------------------------------------------------------------------------------------

        print!("\n");
        for (mut instr, addrs) in xgadget::str_fmt_gadgets(&gadgets, att_syntax, color).unwrap() {
            if  (!args.is_present("filter"))
                || (args.is_present("filter") && instr.contains(args.value_of("filter").unwrap())) {

                instr.push(' ');
                if color {
                    print!("{}", instr);

                    // Format string can't compensate for ANSI color escapes, so do it manually
                    let width = 150;
                    let char_len = strip_ansi_escapes::strip(&instr).unwrap().len();
                    if width > char_len {
                        let fill_cnt = width - char_len;
                        for _ in 0..fill_cnt {
                            print!("-");
                        }
                    }

                    print!(" {}\n", addrs);
                    println!("TEMP DEBUG, HUMAN LEN: {}", char_len);
                } else {
                    println!("{:-<150} {}", instr, addrs);
                }
            }
        }

        println!("\nSUMMARY [ search: {}, x_match: {}, max_len: {}, syntax: {}, str_filter: {} ]",
            {
                let search_mode = if args.is_present("rop") { "ROP-only" }
                else if args.is_present("jop") { "JOP-only" }
                else if args.is_present("sys") { "SYS-only" }
                else if args.is_present("pivot") { "Stack-pivot-only" }
                else if args.is_present("dispatch") { "Dispatcher-only" }
                else { "ROP-JOP-SYS (default)" };

                if color { search_mode.red() }
                else { search_mode.normal() }
            },
            {
                let x_match = if bins.len() == 1 { "none"}
                else if args.is_present("part") { "full-and-partial" }
                else { "full" };

                if color { x_match.red() }
                else { x_match.normal() }

            },
            {
                let max_len = format!("{}", max_gadget_len);

                if color { max_len.red() }
                else { max_len.normal() }
            },
            {
                let syntax = if att_syntax { "AT&T" } else { "Intel" };

                if color { syntax.red() }
                else { syntax.normal() }
            },
            {
                let filter = if args.is_present("filter") {
                    format!("\'{}\'", args.value_of("filter").unwrap())
                } else {
                    String::from("none")
                };

                if color { filter.red() }
                else { filter.normal() }
            },

        );

        if bins.len() > 1 {
            println!("{:.<40} {:?}", "Unique cross-variant gadgets found ", gadgets.len());
        } else {
            println!("{:.<40} {:?}", "Unique gadgets found ", gadgets.len());
        }

        println!("{:.<40} {:?}", "Search/filter time ", run_time);
        println!("{:.<40} {:?}", "Print time ", start_time.elapsed() - run_time);
    }
}

// User flag -> bin.arch for raw files (no headers)
fn set_arch_raw(mut bin: xgadget::Binary, flag_8086: bool, flag_x86: bool) -> xgadget::Binary {
    if bin.arch == xgadget::Arch::Unknown {
        assert!(!(flag_8086 && flag_x86));
        if flag_8086 {
            bin.arch = xgadget::Arch::X8086;
        } else if flag_x86 {
            bin.arch = xgadget::Arch::X86;
        } else {
            bin.arch = xgadget::Arch::X64;
        }
    }

    bin
}