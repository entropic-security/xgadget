//!# xgadget
//!
//!Fast, parallel, cross-variant ROP/JOP gadget search for 8086 (16-bit), x86 (32-bit), and x64 (64-bit) binaries.
//!Uses official Rust bindings for the [zydis disassembler library](https://github.com/zyantific/zydis).
//!
//!**Current state:** decent test coverage, but still in beta :)
//!
//!### About
//!
//!To the best of my knowledge, `xgadget` is the first gadget search tool to have these features:
//!
//!* JOP search uses instruction semantics - not hardcoded regex for individual encodings
//!    * Optionally filter to JOP "dispatcher" gadgets with flag `--dispatcher`
//!* Finds gadgets that work across multiple variants of a binary (e.g. different program or compiler versions)
//!    * **Full-match** - Same instruction sequence, same program counter: gadget fully re-usable.
//!        * E.g. `pop rsp; add [rax-0x77], cl; ret ------------------------------------- [ 0xc748d ]`
//!    * **Partial-match** - Same instruction sequence, different program counter: gadget logic portable.
//!        * E.g. `pop rsp; add [rax-0x77], cl; ret; --- [ 'bin_v1.1': 0xc748d, 'bin_v1.2': 0xc9106 ]`
//!    * This is entirely optional, you're free to run this tool on a single binary.
//!
//!Other features include:
//!
//!* Both library API and CLI tool
//!* Supports ELF32, ELF64, PE32, PE32+ [1], and raw files
//!* Parallel across available cores [2], whether searching a single binary or multiple variants
//!* CI/CD for automated integration test and binary releases (Linux, 64-bit) [3]
//!* Statistical benchmark harness for performance tuning [4]
//!* 8086/x86/x64 only, uses a speed-optimized disassembly backend [5]
//!
//!### API Usage
//!
//!Find gadgets:
//!
//!```no_run
//!use xgadget;
//!
//!let max_gadget_len = 5;
//!let search_config = xgadget::SearchConfig::DEFAULT;
//!
//!// Search single binary
//!let bin_1 = xgadget::Binary::from_path_str("/path/to/bin_v1").unwrap();
//!let bins = vec![bin_1];
//!let gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
//!
//!// Search for cross-variant gadgets
//!let bin_1 = xgadget::Binary::from_path_str("/path/to/bin_v1").unwrap();
//!let bin_2 = xgadget::Binary::from_path_str("/path/to/bin_v2").unwrap();
//!let bins = vec![bin_1, bin_2];
//!let cross_gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
//!```
//!
//!### CLI Usage
//!
//!Run `xgadget --help`:
//!
//!```ignore
//!xgadget v0.1.1
//!
//!About:   Fast, parallel, cross-variant ROP/JOP gadget search for 8086/x86/x64 binaries.
//!CPUs:    8 logical, 8 physical
//!
//!USAGE:
//!    xgadget [FLAGS] [OPTIONS] <FILE(S)>...
//!
//!FLAGS:
//!    -8, --8086             For raw (no header) files: assume 8086 (16-bit) [default: assumes x64 (64-bit)]
//!    -t, --att              Display gadgets using AT&T syntax [default: Intel syntax]
//!    -d, --dispatcher       Filter to potential JOP 'dispatcher' gadgets [default: all gadgets]
//!    -h, --help             Prints help information
//!    -i, --imm16            Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
//!    -j, --jop              Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
//!    -c, --no-color         Don't color output, useful for UNIX piping [default: color output]
//!    -m, --partial-match    Include cross-variant partial matches [default: full matches only]
//!    -p, --stack-pivot      Filter to gadgets that write the stack ptr [default: all gadgets]
//!    -r, --rop              Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
//!    -s, --sys              Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
//!    -V, --version          Prints version information
//!    -x, --x86              For raw (no header) files: assume x86 (32-bit) [default: assumes x64 (64-bit)]
//!
//!OPTIONS:
//!    -f, --str-filter <STR>    Filter to gadgets containing a substring
//!    -l, --max-len <LEN>       Gadgets up to LEN instrs long. If 0: all gadgets, any length [default: 5]
//!
//!ARGS:
//!    <FILE(S)>...    1+ binaries to gadget search. If > 1: gadgets common to all
//!```
//!
//!### CLI Build and Install
//!
//!Build from source and install locally:
//!
//!```bash
//!sudo apt-get install cmake  # Ubuntu-specific, adjust for your package manager
//!cargo install xgadget       # Build on host (pre-req: https://www.rust-lang.org/tools/install)
//!```
//!
//!### CLI Binary Releases for Linux
//!
//!Commits to this repo's `master` branch automatically run integration tests and build a dynamically-linked binary for 64-bit Linux.
//!You can [download it here](https://github.com/tnballo/xgadget-priv/releases) and use the CLI immediately, instead of building from source.
//!Static binaries for Linux and Windows may be supported in the future.
//!
//!### ~~Yeah, but can it do 10 OS kernels in 30 seconds?!~~ Repeatable Benchmark Harness
//!
//!```bash
//!bash ./benches/bench_setup_ubuntu.sh    # Ubuntu-specific, download/build 10 kernel versions
//!cargo bench                             # Grab a coffee, this'll take a while...
//!```
//!
//!* `bench_setup_ubuntu.sh` downloads and builds 10 consecutive Linux kernels (versions `5.0.1` to `5.0.10` - with `x86_64_defconfig`).
//!* `cargo bench`, among other benchmarks, searches all 10 kernels for common gadgets.
//!
//!On an i7-9700K (8C/8T, 3.6GHz base, 4.9 GHz max, e.g. an older-gen consumer CPU) machine with `gcc` version 8.4.0: the average runtime, to process *all ten 54MB kernels simultaneously* with a max gadget length of 5 instructions and full-match search for all gadget types (ROP, JOP, and syscall gadgets), is *only 26 seconds*!
//!
//!Note this is a statistical benchmark that samples from many iterations, and requires a lot of RAM (> 32GB). If you just want to run `xgadget` on the 10 kernels once, use `./benches/run_on_bench_kernels.sh`.
//!
//!Searching all 10 kernels for *both* partial and full matches is still in beta, no benchmarks yet (implemented but not yet optimized). Because of the performance hit and the lower utility of partial gadget matches, this search option is disabled by default. It can be enabled with the `--partial-match` flag for the CLI, or via setting a configuration bit, e.g. `search_config |=  xgadget::SearchConfig::PART`, for the library API. Conversely, removing default options improves performance: searching all 10 kernels for only ROP gadgets (ignoring JOP and syscall gadgets) takes just 17 seconds. `xgadget` is designed to scale for large binaries while being easily configurable.
//!
//!### Acknowledgements
//!
//!This project started as an optimized solution to Chapter 8, exercise 3 of "Practical Binary Analysis" by Dennis Andreisse [6], and builds on the design outlined therein.
//!
//!### References
//!
//!* [1] [`goblin` crate by Lzu Tao, m4b, Philip Craig, seu, Will Glynn](https://crates.io/crates/goblin)
//!* [2] [`rayon` crate by Josh Stone, Niko Matsakis](https://crates.io/crates/rayon)
//!* [3] [`xgadget/.github/workflows`](https://github.com/tnballo/xgadget-priv/tree/master/.github/workflows) # TODO: update from priv!
//!* [4] [`criterion` crate by Brook Heisler, Jorge Aparicio](https://crates.io/crates/criterion)
//!* [5] [`zydis` bindings by Joel Honer, Timo von Hartz](https://crates.io/crates/zydis)
//!* [6] ["Practical Binary Analysis" by Dennis Andreisse](https://practicalbinaryanalysis.com/)

// Macro Import --------------------------------------------------------------------------------------------------------

#[macro_use]
extern crate bitflags;

// Exports -------------------------------------------------------------------------------------------------------------

pub mod binary;
pub use crate::binary::*;

pub mod gadget;
pub use crate::gadget::*;

pub mod filters;
pub use crate::filters::*;

pub mod semantics;
pub use crate::semantics::*;

pub mod str_fmt;
pub use crate::str_fmt::*;