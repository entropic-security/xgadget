# xgadget

[![crates.io](https://img.shields.io/crates/v/xgadget.svg)](https://crates.io/crates/xgadget)
[![GitHub Actions](https://github.com/entropic-security/xgadget/workflows/test/badge.svg)](https://github.com/entropic-security/xgadget/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/entropic-security/xgadget/blob/master/LICENSE)

Fast, parallel, cross-variant ROP/JOP gadget search for x86 (32-bit) and x64 (64-bit) binaries.
Uses the [iced-x86 disassembler library](https://github.com/icedland/iced).

**Current state:** decent test coverage, but still in beta. Issues/PRs welcome :)

### Quickstart

Install the CLI tool and show its help menu:

```bash
cargo install xgadget --features cli-bin    # Build on host (pre-req: https://www.rust-lang.org/tools/install)
xgadget --help                              # List available commandline options
```
### About

`xgadget` is a tool for Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) exploit development.
It's a fast, multi-threaded alternative to awesome tools like [`ROPGadget`](https://github.com/JonathanSalwan/ROPgadget), [`Ropper`](https://github.com/sashs/Ropper), and [`rp`](https://github.com/0vercl0k/rp).

Though not yet as mature as some of its contemporaries, it contains unique and experimental functionality.
To the best of our knowledge, `xgadget` is the first gadget search tool to have these features:

* Finds gadgets that control (overwrite) specific registers - not just operands of a `pop` instruction or matches for a given regex
    * Use the `--reg-ctrl <optional_register_name>` flag
* JOP search uses instruction semantics - not hardcoded regex for individual encodings
    * Optionally filter to JOP "dispatcher" gadgets with flag `--dispatcher`
* Finds gadgets that work across multiple variants of a binary (e.g. different program or compiler versions)
    * **Full-match** - Same instruction sequence, same program counter: gadget fully re-usable.
        * E.g. `pop rsp; add [rax-0x77], cl; ret ------------------------------------- [ 0xc748d ]`
    * **Partial-match** - Same instruction sequence, different program counter: gadget logic portable.
        * E.g. `pop rsp; add [rax-0x77], cl; ret; --- [ 'bin_v1.1': 0xc748d, 'bin_v1.2': 0xc9106 ]`
    * This is entirely optional, you're free to run this tool on a single binary.
* The stack pointer is explicitly colored in terminal output, for workflow convenience.

Other features include:

* Both a library API and CLI tool
* Supports ELF32, ELF64, PE32, PE32+, Mach-O \[1\], and raw files
* Parallel across available cores \[2\], whether searching a single binary or multiple variants
* CI/CD for automated integration test and binary releases (Linux, 64-bit) \[3\]
* Statistical benchmark harness for performance tuning \[4\]
* 8086/x86/x64 only, uses a speed-optimized disassembly backend \[5\]

### API Usage

Find gadgets:

```rust
use xgadget;

let max_gadget_len = 5;

// Search single binary
let search_config = xgadget::SearchConfig::DEFAULT;
let bin_1 = xgadget::Binary::from_path("/path/to/bin_v1").unwrap();
let bins = vec![bin_1];
let gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
let stack_pivot_gadgets = xgadget::filter_stack_pivot(&gadgets);

// Search for cross-variant gadgets, including partial matches
let search_config = xgadget::SearchConfig::DEFAULT | xgadget::SearchConfig::PART;
let bin_1 = xgadget::Binary::from_path("/path/to/bin_v1").unwrap();
let bin_2 = xgadget::Binary::from_path("/path/to/bin_v2").unwrap();
let bins = vec![bin_1, bin_2];
let cross_gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
let cross_reg_pop_gadgets = xgadget::filter_reg_pop_only(&cross_gadgets);
```

Custom filters can be created using the [`GadgetAnalysis`](crate::gadget::GadgetAnalysis) object and/or functions from the [`semantics`](crate::semantics) module.
How the above [`filter_stack_pivot`](crate::filters::filter_stack_pivot) function is implemented:

```rust
use rayon::prelude::*;
use iced_x86;
use xgadget::{Gadget, GadgetAnalysis};

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a>(gadgets: &[Gadget<'a>]) -> Vec<Gadget<'a>> {
    gadgets
        .par_iter()
        .filter(|g| {
            let regs_overwritten = GadgetAnalysis::new(&g).regs_overwritten();
            if regs_overwritten.contains(&iced_x86::Register::RSP)
                || regs_overwritten.contains(&iced_x86::Register::ESP)
                || regs_overwritten.contains(&iced_x86::Register::SP)
            {
                return true;
            }
            false
        })
        .cloned()
        .collect()
}
```

### CLI Usage

Run `xgadget --help`:

```ignore
xgadget v0.7.0

About:  Fast, parallel, cross-variant ROP/JOP gadget search for x86/x64 binaries.
Cores:  8 logical, 8 physical

USAGE:
    xgadget [OPTIONS] <FILE(S)>...

ARGS:
    <FILE(S)>...    1+ binaries to gadget search. If > 1: gadgets common to all

OPTIONS:
    -a, --arch <ARCH>               For raw (no header) files: specify arch ('x8086', 'x86', or 'x64') [default: x64]
    -b, --bad-bytes <BYTE(S)>...    Filter to gadgets whose addrs don't contain given bytes [default: all]
    -c, --check-sec                 Run checksec on the 1+ binaries instead of gadget search
    -d, --dispatcher                Filter to potential JOP 'dispatcher' gadgets [default: all]
    -e, --extended-fmt              Print in terminal-wide format [default: only used for partial match search]
    -f, --regex-filter <EXPR>       Filter to gadgets matching a regular expression
        --fess                      Compute Fast Exploit Similarity Score (FESS) table for 2+ binaries
    -h, --help                      Print help information
        --inc-call                  Include gadgets containing a call [default: don't include]
        --inc-imm16                 Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
    -j, --jop                       Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
    -l, --max-len <LEN>             Gadgets up to LEN instrs long. If 0: all gadgets, any length [default: 5]
    -m, --partial-match             Include cross-variant partial matches [default: full matches only]
    -n, --no-color                  Don't color output [default: color output]
        --no-deref [<OPT_REG>]      Filter to gadgets that don't deref any regs or a specific reg [default: all]
    -p, --stack-pivot               Filter to gadgets that write the stack ptr [default: all]
        --param-ctrl                Filter to gadgets that control function parameters [default: all]
    -r, --rop                       Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
        --reg-ctrl [<OPT_REG>]      Filter to gadgets that control any reg or a specific reg [default: all]
        --reg-pop                   Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all]
    -s, --sys                       Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
    -t, --att                       Display gadgets using AT&T syntax [default: Intel syntax]
    -V, --version                   Print version information

```

### CLI Build and Install (Recommended)

Build a dynamically-linked binary from source and install it locally:

```bash
cargo install xgadget --features cli-bin    # Build on host (pre-req: https://www.rust-lang.org/tools/install)
```

### CLI Binary Releases for Linux

Commits to this repo's `master` branch automatically run integration tests and build a statically-linked binary for 64-bit Linux.
You can [download it here](https://github.com/entropic-security/xgadget/releases) to try out the CLI immediately, instead of building from source.
Static binaries for Windows may also be supported in the future.

Unfortunately the statically-linked binary is several times slower on an i7-9700K, likely due to the built-in memory allocator for target `x86_64-unknown-linux-musl`.
So building a dynamically-linked binary from source with the above `cargo install` command is *highly* recommended for performance (links against your system's allocator).

### Why No Chain Generation?

Tools that attempt to automate ROP/JOP chain generation require heavyweight analysis - typically symbolic execution of an intermediate representation.
This works well for small binaries and CTF problems, but tends to be error-prone and difficult to scale for large, real-world programs.
At present, `xgadget` has a different goal: enable an expert user to manually craft stable exploits by providing fast, accurate gadget discovery.

### ~~Yeah, but can it do 10 OS kernels under 10 seconds?!~~ Repeatable Benchmark Harness

To build a Docker container and connect to it:

```bash
user@host$ git clone git@github.com:entropic-security/xgadget.git
user@host$ cd xgadget
user@host$ docker build -t xgadget_bench_container .
user@host$ docker run -it xgadget_bench_container
root@container:/xgadget#
```

The final build step runs `./benches/bench_setup_ubuntu.sh`.
This script downloads and builds 10 consecutive Linux kernels (versions `5.0.1` to `5.0.10` - with `x86_64_defconfig`).
Grab a coffee, it can take a while.

Once it's done, run `cargo bench` to search all 10 kernels for common gadgets (among other benchmarks):

```bash
root@container:/xgadget# cargo bench
```

On an i7-9700K (8C/8T, 3.6GHz base, 4.9 GHz max) machine with `gcc` version 8.4.0: the average runtime, to process *all ten 54MB kernels simultaneously* with a max gadget length of 5 instructions and full-match search for all gadget types (ROP, JOP, and syscall gadgets), is *only 6.3 seconds*! Including partial matches as well takes *just 7.9 seconds*.

### Fast Exploit Similarity Score (FESS)

The `--fess` flag uses cross-variant gadget matching as a metric of binary similarity.
It's an experiment in anti-diversification for exploitation.
To view similarity scores for kernel versions `5.0.1`, `5.0.5`, and `5.0.10` within the container:

```bash
root@container# cd ./benches/kernels/
root@container# xgadget vmlinux-5.0.1 vmlinux-5.0.5 vmlinux-5.0.10 --fess
TARGET 0 - 'vmlinux-5.0.1': ELF-X64, 0x00000001000000 entry, 21065728/2 executable bytes/segments
TARGET 1 - 'vmlinux-5.0.5': ELF-X64, 0x00000001000000 entry, 21069824/2 executable bytes/segments
TARGET 2 - 'vmlinux-5.0.10': ELF-X64, 0x00000001000000 entry, 21069824/2 executable bytes/segments

+-------------+----------------------+----------------------+-----------------------+
| Gadget Type | vmlinux-5.0.1 (base) | vmlinux-5.0.5 (diff) | vmlinux-5.0.10 (diff) |
+-------------+----------------------+----------------------+-----------------------+
| ROP (full)  |              175,740 |       11,124 (6.33%) |           699 (0.40%) |
+-------------+----------------------+----------------------+-----------------------+
| ROP (part)  |                    - |      85,717 (48.77%) |       79,367 (45.16%) |
+-------------+----------------------+----------------------+-----------------------+
| JOP (full)  |               97,239 |        1,093 (1.12%) |           277 (0.28%) |
+-------------+----------------------+----------------------+-----------------------+
| JOP (part)  |                    - |      16,792 (17.27%) |       12,635 (12.99%) |
+-------------+----------------------+----------------------+-----------------------+
| SYS (full)  |                   81 |          20 (24.69%) |           20 (24.69%) |
+-------------+----------------------+----------------------+-----------------------+
| SYS (part)  |                    - |          59 (72.84%) |           58 (71.60%) |
+-------------+----------------------+----------------------+-----------------------+
```

In the output table, we see that up to 45.16% of individual ROP gadgets are portable across all three versions (counting partial matches).

### Acknowledgements

This project started as an optimized solution to Chapter 8, exercise 3 of "Practical Binary Analysis" by Dennis Andreisse \[6\], and builds on the design outlined therein.

### License and Contributing

Licensed under the [MIT license](https://github.com/entropic-security/xgadget/blob/master/LICENSE).
[Contributions](https://github.com/entropic-security/xgadget/blob/master/CONTRIBUTING.md) are welcome!

### References

* \[1\] [`goblin` crate by Lzu Tao, m4b, Philip Craig, seu, Will Glynn](https://crates.io/crates/goblin)
* \[2\] [`rayon` crate by Josh Stone, Niko Matsakis](https://crates.io/crates/rayon)
* \[3\] [`xgadget/.github/workflows`](https://github.com/entropic-security/xgadget/tree/master/.github/workflows)
* \[4\] [`criterion` crate by Brook Heisler, Jorge Aparicio](https://crates.io/crates/criterion)
* \[5\] [`iced-x86` crate by wtfsck](https://crates.io/crates/iced-x86)
* \[6\] ["Practical Binary Analysis" by Dennis Andreisse](https://practicalbinaryanalysis.com/)
