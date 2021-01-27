# xgadget

![crates.io](https://img.shields.io/crates/v/xgadget.svg)
![GitHub Actions](https://github.com/entropic-security/xgadget/workflows/test/badge.svg)

Fast, parallel, cross-variant ROP/JOP gadget search for x86 (32-bit) and x64 (64-bit) binaries.
Uses the [iced-x86 disassembler library](https://github.com/0xd4d/iced).

**Current state:** decent test coverage, but still in beta. Issues/PRs welcome :)

### About

To the best of my knowledge, `xgadget` is the first gadget search tool to have these features:

* JOP search uses instruction semantics - not hardcoded regex for individual encodings
    * Optionally filter to JOP "dispatcher" gadgets with flag `--dispatcher`
* Finds gadgets that work across multiple variants of a binary (e.g. different program or compiler versions)
    * **Full-match** - Same instruction sequence, same program counter: gadget fully re-usable.
        * E.g. `pop rsp; add [rax-0x77], cl; ret ------------------------------------- [ 0xc748d ]`
    * **Partial-match** - Same instruction sequence, different program counter: gadget logic portable.
        * E.g. `pop rsp; add [rax-0x77], cl; ret; --- [ 'bin_v1.1': 0xc748d, 'bin_v1.2': 0xc9106 ]`
    * This is entirely optional, you're free to run this tool on a single binary.

Other features include:

* Both library API and CLI tool
* Supports ELF32, ELF64, PE32, PE32+ [1], and raw files
* Parallel across available cores [2], whether searching a single binary or multiple variants
* CI/CD for automated integration test and binary releases (Linux, 64-bit) [3]
* Statistical benchmark harness for performance tuning [4]
* 8086/x86/x64 only, uses a speed-optimized disassembly backend [5]

### API Usage

Find gadgets:

```rust
use xgadget;

let max_gadget_len = 5;
let search_config = xgadget::SearchConfig::DEFAULT;

// Search single binary
let bin_1 = xgadget::Binary::from_path_str("/path/to/bin_v1").unwrap();
let bins = vec![bin_1];
let gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
let stack_pivot_gadgets = xgadget::filter_stack_pivot(&gadgets);

// Search for cross-variant gadgets
let bin_1 = xgadget::Binary::from_path_str("/path/to/bin_v1").unwrap();
let bin_2 = xgadget::Binary::from_path_str("/path/to/bin_v2").unwrap();
let bins = vec![bin_1, bin_2];
let cross_gadgets = xgadget::find_gadgets(&bins, max_gadget_len, search_config).unwrap();
let cross_reg_write_gadgets = xgadget::filter_reg_pop_only(&cross_gadgets);
```

### CLI Usage

Run `xgadget --help`:

```
xgadget v0.4.0

About:  Fast, parallel, cross-variant ROP/JOP gadget search for x86/x64 binaries.
Cores:  8 logical, 8 physical

USAGE:
    xgadget [FLAGS] [OPTIONS] <FILE(S)>...

FLAGS:
    -t, --att              Display gadgets using AT&T syntax [default: Intel syntax]
    -c, --check-sec        Run checksec on the 1+ binaries instead of gadget search
    -d, --dispatcher       Filter to potential JOP 'dispatcher' gadgets [default: all gadgets]
    -e, --extended-fmt     Print in terminal-wide format [default: only used for partial match search]
    -h, --help             Prints help information
        --inc-call         Include gadgets containing a call [default: don't include]
        --inc-imm16        Include '{ret, ret far} imm16' (e.g. add to stack ptr) [default: don't include]
    -j, --jop              Search for JOP gadgets only [default: ROP, JOP, and SYSCALL]
    -n, --no-color         Don't color output, useful for UNIX piping [default: color output]
    -m, --partial-match    Include cross-variant partial matches [default: full matches only]
    -w, --reg-write        Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets [default: all gadgets]
    -r, --rop              Search for ROP gadgets only [default: ROP, JOP, and SYSCALL]
    -p, --stack-pivot      Filter to gadgets that write the stack ptr [default: all gadgets]
    -s, --sys              Search for SYSCALL gadgets only [default: ROP, JOP, and SYSCALL]
    -V, --version          Prints version information

OPTIONS:
    -a, --arch <ARCH>               For raw (no header) files: specify arch ('x8086', 'x86', or 'x64') [default: x64]
    -b, --bad-bytes <BYTE(S)>...    Filter to gadgets whose addrs don't contain given bytes [default: all gadgets]
    -l, --max-len <LEN>             Gadgets up to LEN instrs long. If 0: all gadgets, any length [default: 5]
    -f, --regex-filter <EXPR>       Filter to gadgets matching a regular expression

ARGS:
    <FILE(S)>...    1+ binaries to gadget search. If > 1: gadgets common to all
```

### CLI Build and Install (Recommended)

Build a dynamically-linked binary from source and install it locally:

```bash
cargo install xgadget --features cli-bin    # Build on host (pre-req: https://www.rust-lang.org/tools/install)
```

### CLI Binary Releases for Linux

Commits to this repo's `master` branch automatically run integration tests and build a statically-linked binary for 64-bit Linux.
You can [download it here](https://github.com/entropic-security/xgadget/releases) and use the CLI immediately, instead of building from source.
Static binaries for Windows may also be supported in the future.

The statically-linked binary is about 8x slower, presumably due to the built-in memory allocator for target `x86_64-unknown-linux-musl`.
Building a dynamically-linked binary from source with the above `cargo install` command is *highly* recommended.

### ~~Yeah, but can it do 10 OS kernels under 10 seconds?!~~ Repeatable Benchmark Harness

```bash
bash ./benches/bench_setup_ubuntu.sh    # Ubuntu-specific, download/build 10 kernel versions
cargo bench                             # Grab a coffee, this'll take a while...
```

* `bench_setup_ubuntu.sh` downloads and builds 10 consecutive Linux kernels (versions `5.0.1` to `5.0.10` - with `x86_64_defconfig`).
* `cargo bench`, among other benchmarks, searches all 10 kernels for common gadgets.

On an i7-9700K (8C/8T, 3.6GHz base, 4.9 GHz max) machine with `gcc` version 8.4.0: the average runtime, to process *all ten 54MB kernels simultaneously* with a max gadget length of 5 instructions and full-match search for all gadget types (ROP, JOP, and syscall gadgets), is *only 5.8 seconds*! Including partial matches as well takes *just 7.2 seconds*.

### Acknowledgements

This project started as an optimized solution to Chapter 8, exercise 3 of "Practical Binary Analysis" by Dennis Andreisse [6], and builds on the design outlined therein.

### References

* [1] [`goblin` crate by Lzu Tao, m4b, Philip Craig, seu, Will Glynn](https://crates.io/crates/goblin)
* [2] [`rayon` crate by Josh Stone, Niko Matsakis](https://crates.io/crates/rayon)
* [3] [`xgadget/.github/workflows`](https://github.com/entropic-security/xgadget/tree/master/.github/workflows)
* [4] [`criterion` crate by Brook Heisler, Jorge Aparicio](https://crates.io/crates/criterion)
* [5] [`iced-x86` crate by 0xd4d](https://crates.io/crates/iced-x86)
* [6] ["Practical Binary Analysis" by Dennis Andreisse](https://practicalbinaryanalysis.com/)
