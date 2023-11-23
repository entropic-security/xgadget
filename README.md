# xgadget

[![crates.io](https://img.shields.io/crates/v/xgadget.svg)](https://crates.io/crates/xgadget)
[![docs.rs](https://docs.rs/xgadget/badge.svg)](https://docs.rs/xgadget/)
[![GitHub Actions](https://github.com/entropic-security/xgadget/workflows/test/badge.svg)](https://github.com/entropic-security/xgadget/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/entropic-security/xgadget/blob/main/LICENSE)

Fast, parallel, cross-{patch,compiler}-variant ROP/JOP gadget search for x86 (32-bit) and x64 (64-bit) binaries.
Uses the [iced-x86 disassembler library](https://github.com/icedland/iced).

This crate can be used as a **CLI binary** (Windows/Linux/MacOS) or a **library** (7 well-known dependencies, all Rust).

### Quickstart

Install the CLI tool and show its help menu:

```bash
cargo install xgadget --features cli-bin    # Build on host (pre-req: https://www.rust-lang.org/tools/install)
xgadget --help                              # List available command line options
```

### How do ROP and JOP code reuse attacks work?

* **Return Oriented Programming (ROP)** introduced *code-reuse* attacks, after hardware mitigations (aka NX, DEP) made *code-injection* less probable (no simultaneous `WRITE` and `EXECUTE` memory permissions). An attacker with stack control chains together short, existing sequences of assembly (aka "gadgets") - should a leak enable computing gadget addresses in the face of ASLR. When contiguous ROP gadget addresses are written to a corrupted stack, each gadget's ending `ret` instruction pops the next gadget's address into the CPU's instruction pointer. The result? Turing-complete control over a victim process.

<p style="text-align: center;" align="center">
    <img src="https://raw.githubusercontent.com/tnballo/high-assurance-rust/main/src/chp4/exploit_rop_model.svg" width="60%" alt="rop model">
    <figure style="text-align:center;">
    </figure>
</p>

<p align="center">
<i><b>ROP</b> Attack Model (recreated from:<a href="https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf"> Bletsch et. al.</a>)</i>
</p>

* **Jump Oriented Programming (JOP)** is a newer code reuse method which, unlike ROP, doesn't rely on stack control. The attack *bypasses* hardware-assisted shadow-stack implementations (e.g. Intel CET's shadow stack), and is *limited* but *not prevented* by prototype-insensitive indirect target checks (e.g. Intel CET's IBT). JOP allows storing a table of gadget addresses in any `READ`/`WRITE` memory location. Instead of piggy-backing on call-return semantics to execute a gadget list, a "dispatch" gadget (e.g. `add rax, 8; jmp [rax]`) controls table indexing. Chaining happens if each gadget ends with a `jmp` back to the dispatcher (instead of a `ret`).

<p style="text-align: center;" align="center">
    <img src="https://raw.githubusercontent.com/tnballo/high-assurance-rust/main/src/chp4/exploit_jop_model.svg" width="100%" alt="jop model">
    <figure style="text-align:center;">
    </figure>
</p>

<p align="center">
<i><b>JOP</b> Attack Model (recreated from:<a href="https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf"> Bletsch et. al.</a>)</i>
</p>

### About

`xgadget` is a tool for **Return-Oriented Programming (ROP)** and **Jump-Oriented Programming (JOP)** exploit development.
It's a fast, multi-threaded alternative to awesome tools like [`ROPGadget`](https://github.com/JonathanSalwan/ROPgadget), [`Ropper`](https://github.com/sashs/Ropper), and [`rp`](https://github.com/0vercl0k/rp).

The goal is supporting practical usage while simultaneously exploring unique and experimental features.
To the best of our knowledge, `xgadget` is the first gadget search tool to be:

* **Fast-register-sensitive**: Filters gadgets by register usage behavior, not just matches for a given regex, without SMT solving (more powerful, but often impractical).

    * `--reg-overwrite [<OPT_REG(S)>...]` - control any reg (no args) or specific regs (args)

    * `--reg-mem-write [<OPT_REG(S)>...]` - write mem indexed via any reg (no args) or specific regs (args)

    * `--reg-no-write [<OPT_REG(S)>...]` - don't write any reg (no args) or specific regs (args)

    * `--reg-read [<OPT_REG(S)>...]` - read any regs (no args) or specific regs (args)

    * `--reg-mem-read [<OPT_REG(S)>...]` - read mem indexed via any reg (no args) or specific regs (args)

    * `--reg-no-read [<OPT_REG(S)>...]` - don't read any regs (no args) or specific regs (args)

* **JOP-efficient**: JOP search uses instruction semantics - not hardcoded regex for individual encodings.

    * Optionally filter to JOP "dispatcher" gadgets with flag `--dispatcher`

* **Cross-variant:** Finds gadgets that work across multiple variants of a binary (e.g. anti-diversification for different program or compiler versions). Two strategies:

1. ***Full-match*** - Same instruction sequence, same program counter: gadget fully re-usable. Example:
    * Gadget: `pop rdi; ret;`
    * Address (in all binaries): `0xc748d`

<p style="text-align: center;" align="center">
    <img src="https://raw.githubusercontent.com/entropic-security/xgadget/main/img/xgadget_all_match.svg" width="70%" alt="full match">
    <figure style="text-align:center;">
    </figure>
</p>

<p align="center">
<i>Cross-variant <b>Full Match</b></i>
</p>

2. ***Partial-match*** - Same instruction sequence, different program counter: gadget logic portable. Example:
    * Gadget: `pop rdi; ret;`
    * Address in `bin_v1.1`: `0xc748d`
    * Address in `bin_v1.2`: `0xc9106`

<p style="text-align: center;" align="center">
    <img src="https://raw.githubusercontent.com/entropic-security/xgadget/main/img/xgadget_addr_match.svg" width="70%" alt="partial match">
    <figure style="text-align:center;">
    </figure>
</p>

<p align="center">
<i>Cross-variant <b>Partial Match</b></i>
</p>

* This is entirely optional, you're free to run this tool on a single binary.

Other features include:

* Supports ELF32, ELF64, PE32, PE32+, Mach-O, and raw files
* Parallel across available cores, whether searching a single binary or multiple variants
* Currently 8086/x86/x64 only (uses a speed-optimized, arch-specific disassembler)

### CLI Examples

Run `xgadget --help` to enumerate available options.

* **Example:** Search `/usr/bin/sudo` for reliable ways to control `rdi`:

```bash
xgadget /usr/bin/sudo --reg-only --reg-overwrite rdi
```

* **Example:** Search for ROP gadgets that control the value of `rdi`, never read `rsi` or `rdx`, and occur at addresses that don't contain bytes `0x32` or `0x0d`:

```bash
xgadget /usr/bin/sudo --rop --reg-overwrite rdi --reg-no-read rsi rdx --bad-bytes 0x32 0x0d
```

* **Example:** Search `/usr/bin/sudo` for "pop, pop, {jmp,call}" gadgets up to 10 instructions long, print results using AT&T syntax:

```bash
xgadget /usr/bin/sudo --jop --reg-pop --att --max-len 10
```

* **Example:** Same as above, except using a regex filter to match "pop, pop, {jmp,call}" instruction strings (slower/less-accurate here, but regex enables flexible search in general):

```bash
xgadget /usr/bin/sudo --regex-filter "^(?:pop)(?:.*(?:pop))*.*(?:call|jmp)" --att --max-len 10
```

* **Example:** Examine the exploit mitigations binaries `sudo` and `lighttpd` have been compiled with:

```bash
xgadget /usr/bin/sudo /usr/sbin/lighttpd --check-sec
```

* **Example:** List imported and internal symbols for `lighttpd`:

```bash
xgadget /usr/sbin/lighttpd --symbols
```

### API Usage

Find gadgets:

```rust,no_run
use xgadget::{Binary, SearchConfig};

let max_gadget_len = 5;

// Search single binary
let bin = &[Binary::from_path("/path/to/bin_v1").unwrap()];
let gadgets =
    xgadget::find_gadgets(bin, max_gadget_len, SearchConfig::default()).unwrap();
let stack_pivot_gadgets = xgadget::filter_stack_pivot(gadgets);

// Search for cross-variant gadgets, including partial matches
let search_config = SearchConfig::default() | SearchConfig::PART;
let bins = &[
    Binary::from_path("/path/to/bin_v1").unwrap(),
    Binary::from_path("/path/to/bin_v2").unwrap(),
];
let cross_gadgets =
    xgadget::find_gadgets(bins, max_gadget_len, SearchConfig::default()).unwrap();
let cross_reg_pop_gadgets = xgadget::filter_reg_pop_only(cross_gadgets);
```

Custom filters can be created using the [`GadgetAnalysis`](crate::GadgetAnalysis) object and/or functions from the [`semantics`](crate::semantics) module.
How the above [`filter_stack_pivot`](crate::filters::filter_stack_pivot) function is implemented:

```rust
use rayon::prelude::*;
use iced_x86;
use xgadget::{Gadget, GadgetAnalysis};

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a, P>(gadgets: P) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            let regs_overwritten = g.analysis().regs_overwritten(true);
            if regs_overwritten.contains(&iced_x86::Register::RSP)
                || regs_overwritten.contains(&iced_x86::Register::ESP)
                || regs_overwritten.contains(&iced_x86::Register::SP)
            {
                return true;
            }
            false
        })
        .collect()
}
```

<!--- TODO: add back later
### CLI Build and Install (Recommended)

Build a dynamically-linked binary from source and install it locally:

```bash
cargo install xgadget --features cli-bin    # Build on host (pre-req: https://www.rust-lang.org/tools/install)
```

### CLI Binary Releases for Linux

Commits to this repo's `main` branch automatically run integration tests and build a statically-linked binary for 64-bit Linux.
You can [download it here](https://github.com/entropic-security/xgadget/releases) to try out the CLI immediately, instead of building from source.
Static binaries for Windows may also be supported in the future.

Unfortunately the statically-linked binary is several times slower on an i7-9700K, likely due to the built-in memory allocator for target `x86_64-unknown-linux-musl`.
So building a dynamically-linked binary from source with the above `cargo install` command is *highly* recommended for performance (links against your system's allocator).

--->

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
TARGET 0 - [ name: 'vmlinux-5.0.1' | fmt-arch: ELF-X64 | entry: 0x00000001000000 | exec bytes/segments: 21,065,728/2 ]
TARGET 1 - [ name: 'vmlinux-5.0.5' | fmt-arch: ELF-X64 | entry: 0x00000001000000 | exec bytes/segments: 21,069,824/2 ]
TARGET 2 - [ name: 'vmlinux-5.0.10' | fmt-arch: ELF-X64 | entry: 0x00000001000000 | exec bytes/segments: 21,069,824/2 ]

┌─────────────┬──────────────────────┬──────────────────────┬───────────────────────┐
│ Gadget Type │ vmlinux-5.0.1 (base) │ vmlinux-5.0.5 (diff) │ vmlinux-5.0.10 (diff) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  ROP (full) │              108,380 │        7,351 (6.78%) │           556 (0.51%) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  ROP (part) │                    - │      80,783 (74.54%) │       78,053 (72.02%) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  JOP (full) │               79,685 │        1,007 (1.26%) │           276 (0.35%) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  JOP (part) │                    - │      16,458 (20.65%) │       12,461 (15.64%) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  SYS (full) │                8,276 │          422 (5.10%) │           119 (1.44%) │
├─────────────┼──────────────────────┼──────────────────────┼───────────────────────┤
│  SYS (part) │                    - │       4,317 (52.16%) │        3,864 (46.69%) │
└─────────────┴──────────────────────┴──────────────────────┴───────────────────────┘
```

Note these totals exclude low-quality gadgets (use `--all` flag to include).
In the output table, we see that up to 72.02% of individual ROP gadgets, and 15.64% of JOP gadgets, are portable across all three versions (counting partial matches).

### Acknowledgements

This project started as an optimized solution to Chapter 8, exercise 3 of ["Practical Binary Analysis" by Dennis Andreisse](https://amzn.to/3wvtCwa) (affiliate link), and builds on the design outlined therein.

### Related Resource

**Free book about software assurance: [https://highassurance.rs/](https://highassurance.rs/)**

### License and Contributing

Licensed under the [MIT license](https://github.com/entropic-security/xgadget/blob/main/LICENSE).
[Contributions](https://github.com/entropic-security/xgadget/blob/main/CONTRIBUTING.md) are welcome!