use criterion::{criterion_group, criterion_main, Criterion};
use regex::Regex;

// TODO: Now that the filtering one clones - the baseline should also clone?

// Stack Pivot Filter (sequential baseline) ----------------------------------------------------------------------------

// This implementation has faster per-gadget processing because it doesn't do a full gadget analysis.
// We're comparing it against the actual filter implementation which:
//  - Is slower per-gadget but more readable (uses the general purpose gadget analysis)
//  - Is faster overall on multi-core systems due to parallel processing
//  - Includes cost-of-clone in the below benchmark implementations
pub fn filter_stack_pivot_seq_fast<'a>(
    gadgets: &[xgadget::Gadget<'a>],
) -> Vec<xgadget::Gadget<'a>> {
    let rsp_write = iced_x86::UsedRegister::new(iced_x86::Register::RSP, iced_x86::OpAccess::Write);
    let esp_write = iced_x86::UsedRegister::new(iced_x86::Register::ESP, iced_x86::OpAccess::Write);
    let sp_write = iced_x86::UsedRegister::new(iced_x86::Register::SP, iced_x86::OpAccess::Write);

    gadgets
        .iter()
        .filter(|g| {
            for instr in g.instrs() {
                let mut info_factory = iced_x86::InstructionInfoFactory::new();

                let info = info_factory
                    .info_options(instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);

                if info.used_registers().contains(&rsp_write)
                    || info.used_registers().contains(&esp_write)
                    || info.used_registers().contains(&sp_write)
                {
                    return true;
                }
            }
            false
        })
        .cloned()
        .collect()
}

// This function string formats gadgets and then uses a regex to find those which pop registers from the stack
// We're comparing it against the actual filter implementation which:
// - Is stricter, only consecutive pop sequences before the tail instruction, no other instrs allowed
// - Is faster, no need to string format and run a regex state machine
pub fn filter_reg_pop_only_regex(gadgets: &[xgadget::Gadget<'_>]) -> Vec<(String, String)> {
    let re = Regex::new(r"^(?:pop)(?:.*(?:pop))*.*(?:ret|call|jmp)").unwrap();
    let mut matches = Vec::new();

    for (instrs, addrs) in xgadget::fmt_gadget_str_list(gadgets, false) {
        if re.is_match(&instrs) {
            matches.push((instrs, addrs));
        }
    }

    matches
}

fn pivot_bench(c: &mut Criterion) {
    const MAX_GADGET_LEN: usize = 5;

    let readelf_bin = xgadget::Binary::from_path("/usr/bin/readelf").unwrap();
    let bins = vec![readelf_bin];
    let readelf_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::default()).unwrap();

    let gdb_bin = xgadget::Binary::from_path("/usr/bin/gdb").unwrap();
    let bins = vec![gdb_bin];
    let gdb_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::default()).unwrap();

    c.bench_function("readelf_pivot_filter_seq_fast", |b| {
        b.iter(|| filter_stack_pivot_seq_fast(&readelf_gadgets))
    });
    c.bench_function("readelf_pivot_filter_par", |b| {
        b.iter(|| xgadget::filter_stack_pivot(readelf_gadgets.clone()))
    });
    c.bench_function("gdb_pivot_filter_seq_fast", |b| {
        b.iter(|| filter_stack_pivot_seq_fast(&gdb_gadgets))
    });
    c.bench_function("gdb_pivot_filter_par", |b| {
        b.iter(|| xgadget::filter_stack_pivot(gdb_gadgets.clone()))
    });
}

fn reg_pop_only_bench(c: &mut Criterion) {
    const MAX_GADGET_LEN: usize = 5;

    let readelf_bin = xgadget::Binary::from_path("/usr/bin/readelf").unwrap();
    let bins = vec![readelf_bin];
    let readelf_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::default()).unwrap();

    let gdb_bin = xgadget::Binary::from_path("/usr/bin/gdb").unwrap();
    let bins = vec![gdb_bin];
    let gdb_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::default()).unwrap();

    c.bench_function("readelf_reg_pop_only_filter_par", |b| {
        b.iter(|| xgadget::filter_reg_pop_only(readelf_gadgets.clone()))
    });
    c.bench_function("readelf_reg_pop_only_regex", |b| {
        b.iter(|| filter_reg_pop_only_regex(&readelf_gadgets))
    });
    c.bench_function("gdb_reg_pop_only_filter_par", |b| {
        b.iter(|| xgadget::filter_reg_pop_only(gdb_gadgets.clone()))
    });
    c.bench_function("gdb_reg_pop_only_regex", |b| {
        b.iter(|| filter_reg_pop_only_regex(&gdb_gadgets))
    });
}

// Runner --------------------------------------------------------------------------------------------------------------

criterion_group!(benches, reg_pop_only_bench, pivot_bench);
criterion_main!(benches);
