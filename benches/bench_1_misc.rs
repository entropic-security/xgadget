use criterion::{criterion_group, criterion_main, Criterion};

// Opcode offset search ------------------------------------------------------------------------------------------------

pub fn gen_rand_buf(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random()).collect()
}

pub fn find_match_idxs_sequential_baseline(haystack: &[u8], needles: &[u8]) -> Vec<usize> {
    let mut match_offsets = Vec::new();
    for (i, b) in haystack.iter().enumerate() {
        if needles.contains(b) {
            match_offsets.push(i);
        }
    }
    match_offsets
}

pub fn find_match_idxs_sequential_functional(haystack: &[u8], needles: &[u8]) -> Vec<usize> {
    haystack
        .iter()
        .enumerate()
        .filter(|&(_, b)| needles.contains(b))
        .map(|(i, _)| i)
        .collect()
}

fn opcode_offset_bench(c: &mut Criterion) {
    let rand_1_000 = gen_rand_buf(1_000);
    let rand_10_000 = gen_rand_buf(10_000);
    let rand_100_000 = gen_rand_buf(100_000);

    let search_config =
        xgadget::SearchConfig::ROP | xgadget::SearchConfig::JOP | xgadget::SearchConfig::IMM16;
    let op_codes = xgadget::gadget::get_flow_opcodes(search_config);

    let bin = xgadget::Binary::from_bytes("test_1_000", &rand_1_000).unwrap();
    let seg = bin.segments.iter().next().unwrap();
    c.bench_function("off_seq_base_1_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_1_000, &op_codes))
    });
    c.bench_function("off_seq_func_1_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_1_000, &op_codes))
    });
    c.bench_function("off_par_bin_1_000", |b| {
        b.iter(|| seg.get_matching_offsets(&op_codes))
    });

    let bin = xgadget::Binary::from_bytes("test_10_000", &rand_10_000).unwrap();
    let seg = bin.segments.iter().next().unwrap();
    c.bench_function("off_seq_base_10_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_10_000, &op_codes))
    });
    c.bench_function("off_seq_func_10_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_10_000, &op_codes))
    });
    c.bench_function("off_par_bin_10_000", |b| {
        b.iter(|| seg.get_matching_offsets(&op_codes))
    });

    let bin = xgadget::Binary::from_bytes("test_100_000", &rand_100_000).unwrap();
    let seg = bin.segments.iter().next().unwrap();
    c.bench_function("off_seq_base_100_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_100_000, &op_codes))
    });
    c.bench_function("off_seq_func_100_000", |b| {
        b.iter(|| find_match_idxs_sequential_baseline(&rand_100_000, &op_codes))
    });
    c.bench_function("off_par_bin_100_000", |b| {
        b.iter(|| seg.get_matching_offsets(&op_codes))
    });
}

// Stack Pivot Filter --------------------------------------------------------------------------------------------------

pub fn filter_stack_pivot_sequential<'a>(
    gadgets: &Vec<xgadget::gadget::Gadget<'a>>,
) -> Vec<xgadget::gadget::Gadget<'a>> {
    gadgets
        .iter()
        .filter(|g| {
            for i in &g.instrs {
                for o in &i.operands {
                    if (o.reg == zydis::Register::RSP || o.reg == zydis::Register::ESP)
                        && (o.action == zydis::OperandAction::WRITE)
                    {
                        return true;
                    }
                }
            }
            false
        })
        .cloned()
        .collect()
}

fn pivot_bench(c: &mut Criterion) {
    const MAX_GADGET_LEN: usize = 5;

    let readelf_bin = xgadget::Binary::from_path_str("/usr/bin/readelf").unwrap();
    let bins = vec![readelf_bin];
    let readelf_gadgets = xgadget::find_gadgets(
        &bins,
        MAX_GADGET_LEN,
        xgadget::gadget::SearchConfig::DEFAULT,
    )
    .unwrap();

    let gdb_bin = xgadget::Binary::from_path_str("/usr/bin/gdb").unwrap();
    let bins = vec![gdb_bin];
    let gdb_gadgets = xgadget::find_gadgets(
        &bins,
        MAX_GADGET_LEN,
        xgadget::gadget::SearchConfig::DEFAULT,
    )
    .unwrap();

    c.bench_function("readelf_pivot_filter_seq", |b| {
        b.iter(|| filter_stack_pivot_sequential(&readelf_gadgets))
    });
    c.bench_function("readelf_pivot_filter_par", |b| {
        b.iter(|| xgadget::filter_stack_pivot(&readelf_gadgets))
    });
    c.bench_function("gdb_pivot_filter_seq", |b| {
        b.iter(|| filter_stack_pivot_sequential(&gdb_gadgets))
    });
    c.bench_function("gdb_pivot_filter_par", |b| {
        b.iter(|| xgadget::filter_stack_pivot(&gdb_gadgets))
    });
}

// Runner --------------------------------------------------------------------------------------------------------------

criterion_group!(benches, opcode_offset_bench, pivot_bench);
criterion_main!(benches);
