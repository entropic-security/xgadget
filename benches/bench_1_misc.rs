use criterion::{criterion_group, criterion_main, Criterion};
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
    let readelf_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    let gdb_bin = xgadget::Binary::from_path_str("/usr/bin/gdb").unwrap();
    let bins = vec![gdb_bin];
    let gdb_gadgets =
        xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

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

criterion_group!(benches, pivot_bench);
criterion_main!(benches);
