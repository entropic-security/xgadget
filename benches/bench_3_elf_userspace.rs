use criterion::{criterion_group, criterion_main, Criterion};

// Gadget Search -------------------------------------------------------------------------------------------------------

const MAX_GADGET_LEN: usize = 3;

fn elf_userspace_bench(c: &mut Criterion) {
    let bin = xgadget::Binary::from_path_str("/usr/bin/readelf").unwrap();
    let bins = vec![bin];
    c.bench_function("readelf_search", |b| {
        b.iter(|| {
            xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::DEFAULT).unwrap()
        })
    });
    c.bench_function("gdb_search", |b| {
        b.iter(|| {
            xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::DEFAULT).unwrap()
        })
    });
}

// Runner --------------------------------------------------------------------------------------------------------------

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = elf_userspace_bench
);

criterion_main!(benches);
