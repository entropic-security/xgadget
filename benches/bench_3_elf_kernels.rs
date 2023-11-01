use std::fs;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};

// Cross-variant Gadget Search -----------------------------------------------------------------------------------------

const MAX_GADGET_LEN: usize = 5;

fn elf_kernel_bench(c: &mut Criterion) {
    let kernels_dir = Path::new(file!()).parent().unwrap().join("kernels");

    let files = fs::read_dir(kernels_dir).unwrap();
    let bins: Vec<_> = files
        .into_iter()
        .map(|file| file.unwrap().path())
        .map(|path| xgadget::Binary::from_path(path.to_str().unwrap()).unwrap())
        .collect();

    c.bench_function("10_kernel_search_full_match", |b| {
        b.iter(|| {
            xgadget::find_gadgets(&bins, MAX_GADGET_LEN, xgadget::SearchConfig::default()).unwrap()
        })
    });

    c.bench_function("10_kernel_search_part_match", |b| {
        b.iter(|| {
            xgadget::find_gadgets(
                &bins,
                MAX_GADGET_LEN,
                xgadget::SearchConfig::default() | xgadget::SearchConfig::PART,
            )
            .unwrap()
        })
    });
}

// Runner --------------------------------------------------------------------------------------------------------------

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = elf_kernel_bench
);
criterion_main!(benches);
