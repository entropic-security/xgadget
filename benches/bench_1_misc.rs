use criterion::{criterion_group, criterion_main, Criterion};
// Stack Pivot Filter (sequential baseline) ----------------------------------------------------------------------------

pub fn filter_stack_pivot_sequential<'a>(
    gadgets: &Vec<xgadget::gadget::Gadget<'a>>,
) -> Vec<xgadget::gadget::Gadget<'a>> {
    let rsp_write = iced_x86::UsedRegister::new(iced_x86::Register::RSP, iced_x86::OpAccess::Write);
    let esp_write = iced_x86::UsedRegister::new(iced_x86::Register::ESP, iced_x86::OpAccess::Write);
    let sp_write = iced_x86::UsedRegister::new(iced_x86::Register::SP, iced_x86::OpAccess::Write);

    gadgets
        .iter()
        .filter(|g| {
            for instr in g.instrs() {
                let mut info_factory = iced_x86::InstructionInfoFactory::new();

                let info = info_factory
                    .info_options(&instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);

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
