use colored::Colorize;
use criterion::{criterion_group, criterion_main, Criterion};

mod flame_graph;

const MAX_LEN: usize = 100;

#[rustfmt::skip]
pub const X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3,                                                   // ret
    0x48, 0x8d, 0x0d, 0xe1, 0xdd, 0x05, 0x00,               // lea rcx,[rip+0x5DDE1]
    0xff, 0xe1,                                             // jmp rcx
    0x48, 0x8d, 0x0d, 0xcb, 0xdd, 0x05, 0x00,               // lea rax,[rip+0x5DDCB]    // Intentionally unused rax
    0xff, 0x21,                                             // jmp [rcx]
];

#[rustfmt::skip]
pub const X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64: &[u8] = &[
    0x48, 0x8b, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00,         // mov  rax,QWORD PTR [rsp+0xb8]
    0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,   // xor  rax,QWORD PTR fs:0x28
    0x0f, 0x85, 0xf0, 0x01, 0x00, 0x00,                     // jne  a3fc <__sprintf_chk@plt+0x86c>
    0x48, 0x81, 0xc4, 0xc8, 0x00, 0x00, 0x00,               // add  rsp,0xc8
    0x44, 0x89, 0xe0,                                       // mov  eax,r12d
    0x41, 0x5e,                                             // pop  r14
    0x41, 0x5f,                                             // pop  r15
    0xc3,                                                   // ret - Partial match, X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64 and X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
    0x5b,                                                   // pop  rbx
    0x5d,                                                   // pop  rbp
    0x41, 0x5c,                                             // pop  r12
    0x41, 0x5d,                                             // pop  r13
    0x48, 0x8d, 0x1d, 0xe1, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDE1]
    0xff, 0xd3,                                             // call rbx  - Full match against X_RET_AFTER_JNE_AND_ADJACENT_CALL_X64
    0x48, 0x8d, 0x1d, 0xcb, 0xdd, 0x05, 0x00,               // lea  rbx,[rip+0x5DDCB]
    0xff, 0x21,                                             // jmp [rcx] - Full match against X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64
];

fn get_raw_bin(name: &str, bytes: &[u8]) -> xgadget::Binary {
    let mut bin = xgadget::Binary::from_bytes(name, bytes).unwrap();
    assert_eq!(bin.format(), xgadget::Format::Raw);
    assert_eq!(bin.arch(), xgadget::Arch::Unknown);
    bin.set_arch(xgadget::Arch::X64);

    bin
}

fn collect_strs_seq(gadgets: &[xgadget::Gadget], extended: bool) -> Vec<String> {
    let att = false;
    let color = true;
    let term_width = 150;
    gadgets
        .iter()
        .filter_map(|g| g.fmt(att))
        .map(|(instrs, addrs)| match extended {
            true => {
                let content_len = instrs.len() + addrs.len();
                match term_width > content_len {
                    true => {
                        let padding = (0..(term_width - content_len))
                            .map(|_| "-")
                            .collect::<String>();

                        let padding = match color {
                            true => padding,
                            false => format!("{}", padding.bright_magenta()),
                        };

                        format!("{}{} [ {} ]", instrs, padding, addrs)
                    }
                    false => {
                        format!("{} [ {} ]", instrs, addrs)
                    }
                }
            }
            false => {
                format!("{}{} {}", addrs, ":".bright_magenta(), instrs)
            }
        })
        .collect()
}

fn fmt_bench(c: &mut Criterion) {
    let bin_ret_post_jmp = get_raw_bin("bin_ret_post_jmp", X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bins = vec![bin_ret_post_jmp];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    c.bench_function("fmt_regular", |b| {
        b.iter(|| collect_strs_seq(&gadgets, false))
    });

    c.bench_function("fmt_extended", |b| {
        b.iter(|| collect_strs_seq(&gadgets, true))
    });
}

fn fmt_partial_bench(c: &mut Criterion) {
    let bin_ret_jmp = get_raw_bin("bin_ret_jmp", X_RET_AFTER_JNE_AND_ADJACENT_JMP_X64);
    let bin_mix = get_raw_bin("bin_mix", X_RET_AFTER_JNE_AND_ADJACENT_CALL_MIX_MATCH_X64);

    let full_part_match_config = xgadget::SearchConfig::default() | xgadget::SearchConfig::PART;
    assert!(full_part_match_config.intersects(xgadget::SearchConfig::PART));

    let bins = vec![bin_mix, bin_ret_jmp];
    let gadgets = xgadget::find_gadgets(&bins, MAX_LEN, full_part_match_config).unwrap();

    c.bench_function("fmt_partial", |b| {
        b.iter(|| collect_strs_seq(&gadgets, true))
    });
}

// Runner --------------------------------------------------------------------------------------------------------------

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(flame_graph::FlamegraphProfiler::new(100));
    targets = fmt_bench, fmt_partial_bench
);
criterion_main!(benches);
