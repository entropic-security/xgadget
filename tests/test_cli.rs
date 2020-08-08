use tempfile::NamedTempFile;
use std::io::Write;
use assert_cmd::Command;
use predicates::prelude::*;

// Non-exhaustive Error Cases ------------------------------------------------------------------------------------------

#[test]
fn test_no_arg_err() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.assert().failure().stderr(predicate::str::contains("The following required arguments were not provided:"));
}

#[test]
fn test_file_not_found_err() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea");
    xgadget_bin.assert().failure().stderr(predicate::str::contains("No such file or directory"));
}

#[test]
fn test_conflicting_flags_rop_jop() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-r")
        .arg("-j");

    xgadget_bin.assert().failure().stderr(predicate::str::contains("The argument '--rop' cannot be used with '--jop'"));
}

#[test]
fn test_conflicting_flags_dispatcher_stack_set_reg() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-c")
        .arg("-d");

    xgadget_bin.assert().failure().stderr(predicate::str::contains("The argument '--dispatcher' cannot be used with '--reg-ctrl'"));
}

#[test]
fn test_conflicting_flags_x86_8086() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-8")
        .arg("-x");

    xgadget_bin.assert().failure().stderr(predicate::str::contains("The argument '--x86' cannot be used with '--8086'"));
}

#[test]
fn test_conflicting_flags_imm16_jop() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-i")
        .arg("-j");

    xgadget_bin.assert().failure().stderr(predicate::str::contains("The argument '--jop' cannot be used with '--imm16'"));
}

// Non-exhaustive Success Cases ----------------------------------------------------------------------------------------

#[test]
fn test_raw() {
    #[rustfmt::skip]
    pub const ADJACENT_JMP_X64: &[u8] = &[
        0x48, 0x8d, 0x0d, 0xe1, 0xdd, 0x05, 0x00,               // lea rcx,[rip+0x5DDE1]
        0xff, 0xe1,                                             // jmp rcx
        0x48, 0x8d, 0x0d, 0xcb, 0xdd, 0x05, 0x00,               // lea rax,[rip+0x5DDCB]
        0xff, 0x21,                                             // jmp [rcx]
    ];

    let mut raw_file = NamedTempFile::new().unwrap();
    raw_file.write(ADJACENT_JMP_X64).unwrap();

    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();
    xgadget_bin
        .arg(raw_file.path())
        .arg("-n");

    xgadget_bin.assert().success().stdout(predicate::str::contains("lea ecx, [rip+0x5DDCB]; jmp [rcx];"));
    xgadget_bin.assert().success().stdout(predicate::str::contains("jmp rcx;"));
}

#[cfg(target_os = "linux")]
#[test]
fn test_single_bin() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/bin/cat");
    xgadget_bin.assert().success();
}

#[cfg(target_os = "linux")]
#[test]
fn test_dual_bin() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/bin/cat")
        .arg("/bin/cp");

    xgadget_bin.assert().success();
}

#[cfg(target_os = "linux")]
#[test]
fn test_triple_bin_with_arg() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/bin/cat")
        .arg("/bin/ls")
        .arg("/bin/cp")
        .arg("--att")
        .arg("-r");

    xgadget_bin.assert().success();
}

#[cfg(target_os = "linux")]
#[test]
fn test_search_args() {

    let output_all = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .output()
        .unwrap()
        .stdout;

    let output_rop = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-r")
        .output()
        .unwrap()
        .stdout;

    let output_rop_imm16 = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-r")
        .arg("-i")
        .output()
        .unwrap()
        .stdout;

    let output_jop = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-j")
        .output()
        .unwrap()
        .stdout;

    let output_sys = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-s")
        .output()
        .unwrap()
        .stdout;

    let output_stack_pivot = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-p")
        .output()
        .unwrap()
        .stdout;

   let output_dispatch = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-d")
        .output()
        .unwrap()
        .stdout;

    let output_reg_ctrl = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-c")
        .output()
        .unwrap()
        .stdout;

    assert!(output_all.len() >= output_rop.len());
    assert!(output_all.len() >= output_jop.len());
    assert!(output_all.len() >= output_sys.len());
    assert!(output_all.len() >= output_stack_pivot.len());
    assert!(output_all.len() >= output_dispatch.len());
    assert!(output_all.len() >= output_reg_ctrl.len());
    assert!(output_rop_imm16.len() >= output_rop.len());
}

#[cfg(target_os = "linux")]
#[test]
fn test_max_len() {

    let output_def = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .output()
        .unwrap()
        .stdout;

    let output_100_len = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-l 100")
        .output()
        .unwrap()
        .stdout;

    assert!(output_100_len.len() >= output_def.len());
}

#[cfg(target_os = "linux")]
#[test]
fn test_color_filter_line_count() {

    #[cfg(target_arch = "x86")]
    let reg_name = "eax";

    #[cfg(target_arch = "x86_64")]
    let reg_name = "rax";

    let output_color = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg(format!("-f \"mov {}\"", reg_name))
        .output()
        .unwrap()
        .stdout;

    let output_color_line_cnt = std::str::from_utf8(&output_color)
        .unwrap()
        .lines()
        .count();

    let output_no_color = Command::cargo_bin("xgadget")
        .unwrap()
        .arg("/bin/cat")
        .arg("-n")
        .arg(format!("-f \"mov {}\"", reg_name))
        .output()
        .unwrap()
        .stdout;

    let output_no_color_line_cnt = std::str::from_utf8(&output_no_color)
        .unwrap()
        .lines()
        .count();

    assert!(output_color_line_cnt == output_no_color_line_cnt);
}