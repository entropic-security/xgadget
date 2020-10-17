use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

// Non-exhaustive Error Cases ------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_no_arg_err() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The following required arguments were not provided:",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_file_not_found_err() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea");
    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains("No such file or directory"));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_conflicting_flags_rop_jop() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-r")
        .arg("-j");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The argument '--rop' cannot be used with '--jop'",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_conflicting_flags_dispatcher_stack_set_reg() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-w")
        .arg("-d");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The argument '--dispatcher' cannot be used with '--reg-write'",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_conflicting_flags_imm16_jop() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("-i")
        .arg("-j");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The argument '--jop' cannot be used with '--imm16'",
        ));
}

// Non-exhaustive Success Cases ----------------------------------------------------------------------------------------

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
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
    xgadget_bin.arg(raw_file.path()).arg("-n");

    xgadget_bin
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "lea ecx, [rip+0x5DDCB]; jmp [rcx];",
        ));
    xgadget_bin
        .assert()
        .success()
        .stdout(predicate::str::contains("jmp rcx;"));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
#[cfg(target_os = "linux")]
fn test_single_bin() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/bin/cat");
    xgadget_bin.assert().success();
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_dual_bin() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/bin/cat").arg("/bin/cp");

    xgadget_bin.assert().success();
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
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

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_checksec() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin.arg("/bin/cat").arg("-c");

    xgadget_bin.assert().success();
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_search_args() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_rop = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-r")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_rop_imm16 = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-r")
            .arg("-i")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_jop = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-j")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_sys = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-s")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_stack_pivot = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-p")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_dispatch = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-d")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_reg_ctrl = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-c")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    assert!(output_all.len() >= output_rop.len());
    assert!(output_all.len() >= output_jop.len());
    assert!(output_all.len() >= output_sys.len());
    assert!(output_all.len() >= output_stack_pivot.len());
    assert!(output_all.len() >= output_dispatch.len());
    assert!(output_all.len() >= output_reg_ctrl.len());
    assert!(output_rop_imm16.len() >= output_rop.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_max_len() {
    let output_def_len = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_100_len = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-l")
            .arg("100")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    assert!(output_100_len.len() >= output_def_len.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_color_filter_line_count() {
    #[cfg(target_arch = "x86")]
    let reg_name = "eax";

    #[cfg(target_arch = "x86_64")]
    let reg_name = "rax";

    let output_color = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg(format!("-f mov {}", reg_name))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_color_line_cnt = output_color.lines().count();

    let output_no_color = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-n")
            .arg(format!("-f mov {}", reg_name))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_no_color_line_cnt = output_no_color.lines().count();

    assert!(output_color_line_cnt == output_no_color_line_cnt);
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_extended_line_count() {
    let output_default = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_default_line_cnt = output_default.lines().count();

    let output_extended = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-e")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_extended_line_cnt = output_extended.lines().count();

    assert!(output_default_line_cnt == output_extended_line_cnt);
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_regex() {
    let pop_pop_ret_regex = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg(format!("-f {}", r"^(?:pop)(?:.*(?:pop))*.*ret"))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let reg_ctrl_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-ctrl")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    assert!(pop_pop_ret_regex.len() >= reg_ctrl_filter.len());
}
