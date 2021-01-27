use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

mod common;

// TODO: make sure every flag has a test
// TODO: pipe to tempfile test, check that color and no-color are equivalent

// TARGET-SPECIFIC PARAMS ----------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
static REG_NAME: &str = "eax";

#[cfg(target_arch = "x86_64")]
static REG_NAME: &str = "rax";

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
        .arg("--reg-pop")
        .arg("-d");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The argument '--dispatcher' cannot be used with '--reg-pop'",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_conflicting_flags_imm16_jop() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("--inc-imm16")
        .arg("-j");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "The argument '--jop' cannot be used with '--inc-imm16'",
        ));
}

// Non-exhaustive Success Cases ----------------------------------------------------------------------------------------

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_raw() {
    let mut raw_file = NamedTempFile::new().unwrap();
    raw_file.write(common::ADJACENT_JMP_X64).unwrap();

    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();
    xgadget_bin.arg(raw_file.path()).arg("-n");

    xgadget_bin
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "lea ecx, [rip+0x5ddcb]; jmp qword ptr [rcx];",
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
            .arg("--inc-imm16")
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

    // TODO: below are filters, separate category, move
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

    let output_reg_pop = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-pop")
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
    assert!(output_all.len() >= output_reg_pop.len());
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
    let output_color = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-f")
            .arg(format!("mov {}", REG_NAME))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("OUTPUT_COLOR: {}", output_color);
    let output_color_line_cnt = output_color.lines().count();

    let output_no_color = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-n")
            .arg("-f")
            .arg(format!("mov {}", REG_NAME))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("OUTPUT_NO_COLOR: {}", output_no_color);
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

    println!("OUTPUT_DEFAULT: {}", output_default);
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

    println!("OUTPUT_EXTENDED: {}", output_extended);
    let output_extended_line_cnt = output_extended.lines().count();

    assert!(output_default_line_cnt == output_extended_line_cnt);
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_regex() {
    let reg_pop_regex = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-f")
            .arg(r"^(?:pop)(?:.*(?:pop))*.*(?:ret|call|jmp)")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let reg_pop_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-pop")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("REG_POP_REGEX: {}", reg_pop_regex);
    println!("REG_POP_FILTER: {}", reg_pop_filter);
    assert!(reg_pop_regex.len() >= reg_pop_filter.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_no_deref() {
    let no_deref_rax_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--no-deref")
            .arg(REG_NAME)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let no_deref_all_regs_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--no-deref")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("NO_DEREF_RAX: {}", no_deref_rax_filter);
    println!("NO_DEREF: {}", no_deref_all_regs_filter);
    assert!(no_deref_rax_filter.len() >= no_deref_all_regs_filter.len());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_equivalence() {
    let no_deref_r8l_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--no-deref")
            .arg("r8l")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let no_deref_r8b_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--no-deref")
            .arg("r8b")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("NO_DEREF_R8L: {}", no_deref_r8l_filter);
    println!("NO_DEREF_R8B: {}", no_deref_r8b_filter);
    assert!(no_deref_r8l_filter.lines().count() == no_deref_r8b_filter.lines().count());
}
