use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

mod common;

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
            "the following required arguments were not provided:",
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
            "the argument '--rop' cannot be used with '--jop'",
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
            "the argument '--reg-pop' cannot be used with '--dispatcher'",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_conflicting_flags_fess_checksec() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/usr/bin/some_file_83bb57de34d8713f6e4940b4bdda4bea")
        .arg("--fess")
        .arg("--check-sec");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "the argument '--fess' cannot be used with '--check-sec'",
        ));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
#[cfg(target_os = "linux")]
fn test_invalid_bad_bytes() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/bin/cat")
        .arg("-b")
        .arg("0xff")
        .arg("0xgg");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains("InvalidDigit"));
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
#[cfg(target_os = "linux")]
fn test_invalid_reg_name() {
    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();

    xgadget_bin
        .arg("/bin/cat")
        .arg("--reg-overwrite")
        .arg("r42");

    xgadget_bin
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid register: \"r42\""));
}

// Non-exhaustive Success Cases ----------------------------------------------------------------------------------------

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_raw() {
    let mut raw_file = NamedTempFile::new().unwrap();
    raw_file.write_all(common::ADJACENT_JMP_X64).unwrap();

    let mut xgadget_bin = Command::cargo_bin("xgadget").unwrap();
    xgadget_bin.arg(raw_file.path());

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
    let output_rop_jop_sys = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_rop_jop_sys_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--all")
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

    assert!(output_rop_jop_sys_all.len() >= output_rop_jop_sys.len());
    assert!(output_rop_jop_sys.len() >= output_rop.len());
    assert!(output_rop_jop_sys.len() >= output_jop.len());
    assert!(output_rop_jop_sys.len() >= output_sys.len());
    assert!(output_rop_jop_sys.len() >= output_stack_pivot.len());
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
fn test_att_intel_syntax_line_count() {
    let output_intel = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("OUTPUT_INTEL: {}", output_intel);
    let output_intel_line_cnt = output_intel.lines().count();

    let output_att = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--att")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("OUTPUT_ATT: {}", output_att);
    let output_att_line_cnt = output_att.lines().count();

    assert!(output_intel_line_cnt == output_att_line_cnt);
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
fn test_dispatcher_filter() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_dispatch_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-d")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("DISPATCHER: {}", output_dispatch_filter);
    assert!(output_all.len() >= output_dispatch_filter.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_pop_filter() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_reg_pop_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-pop")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("REG_POP: {}", output_reg_pop_filter);
    assert!(output_all.len() >= output_reg_pop_filter.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_param_ctrl_filter() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_param_ctrl_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--param-ctrl")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("PARAM_CTRL: {}", output_param_ctrl_filter);
    assert!(output_all.len() >= output_param_ctrl_filter.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_no_read_filter_1() {
    let output_reg_no_read_rax_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-no-read")
            .arg(REG_NAME)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_reg_no_read_all_regs_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-no-read")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("REG_NO_READ_RAX: {}", output_reg_no_read_rax_filter);
    println!("REG_NO_READ: {}", output_reg_no_read_all_regs_filter);
    assert!(output_reg_no_read_rax_filter.len() >= output_reg_no_read_all_regs_filter.len());
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_no_read_filter_2() {
    let mut raw_file = NamedTempFile::new().unwrap();
    raw_file
        .write_all(common::FILTERS_REG_NO_DEREF_AND_REG_WRITE)
        .unwrap();

    let reg_no_read_1_reg = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-no-read")
            .arg("rdi")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let reg_no_read_2_regs = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-no-read")
            .arg("rdi")
            .arg("rsi")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let reg_no_read_any_regs = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-no-read")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("REG_NO_READ_1_REG: {}", reg_no_read_1_reg);
    println!("REG_NO_READ_2_REGS: {}", reg_no_read_2_regs);
    println!("REG_NO_READ_ANY_REGS: {}", reg_no_read_any_regs);
    assert!(reg_no_read_1_reg.lines().count() >= reg_no_read_2_regs.lines().count());
    assert!(reg_no_read_2_regs.lines().count() >= reg_no_read_any_regs.lines().count());

    assert!(reg_no_read_2_regs.contains("pop rsi; pop rdi; ret;"));
    assert!(reg_no_read_1_reg.contains("pop rsi; pop rdi; ret;"));

    assert!(reg_no_read_1_reg.contains("add r8, [rsi]; add r8, [rdx]; pop rsi; pop rdi; ret;"));
    assert!(reg_no_read_2_regs.contains("add r8, [rdx]; pop rsi; pop rdi; ret;"));
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_overwrite_filter_1() {
    let output_reg_write_rax_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-overwrite")
            .arg(REG_NAME)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_reg_write_all_regs_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-overwrite")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("REG_WRITE_RAX: {}", output_reg_write_rax_filter);
    println!("REG_WRITE_ALL: {}", output_reg_write_all_regs_filter);
    assert!(output_reg_write_all_regs_filter.len() >= output_reg_write_rax_filter.len());
}

#[test]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_overwrite_filter_2() {
    let mut raw_file = NamedTempFile::new().unwrap();
    raw_file
        .write_all(common::FILTERS_REG_NO_DEREF_AND_REG_WRITE)
        .unwrap();

    let ctrl_1_reg = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-overwrite")
            .arg("rsi")
            .arg("--max-len")
            .arg("25")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let ctrl_2_regs = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-overwrite")
            .arg("rsi")
            .arg("rdi")
            .arg("--max-len")
            .arg("25")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let ctrl_any_regs = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg(raw_file.path())
            .arg("--reg-overwrite")
            .arg("--max-len")
            .arg("25")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("CTRL_1_REG: {}", ctrl_1_reg);
    println!("CTRL_2_REGS: {}", ctrl_2_regs);
    println!("CTRL_ANY_REGS: {}", ctrl_any_regs);
    assert!(ctrl_any_regs.lines().count() >= ctrl_1_reg.lines().count());
    assert!(ctrl_1_reg.lines().count() >= ctrl_2_regs.lines().count());

    assert!(ctrl_any_regs.contains("pop rsi; pop rdi; ret;"));
    assert!(ctrl_1_reg.contains("pop rsi; pop rdi; ret;"));
    assert!(ctrl_2_regs.contains("pop rsi; pop rdi; ret;"));

    // Note: not unique to this result
    assert!(ctrl_any_regs
        .contains("add r8, [rdi]; add r8, [rsi]; add r8, [rdx]; pop rsi; pop rdi; ret;"));
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_bad_bytes_filter() {
    let output_all_bytes = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_bad_bytes = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("-b")
            .arg("0x40")
            .arg("0x55")
            .arg("ff")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL_BYTES: {}", output_all_bytes);
    println!("BAD_BYTES: {}", output_bad_bytes);
    assert!(output_all_bytes.len() >= output_bad_bytes.len());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_reg_equivalence() {
    let reg_no_deref_r8l_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-no-read")
            .arg("r8l")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let reg_no_deref_r8b_filter = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat")
            .arg("--reg-no-read")
            .arg("r8b")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("REG_NO_DEREF_R8L: {}", reg_no_deref_r8l_filter);
    println!("REG_NO_DEREF_R8B: {}", reg_no_deref_r8b_filter);
    assert!(reg_no_deref_r8l_filter.lines().count() == reg_no_deref_r8b_filter.lines().count());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_0() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .arg("--reg-only")
            .arg("--reg-overwrite")
            .arg("rdi")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("README_0: {}", output_readme);
    assert!(!output_readme.is_empty());
    assert!(output_all.len() >= output_readme.len());
}
#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_1() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .arg("--jop")
            .arg("--reg-pop")
            .arg("--att")
            .arg("--max-len")
            .arg("10")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("README_1: {}", output_readme);
    assert!(!output_readme.is_empty());
    assert!(output_all.len() >= output_readme.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_2() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .arg("--regex-filter")
            .arg("^(?:pop)(?:.*(?:pop))*.*(?:call|jmp)")
            .arg("--att")
            .arg("--max-len")
            .arg("10")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("README_2: {}", output_readme);
    assert!(!output_readme.is_empty());
    assert!(output_all.len() >= output_readme.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_3() {
    let output_all = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .arg("--rop")
            .arg("--reg-overwrite")
            .arg("rdi")
            .arg("--reg-no-read")
            .arg("rsi")
            .arg("rdx")
            .arg("--bad-bytes")
            .arg("0x32")
            .arg("0x0d")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("ALL: {}", output_all);
    println!("README_3: {}", output_readme);
    assert!(!output_readme.is_empty());
    assert!(output_all.len() >= output_readme.len());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_4() {
    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/usr/bin/sudo")
            .arg("/bin/cat") // http may not be installed
            .arg("--check-sec")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("README_4: {}", output_readme);
    assert!(!output_readme.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "cli-bin"), ignore)]
fn test_readme_5() {
    let output_readme = String::from_utf8(
        Command::cargo_bin("xgadget")
            .unwrap()
            .arg("/bin/cat") // http may not be installed
            .arg("--symbols")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    println!("README_4: {}", output_readme);
    assert!(!output_readme.is_empty());
}
