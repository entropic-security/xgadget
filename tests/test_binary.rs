use xgadget;
mod test_utils;

#[cfg(target_os = "linux")]
#[test]
fn test_elf() {
    let bin = xgadget::Binary::from_path_str("/bin/cat").unwrap();
    assert_eq!(bin.name, "cat");
    assert_eq!(bin.format, xgadget::Format::ELF);

    #[cfg(target_arch = "x86")]
    assert_eq!(bin.arch, xgadget::Arch::X86);

    #[cfg(target_arch = "x86_64")]
    assert_eq!(bin.arch, xgadget::Arch::X64);

    // bin.entry and bin.segments is version dependant

    // Regardless of version, should find some gadgets
    let bins = vec![bin];
    let gadgets = xgadget::find_gadgets(&bins, 5, xgadget::SearchConfig::DEFAULT).unwrap();
    assert!(gadgets.len() > 0);
}