mod common;

#[test]
fn test_regs_deref() {
    let bin_pshape = common::get_raw_bin("pshape_example", &common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x0));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_no_deref(&gadgets, None).is_empty());

    let gadget_analysis = xgadget::gadget::GadgetAnalysis::new(&gadgets[0]);

    assert!(gadget_analysis.regs_dereferenced().len() == 3);
    assert!(gadget_analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RAX));
    assert!(gadget_analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RCX));
    assert!(gadget_analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RSP));

    assert!(gadget_analysis.regs_dereferenced_write().len() == 2);
    assert!(gadget_analysis
        .regs_dereferenced_write()
        .contains(&iced_x86::Register::RAX));
    assert!(gadget_analysis
        .regs_dereferenced_write()
        .contains(&iced_x86::Register::RCX));

    assert!(gadget_analysis.regs_dereferenced_read().len() == 2);
    assert!(gadget_analysis
        .regs_dereferenced_read()
        .contains(&iced_x86::Register::RCX));
    assert!(gadget_analysis
        .regs_dereferenced_read()
        .contains(&iced_x86::Register::RSP));
}

#[test]
fn test_regs_updated() {
    let bin_pshape = common::get_raw_bin("pshape_example", &common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x24));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_no_deref(&gadgets, None).is_empty());

    let gadget_analysis = xgadget::gadget::GadgetAnalysis::new(&gadgets[0]);

    assert!(gadget_analysis.regs_updated().len() == 2);
    assert!(gadget_analysis
        .regs_updated()
        .contains(&iced_x86::Register::RAX));
    assert!(gadget_analysis
        .regs_updated()
        .contains(&iced_x86::Register::RSP));
}

#[test]
fn test_regs_overwritten() {
    let bin_pshape = common::get_raw_bin("pshape_example", &common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x20));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_no_deref(&gadgets, None).is_empty());

    let gadget_analysis = xgadget::gadget::GadgetAnalysis::new(&gadgets[0]);

    assert!(gadget_analysis.regs_overwritten().len() == 1);
    assert!(gadget_analysis
        .regs_overwritten()
        .contains(&iced_x86::Register::RAX));
}

#[test]
fn test_no_deref_1() {
    let bin_misc_1 = common::get_raw_bin("misc_1", &common::MISC_1);
    let bins = vec![bin_misc_1];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x0));
    assert!(gadgets.len() == 1);

    let gadget_analysis = xgadget::gadget::GadgetAnalysis::new(&gadgets[0]);
    assert!(!gadget_analysis.regs_dereferenced().is_empty());

    for instr in gadgets[0].instrs() {
        common::dump_instr(&instr);
    }

    assert!(xgadget::filter_no_deref(&gadgets, None).is_empty());
}