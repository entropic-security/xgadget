mod common;

/*
#[test]
fn test_regs_deref() {
    let bin_pshape = common::get_raw_bin("pshape_example", &common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets = xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::DEFAULT).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x0));
    assert!(gadgets.len() == 1);

    let gadget_analysis = xgadget::gadget::GadgetAnalysis::new(&gadgets[0]);

    // TODO: Debug!
    for um in gadget_analysis.regs_dereferenced() {
        println!("{:?}", um);
    }
    assert!(gadget_analysis.regs_dereferenced().len() == 2);
}
*/
