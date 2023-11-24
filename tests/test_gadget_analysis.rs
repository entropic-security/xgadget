use xgadget::{Binary, GadgetType};

mod common;

fn get_reg_sensitive_data_bin<'a>() -> Binary {
    #[allow(dead_code)]
    #[rustfmt::skip]
    const REG_SENSITIVE_TEST_SET: &[u8] = &[
        0x48, 0x89, 0xd8,                                       // 0x0: mov rax,rbx
        0xc3,                                                   // 0x3: ret
        0x48, 0x81, 0xc1, 0xff, 0x00, 0x00, 0x00,               // 0x4: add rcx,0xff
        0xc3,                                                   // 0xb: ret
        0x48, 0x39, 0xc8,                                       // 0xc: cmp rax,rcx
        0xc3,                                                   // 0xf: ret
    ];

    Binary::from_bytes("reg_sensitive", REG_SENSITIVE_TEST_SET).unwrap()
}

#[test]
fn test_set_reg_overwrite() {
    let bins = &[get_reg_sensitive_data_bin()];

    let gadgets =
        xgadget::find_gadgets(bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    let mov_rax_gadget = gadgets
        .iter()
        .filter(|g| g.full_matches().contains(&0x0))
        .collect::<Vec<_>>();

    assert!(mov_rax_gadget.len() == 1);
    let mov_rax_gadget = mov_rax_gadget.first().unwrap();

    let analysis = mov_rax_gadget.analysis();
    assert_eq!(analysis.ty(), GadgetType::Rop);
    assert!(analysis.regs_overwritten(true).len() == 1);
    assert!(analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RAX));
    assert!(!analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RBX));

    assert!(analysis.regs_read().contains(&iced_x86::Register::RBX));
    assert!(!analysis.regs_read().contains(&iced_x86::Register::RAX));
}

#[test]
fn test_set_reg_read() {
    let bins = &[get_reg_sensitive_data_bin()];

    let gadgets =
        xgadget::find_gadgets(bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    let cmp_rax_rcx_gadget = gadgets
        .iter()
        .filter(|g| g.full_matches().contains(&0xc))
        .collect::<Vec<_>>();

    assert!(cmp_rax_rcx_gadget.len() == 1);
    let cmp_rax_rcx = cmp_rax_rcx_gadget.first().unwrap();

    let analysis = cmp_rax_rcx.analysis();
    assert_eq!(analysis.ty(), GadgetType::Rop);
    assert!(analysis.regs_read().len() == 3); // TODO: why RSP?

    assert!(analysis.regs_read().contains(&iced_x86::Register::RAX));
    assert!(analysis.regs_read().contains(&iced_x86::Register::RCX));

    assert!(!analysis.regs_updated().contains(&iced_x86::Register::RAX));
    assert!(!analysis.regs_updated().contains(&iced_x86::Register::RCX));

    assert!(!analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RAX));
    assert!(!analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RCX));
}

#[test]
fn test_set_reg_update() {
    let bins = &[get_reg_sensitive_data_bin()];

    let gadgets =
        xgadget::find_gadgets(bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    let add_rcx_0xff = gadgets
        .iter()
        .filter(|g| g.full_matches().contains(&0x4))
        .collect::<Vec<_>>();

    assert!(add_rcx_0xff.len() == 1);
    let add_rcx_0xff = add_rcx_0xff.first().unwrap();

    let analysis = add_rcx_0xff.analysis();
    assert_eq!(analysis.ty(), GadgetType::Rop);

    assert!(analysis.regs_updated().len() == 2); // TODO: RSP?
    assert!(analysis.regs_updated().contains(&iced_x86::Register::RCX));

    assert!(analysis.regs_read().contains(&iced_x86::Register::RCX));

    assert!(!analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RCX));
}

#[test]
fn test_regs_deref() {
    let bin_pshape = common::get_raw_bin("pshape_example", common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x0));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_reg_no_deref(gadgets.clone(), None).is_empty());

    let analysis = gadgets[0].analysis();

    assert!(analysis.regs_dereferenced().len() == 3);
    assert!(analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RAX));
    assert!(analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RCX));
    assert!(analysis
        .regs_dereferenced()
        .contains(&iced_x86::Register::RSP));

    assert!(analysis.regs_dereferenced_mem_write().len() == 2);
    assert!(analysis
        .regs_dereferenced_mem_write()
        .contains(&iced_x86::Register::RAX));
    assert!(analysis
        .regs_dereferenced_mem_write()
        .contains(&iced_x86::Register::RCX));

    assert!(analysis.regs_dereferenced_mem_read().len() == 2);
    assert!(analysis
        .regs_dereferenced_mem_read()
        .contains(&iced_x86::Register::RCX));
    assert!(analysis
        .regs_dereferenced_mem_read()
        .contains(&iced_x86::Register::RSP));
}

#[test]
fn test_regs_updated() {
    let bin_pshape = common::get_raw_bin("pshape_example", common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x24));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_reg_no_deref(gadgets.clone(), None).is_empty());

    let analysis = gadgets[0].analysis();

    assert!(analysis.regs_updated().len() == 2);
    assert!(analysis.regs_updated().contains(&iced_x86::Register::RAX));
    assert!(analysis.regs_updated().contains(&iced_x86::Register::RSP));
}

#[test]
fn test_regs_overwritten() {
    let bin_pshape = common::get_raw_bin("pshape_example", common::PSHAPE_PG_5_X64);
    let bins = vec![bin_pshape];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x20));
    assert!(gadgets.len() == 1);
    assert!(xgadget::filter_reg_no_deref(gadgets.clone(), None).is_empty());

    let analysis = gadgets[0].analysis();

    assert!(analysis.regs_overwritten(true).len() == 1);
    assert!(analysis
        .regs_overwritten(true)
        .contains(&iced_x86::Register::RAX));
}

#[test]
fn test_reg_no_deref_1() {
    let bin_misc_1 = common::get_raw_bin("misc_1", common::MISC_1);
    let bins = vec![bin_misc_1];
    let mut gadgets =
        xgadget::find_gadgets(&bins, common::MAX_LEN, xgadget::SearchConfig::default()).unwrap();

    gadgets.retain(|g| g.full_matches().contains(&0x0));
    assert!(gadgets.len() == 1);

    let analysis = gadgets[0].analysis();
    assert!(!analysis.regs_dereferenced().is_empty());

    for instr in gadgets[0].instrs() {
        common::dump_instr(instr);
    }

    assert!(xgadget::filter_reg_no_deref(gadgets, None).is_empty());
}
