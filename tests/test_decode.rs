mod common;

fn dbg_print_instr(instr: &iced_x86::Instruction) {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    println!("\nInstruction: {:#x?}", instr);
    println!(
        "\nUsed Registers: {:#x?}",
        info_factory.info(instr).used_registers()
    );
    println!(
        "\nUsed Memory: {:#x?}",
        info_factory.info(instr).used_memory()
    );
}

#[test]
fn test_xchg_rsp_rax() {
    let xchg_rsp_rax: [u8; 2] = [0x48, 0x94];
    let instr = common::decode_single_x64_instr(0, &xchg_rsp_rax);
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let used_regs = info_factory.info(&instr).used_registers();

    dbg_print_instr(&instr);
    assert!(used_regs.iter().any(|ur| *ur
        == iced_x86::UsedRegister::new(iced_x86::Register::RAX, iced_x86::OpAccess::ReadWrite)));
}

#[test]
fn test_xor_eax_const() {
    let xor_eax_const: [u8; 5] = [0x35, 0x0B, 0xE3, 0xFF, 0xFF];
    let instr = common::decode_single_x64_instr(0, &xor_eax_const);
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let used_regs = info_factory.info(&instr).used_registers();

    dbg_print_instr(&instr);
    assert!(used_regs
        .iter()
        .any(|ur| *ur
            == iced_x86::UsedRegister::new(iced_x86::Register::RAX, iced_x86::OpAccess::Write)));
}

#[test]
fn test_xor_eax_eax() {
    let xor_eax_eax: [u8; 3] = [0x31, 0xC0, 0xC3];
    let instr = common::decode_single_x64_instr(0, &xor_eax_eax);
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let used_regs = info_factory.info(&instr).used_registers();

    dbg_print_instr(&instr);
    assert!(used_regs
        .iter()
        .any(|ur| *ur
            == iced_x86::UsedRegister::new(iced_x86::Register::RAX, iced_x86::OpAccess::Write)));
}

#[test]
fn test_xor_al_ch() {
    let xor_al_ch: [u8; 5] = [0x30, 0xE8, 0xC2, 0x06, 0xFF];
    let instr = common::decode_single_x64_instr(0, &xor_al_ch);
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let _used_regs = info_factory.info(&instr).used_registers();

    dbg_print_instr(&instr);

    // TODO: for filters, introduce sub-register concept

    /*
    TODO: upstream inconsistency?
    assert!(used_regs
        .iter()
        .any(|ur| *ur
            == iced_x86::UsedRegister::new(iced_x86::Register::RAX, iced_x86::OpAccess::Write)));
    */
}

#[test]
fn test_ip_deref_read() {
    let mov_rax_ip_offset: [u8; 7] = [0x48, 0x8B, 0x05, 0xA6, 0x33, 0x02, 0x00];
    let instr = common::decode_single_x64_instr(0, &mov_rax_ip_offset);

    dbg_print_instr(&instr);
    assert_eq!(instr.memory_base(), iced_x86::Register::RIP)
}
