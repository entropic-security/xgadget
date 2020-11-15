// Constructs for attacker control -------------------------------------------------------------------------------------

/// Check if instruction is a ROP/JOP/SYS gadget tail
#[inline(always)]
pub fn is_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr) || is_jop_gadget_tail(instr) || is_sys_gadget_tail(instr)
}

/// Check if instruction is a JOP gadget tail
#[inline(always)]
pub fn is_jop_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_reg_indirect_call(instr) || is_reg_indirect_jmp(instr)
}

/// Check if instruction is a SYS gadget tail
#[inline(always)]
pub fn is_sys_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_syscall(instr) || is_legacy_linux_syscall(instr)
}

// Categorization ------------------------------------------------------------------------------------------------------

/// Check if call instruction with register-controlled target
#[inline(always)]
pub fn is_reg_indirect_call(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectCall)
        && ((instr.op0_kind() == iced_x86::OpKind::Register)
            || ((instr.op0_kind() == iced_x86::OpKind::Memory)
                && instr.memory_base() != iced_x86::Register::None))
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_indirect_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectBranch)
        && ((instr.op0_kind() == iced_x86::OpKind::Register)
            || ((instr.op0_kind() == iced_x86::OpKind::Memory)
                && instr.memory_base() != iced_x86::Register::None))
}

/// Check if return instruction
#[inline(always)]
pub fn is_ret(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Ret) || (instr.mnemonic() == iced_x86::Mnemonic::Retf)
}

/// Check if return instruction that adds to stack pointer
#[inline(always)]
pub fn is_ret_imm16(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr) && (instr.op_count() != 0)
}

/// Check if call instruction
#[inline(always)]
pub fn is_fixed_call(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Call) && (!is_reg_indirect_call(instr))
}

/// Check if unconditional jmp instruction
pub fn is_uncond_fixed_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Jmp) && (!is_reg_indirect_jmp(instr))
}

/// Check if interrupt instruction
#[inline(always)]
pub fn is_int(instr: &iced_x86::Instruction) -> bool {
    instr.flow_control() == iced_x86::FlowControl::Interrupt
}

/// Check if interrupt instruction that specifies vector
#[inline(always)]
pub fn is_int_imm8(instr: &iced_x86::Instruction) -> bool {
    instr.mnemonic() == iced_x86::Mnemonic::Int
}

/// Check if syscall/sysenter instruction
#[inline(always)]
pub fn is_syscall(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Syscall)
        || (instr.mnemonic() == iced_x86::Mnemonic::Sysenter)
}

/// Check if legacy Linux syscall
#[inline(always)]
pub fn is_legacy_linux_syscall(instr: &iced_x86::Instruction) -> bool {
    is_int_imm8(instr) && (instr.immediate(0) == 0x80)
}

// Properties ----------------------------------------------------------------------------------------------------------

/// Check if instruction both reads and writes the same register
#[inline(always)]
pub fn is_reg_rw(instr: &iced_x86::Instruction, reg: &iced_x86::Register) -> bool {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let info = info_factory.info_options(&instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);
    let reg_rw = iced_x86::UsedRegister::new(*reg, iced_x86::OpAccess::ReadWrite);

    info.used_registers().contains(&reg_rw)
}
