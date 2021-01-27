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
    (instr.flow_control() == iced_x86::FlowControl::IndirectCall) && (has_ctrled_ops(instr))
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_indirect_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectBranch) && (has_ctrled_ops(instr))
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

/// Check if direct call instruction
#[inline(always)]
pub fn is_direct_call(instr: &iced_x86::Instruction) -> bool {
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

/// Check if syscall/sysenter instruction
#[inline(always)]
pub fn is_syscall(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Syscall)
        || (instr.mnemonic() == iced_x86::Mnemonic::Sysenter)
}

/// Check if legacy Linux syscall
#[inline(always)]
pub fn is_legacy_linux_syscall(instr: &iced_x86::Instruction) -> bool {
    match instr.try_immediate(0) {
        Ok(imm) => (imm == 0x80) && (instr.mnemonic() == iced_x86::Mnemonic::Int),
        _ => false,
    }
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

/// Check if sets register from another register or stack (e.g. exclude constant write)
#[inline(always)]
pub fn is_reg_set(instr: &iced_x86::Instruction, reg: &iced_x86::Register) -> bool {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let info = info_factory.info_options(&instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);
    let reg_w = iced_x86::UsedRegister::new(*reg, iced_x86::OpAccess::Write);

    let reg_read = |ur: iced_x86::UsedRegister| {
        ur.access() == iced_x86::OpAccess::Read || ur.access() == iced_x86::OpAccess::ReadWrite
    };

    if info.used_registers().iter().any(|ur| reg_read(*ur))
        && info.used_registers().contains(&reg_w)
    {
        return true;
    }

    false
}

// TODO: add test
/// Check if instruction has a controllable operands
#[inline(always)]
pub fn has_ctrled_ops(instr: &iced_x86::Instruction) -> bool {
    let op_cnt = instr.op_count();
    for op_idx in 0..op_cnt {
        match instr.try_op_kind(op_idx) {
            Ok(kind) => match kind {
                iced_x86::OpKind::Register => continue,
                iced_x86::OpKind::Memory => match instr.memory_base() {
                    iced_x86::Register::None => return false,
                    iced_x86::Register::RIP => return false,
                    iced_x86::Register::EIP => return false,
                    //iced_x86::Register::IP => false, // TODO: why missing?
                    _ => continue,
                },
                _ => return false,
            },
            _ => return false,
        }
    }

    op_cnt > 0
}
