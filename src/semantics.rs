//! Determine attack-relevant instruction semantics

// Constructs for attacker control -------------------------------------------------------------------------------------

/// Check if instruction is a ROP/JOP/SYS gadget tail
pub fn is_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr) || is_jop_gadget_tail(instr) || is_sys_gadget_tail(instr)
}

/// Check if instruction is a JOP gadget tail
pub fn is_jop_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_reg_indirect_call(instr) || is_reg_indirect_jmp(instr)
}

/// Check if instruction is a SYS gadget tail, in general
pub fn is_sys_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_syscall(instr)
}

// Categorization ------------------------------------------------------------------------------------------------------

/// Check if call instruction with register-controlled target
pub fn is_reg_indirect_call(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectCall) && (has_reg_ops_only(instr))
}

/// Check if jump instruction with register-controlled target
pub fn is_reg_indirect_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectBranch) && (has_reg_ops_only(instr))
}

/// Check if return instruction
pub fn is_ret(instr: &iced_x86::Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Retf
    )
}

/// Check if return instruction that adds to stack pointer
pub fn is_ret_imm16(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr) && (instr.op_count() != 0)
}

/// Check if direct call instruction
pub fn is_direct_call(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Call) && (!is_reg_indirect_call(instr))
}

/// Check if unconditional jmp instruction
pub fn is_uncond_fixed_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.mnemonic() == iced_x86::Mnemonic::Jmp) && (!is_reg_indirect_jmp(instr))
}

/// Check if interrupt instruction
pub fn is_int(instr: &iced_x86::Instruction) -> bool {
    instr.flow_control() == iced_x86::FlowControl::Interrupt
}

/// Check if syscall/sysenter instruction
pub fn is_syscall(instr: &iced_x86::Instruction) -> bool {
    match instr.mnemonic() {
        iced_x86::Mnemonic::Int => matches!(instr.try_immediate(0), Ok(0x80)),
        iced_x86::Mnemonic::Syscall | iced_x86::Mnemonic::Sysenter => true,
        _ => false,
    }
}

/// Check if sysret/sysexit instruction
pub fn is_sysret(instr: &iced_x86::Instruction) -> bool {
    match instr.mnemonic() {
        iced_x86::Mnemonic::Iret
        | iced_x86::Mnemonic::Iretd
        | iced_x86::Mnemonic::Iretq
        | iced_x86::Mnemonic::Sysexit
        | iced_x86::Mnemonic::Sysexitq
        | iced_x86::Mnemonic::Sysret
        | iced_x86::Mnemonic::Sysretq => true,
        _ => false,
    }
}

// Register usage ------------------------------------------------------------------------------------------------------

/// Check if instruction both reads and writes the same register
pub fn is_reg_rw(instr: &iced_x86::Instruction, reg: &iced_x86::Register) -> bool {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let info = info_factory.info_options(instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);
    let reg_rw = iced_x86::UsedRegister::new(*reg, iced_x86::OpAccess::ReadWrite);

    info.used_registers().contains(&reg_rw)
}

/// Check if sets register from another register or stack (e.g. exclude constant write)
pub fn is_reg_set(instr: &iced_x86::Instruction, reg: &iced_x86::Register) -> bool {
    let mut info_factory = iced_x86::InstructionInfoFactory::new();
    let info = info_factory.info_options(instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);
    let reg_w = iced_x86::UsedRegister::new(*reg, iced_x86::OpAccess::Write);

    if info.used_registers().iter().any(|ur| {
        matches!(
            ur.access(),
            iced_x86::OpAccess::Read | iced_x86::OpAccess::ReadWrite
        )
    }) && info.used_registers().contains(&reg_w)
    {
        return true;
    }

    false
}

/// Check if instruction has controllable operands only
pub fn has_reg_ops_only(instr: &iced_x86::Instruction) -> bool {
    let op_cnt = instr.op_count();
    for op_idx in 0..op_cnt {
        match instr.try_op_kind(op_idx) {
            Ok(kind) => match kind {
                // Direct register use
                iced_x86::OpKind::Register => {}
                // Register dereference
                iced_x86::OpKind::Memory => {
                    if matches!(
                        instr.memory_base(),
                        iced_x86::Register::None
                            // | iced_x86::Register::IP // TODO: why missing?
                            | iced_x86::Register::EIP
                            | iced_x86::Register::RIP
                    ) {
                        return false;
                    }
                }
                _ => return false,
            },
            _ => return false,
        }
    }

    op_cnt > 0
}
