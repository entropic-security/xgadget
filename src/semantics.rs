//! Determine attack-relevant instruction semantics

// Instruction Categorization for Attacker Use -------------------------------------------------------------------------

/// Check if instruction is a ROP/JOP/SYS gadget tail
pub fn is_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_rop_gadget_tail(instr) || is_jop_gadget_tail(instr) || is_sys_gadget_tail(instr)
}

/// Check if instruction is a ROP gadget tail
pub fn is_rop_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr)
}

/// Check if instruction is a JOP gadget tail
pub fn is_jop_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_indirect_call(instr) || is_indirect_jmp(instr)
}

/// Check if instruction is a SYS gadget tail, in general
pub fn is_sys_gadget_tail(instr: &iced_x86::Instruction) -> bool {
    is_syscall(instr) || is_sysret(instr)
}

/// Check if instruction should exist in a gadget body.
/// If `all == false`, the following instructions are excluded for cleaner output:
///
/// * Direct branches
/// * Direct calls
/// * Returns
/// * Interrupts
/// * Repetition pre-fixed instructions
pub fn is_gadget_body(instr: &iced_x86::Instruction, all: bool) -> bool {
    let instr_flow = instr.flow_control();

    // Invalid instruction
    if instr_flow == iced_x86::FlowControl::Exception {
        return false;
    }

    if !all {
        // Flow control doesn't reach gadget tail
        if matches!(
            instr_flow,
            iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::ConditionalBranch
                | iced_x86::FlowControl::Call
                | iced_x86::FlowControl::Return
                | iced_x86::FlowControl::Interrupt
        ) {
            return false;
        }

        // Prefixes which repeat instruction, making the gadget hard to reason about
        // See: https://wiki.osdev.org/X86-64_Instruction_Encoding#Legacy_Prefixes
        if instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix() {
            return false;
        }
    }

    !is_gadget_tail(instr)
}

// TODO: should these be made private? Which should be removed entirely? What about trait impls for public APIs?

// General Instruction Categorization ----------------------------------------------------------------------------------

/// Check if call instruction with register-controlled target
pub fn is_indirect_call(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectCall) && (is_reg_ops_only(instr))
}

/// Check if jump instruction with register-controlled target
pub fn is_indirect_jmp(instr: &iced_x86::Instruction) -> bool {
    (instr.flow_control() == iced_x86::FlowControl::IndirectBranch) && (is_reg_ops_only(instr))
}

/// Check if syscall/sysenter instruction
pub fn is_syscall(instr: &iced_x86::Instruction) -> bool {
    match instr.mnemonic() {
        // `int 0x80` -> 32-bit Linux
        // `int 0x2e` -> 32-bit Windows
        // For API simplicity, don't take `Binary` as an argument to make this result OS/bit-ness sensitive.
        // False positives should be rare enough these days :)
        iced_x86::Mnemonic::Int => matches!(instr.try_immediate(0), Ok(0x80) | Ok(0x2e)),
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

/// Check if instruction has register (controllable) operands only
pub fn is_reg_ops_only(instr: &iced_x86::Instruction) -> bool {
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

// Crate-private Helpers -----------------------------------------------------------------------------------------------

/// Check if return instruction
pub(crate) fn is_ret(instr: &iced_x86::Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Retf
    )
}

/// Check if return instruction that adds to stack pointer
pub(crate) fn is_ret_imm16(instr: &iced_x86::Instruction) -> bool {
    is_ret(instr) && (instr.op_count() != 0)
}
