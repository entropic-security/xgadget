// Constructs for attacker control -------------------------------------------------------------------------------------

/// Check if instruction's sole operand is a register
#[inline(always)]
pub fn is_single_reg(instr: &zydis::DecodedInstruction) -> bool {

    let regs_read_cnt = instr.operands.iter().filter(|&o| {
        (o.action == zydis::enums::OperandAction::READ)
        && (o.ty == zydis::enums::OperandType::REGISTER)
        }).count();

    regs_read_cnt == 1
}

/// Check if instruction's sole operand is a register-controlled memory deref
#[inline(always)]
pub fn is_single_reg_deref(instr: &zydis::DecodedInstruction) -> bool {

    let regs_deref_cnt = instr.operands.iter().filter(|&o| {
        (o.action == zydis::enums::OperandAction::READ)
        && (o.ty == zydis::enums::OperandType::MEMORY)
        && (o.mem.base != zydis::Register::NONE)
        }).count();

    regs_deref_cnt == 1
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_set_call(instr: &zydis::DecodedInstruction) -> bool {
    is_call(&instr)
    && is_single_reg(&instr)
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_set_jmp(instr: &zydis::DecodedInstruction) -> bool {
    is_jmp(&instr)
    && is_single_reg(&instr)
}

/// Check if jump instruction with register-controlled memory deref target
#[inline(always)]
pub fn is_mem_ptr_set_jmp(instr: &zydis::DecodedInstruction) -> bool {
    is_jmp(&instr)
    && is_single_reg_deref(&instr)
}

/// Check if call instruction with register-controlled memory deref target
#[inline(always)]
pub fn is_mem_ptr_set_call(instr: &zydis::DecodedInstruction) -> bool {
    is_call(&instr)
    && is_single_reg_deref(&instr)
}

/// Check if instruction is a ROP/JOP/SYS gadget tail
#[inline(always)]
pub fn is_gadget_tail(instr: &zydis::DecodedInstruction) -> bool {
    is_ret(instr)
    || is_jop_gadget_tail(instr)
    || is_sys_gadget_tail(instr)
}

/// Check if instruction is a JOP gadget tail
#[inline(always)]
pub fn is_jop_gadget_tail(instr: &zydis::DecodedInstruction) -> bool {
    is_reg_set_jmp(instr)
    || is_reg_set_call(instr)
    || is_mem_ptr_set_jmp(instr)
    || is_mem_ptr_set_call(instr)
}

/// Check if instruction is a SYS gadget tail
#[inline(always)]
pub fn is_sys_gadget_tail(instr: &zydis::DecodedInstruction) -> bool {
    is_syscall(instr)
    || is_linux_syscall(instr)
}

// Categorization ------------------------------------------------------------------------------------------------------

/// Check if return instruction
#[inline(always)]
pub fn is_ret(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::RET
}

/// Check if call instruction
#[inline(always)]
pub fn is_call(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::CALL
}

/// Check if jmp instruction
pub fn is_jmp(instr: &zydis::DecodedInstruction) -> bool {
    instr.mnemonic == zydis::enums::Mnemonic::JMP
}

/// Check if interrupt instruction
#[inline(always)]
pub fn is_int(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::INTERRUPT
}

/// Check if syscall instruction
#[inline(always)]
pub fn is_syscall(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::SYSCALL
}

/// Inline check if Linux syscall instruction
#[inline(always)]
pub fn is_linux_syscall(instr: &zydis::DecodedInstruction) -> bool {

     let imm_0x80_cnt = instr.operands.iter().filter(|&o| {
        (o.action == zydis::enums::OperandAction::READ)
        && (o.ty == zydis::enums::OperandType::IMMEDIATE)
        && (o.imm.value == 0x80)
        }).count();

    (instr.meta.category == zydis::enums::InstructionCategory::INTERRUPT)
    && (imm_0x80_cnt == 1)
}