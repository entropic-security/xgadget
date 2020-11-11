// Constructs for attacker control -------------------------------------------------------------------------------------

/// Check if instruction reads single register
#[inline(always)]
pub fn is_single_reg_read(instr: &zydis::DecodedInstruction) -> bool {
    let reg_read_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action == zydis::enums::OperandAction::READ)
                && (o.ty == zydis::enums::OperandType::REGISTER)
        })
        .count();

    reg_read_cnt == 1
}

/// Check if instruction writes single register
#[inline(always)]
pub fn is_single_reg_write(instr: &zydis::DecodedInstruction) -> bool {
    let reg_write_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action == zydis::enums::OperandAction::WRITE)
                && (o.ty == zydis::enums::OperandType::REGISTER)
        })
        .count();

    reg_write_cnt == 1
}

/// Check if instruction reads single register-controlled memory location
#[inline(always)]
pub fn is_single_reg_deref_read(instr: &zydis::DecodedInstruction) -> bool {
    let reg_deref_read_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action == zydis::enums::OperandAction::READ)
                && (o.ty == zydis::enums::OperandType::MEMORY)
                && (o.mem.base != zydis::Register::NONE)
        })
        .count();

    reg_deref_read_cnt == 1
}

/// Check if instruction writes single register-controlled memory location
#[inline(always)]
pub fn is_single_reg_deref_write(instr: &zydis::DecodedInstruction) -> bool {
    let reg_deref_write_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action == zydis::enums::OperandAction::WRITE)
                && (o.ty == zydis::enums::OperandType::MEMORY)
                && (o.mem.base != zydis::Register::NONE)
        })
        .count();

    reg_deref_write_cnt == 1
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_set_call(instr: &zydis::DecodedInstruction) -> bool {
    is_call(&instr) && is_single_reg_read(&instr)
}

/// Check if jump instruction with register-controlled target
#[inline(always)]
pub fn is_reg_set_jmp(instr: &zydis::DecodedInstruction) -> bool {
    is_jmp(&instr) && is_single_reg_read(&instr)
}

/// Check if jump instruction with register-controlled memory deref target
#[inline(always)]
pub fn is_mem_ptr_set_jmp(instr: &zydis::DecodedInstruction) -> bool {
    is_jmp(&instr) && is_single_reg_deref_read(&instr)
}

/// Check if call instruction with register-controlled memory deref target
#[inline(always)]
pub fn is_mem_ptr_set_call(instr: &zydis::DecodedInstruction) -> bool {
    is_call(&instr) && is_single_reg_deref_read(&instr)
}

/// Check if instruction is a ROP/JOP/SYS gadget tail
#[inline(always)]
pub fn is_gadget_tail(instr: &zydis::DecodedInstruction) -> bool {
    is_ret(instr) || is_jop_gadget_tail(instr) || is_sys_gadget_tail(instr)
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
    is_syscall(instr) || is_legacy_linux_syscall(instr)
}

/// Check if instruction updates register in predictable fashion suitable for a dispatcher
#[inline(always)]
pub fn is_reg_update_from_curr_val(
    instr: &zydis::DecodedInstruction,
    reg: zydis::Register,
) -> bool {
    let reg_read_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action.intersects(zydis::OperandAction::MASK_READ))
                && (o.ty == zydis::enums::OperandType::REGISTER)
                && (o.reg == reg)
        })
        .count();

    if reg_read_cnt != 0 {
        let reg_write_cnt = instr
            .operands
            .iter()
            .filter(|&o| {
                (o.action.intersects(zydis::OperandAction::MASK_WRITE))
                    && (o.visibility != zydis::OperandVisibility::HIDDEN)
                    && (o.ty == zydis::enums::OperandType::REGISTER)
                    && (o.reg == reg)
            })
            .count();

        if reg_write_cnt == 1 {
            return true;
        }
    }

    false
}

// Categorization ------------------------------------------------------------------------------------------------------

/// Check if return instruction
#[inline(always)]
pub fn is_ret(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::RET
}

/// Check if return instruction that adds to stack pointer
#[inline(always)]
pub fn is_ret_imm16(instr: &zydis::DecodedInstruction) -> bool {
    instr.meta.category == zydis::enums::InstructionCategory::RET
        && (instr
            .operands
            .iter()
            .filter(|&o| o.ty == zydis::enums::OperandType::IMMEDIATE)
            .count()
            == 1)
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

/// Check if legacy Linux syscall
#[inline(always)]
pub fn is_legacy_linux_syscall(instr: &zydis::DecodedInstruction) -> bool {
    let imm_0x80_cnt = instr
        .operands
        .iter()
        .filter(|&o| {
            (o.action == zydis::enums::OperandAction::READ)
                && (o.ty == zydis::enums::OperandType::IMMEDIATE)
                && (o.imm.value == 0x80)
        })
        .count();

    (instr.meta.category == zydis::enums::InstructionCategory::INTERRUPT) && (imm_0x80_cnt == 1)
}
