use rayon::prelude::*;

use crate::semantics;
use crate::gadget;

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a>(gadgets: &[gadget::Gadget<'a>]) -> Vec<gadget::Gadget<'a>> {
    gadgets.par_iter()
        .filter(|g| {
            for i in &g.instrs {
                for o in &i.operands {

                    // Stack pointer
                    if (o.reg == zydis::Register::RSP
                        || o.reg == zydis::Register::ESP
                        || o.reg == zydis::Register::SP)

                        // Write
                        && (o.action.intersects(zydis::OperandAction::MASK_WRITE))
                        && (o.visibility != zydis::OperandVisibility::HIDDEN) {

                            return true;
                    }
                }
            }
            false
        })
        .cloned()
        .collect()
}

/// Parallel filter to gadgets that may be suitable JOP dispatchers
pub fn filter_dispatcher<'a>(gadgets: &[gadget::Gadget<'a>]) -> Vec<gadget::Gadget<'a>> {
    gadgets.par_iter()
        .filter(|g| {
            if let Some((tail_instr, preceding_instrs)) = g.instrs.split_last() {
                if semantics::is_jop_gadget_tail(tail_instr) {

                    // Get dispatch register
                    let dispatch_op = &tail_instr.operands[0];
                    let dispatch_reg = match dispatch_op.ty {
                        zydis::enums::OperandType::REGISTER => dispatch_op.reg,
                        zydis::enums::OperandType::MEMORY => dispatch_op.mem.base,
                        _ => return false
                    };

                    // Predictable update of dispatch register
                    for i in preceding_instrs {
                        if semantics::is_reg_update_from_curr_val(&i, dispatch_reg) {
                            return true;
                        }
                    }
                }
            }
            false
        })
        .cloned()
        .collect()
}