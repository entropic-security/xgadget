use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;

use crate::gadget;
use crate::semantics;

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a>(gadgets: &[gadget::Gadget<'a>]) -> Vec<gadget::Gadget<'a>> {
    gadgets
        .par_iter()
        .filter(|g| {
            for i in &g.instrs {
                for o in &i.operands {
                    // Stack pointer
                    if (o.reg == zydis::Register::RSP
                        || o.reg == zydis::Register::ESP
                        || o.reg == zydis::Register::SP)

                        // Write
                        && (o.action.intersects(zydis::OperandAction::MASK_WRITE))
                        && (o.visibility != zydis::OperandVisibility::HIDDEN)
                    {
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
    gadgets
        .par_iter()
        .filter(|g| {
            if let Some((tail_instr, preceding_instrs)) = g.instrs.split_last() {
                if semantics::is_jop_gadget_tail(tail_instr) {
                    // Get dispatch register
                    let dispatch_op = &tail_instr.operands[0];
                    let dispatch_reg = match dispatch_op.ty {
                        zydis::enums::OperandType::REGISTER => dispatch_op.reg,
                        zydis::enums::OperandType::MEMORY => dispatch_op.mem.base,
                        _ => return false,
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

/// Parallel filter to gadgets of the form "pop {reg} * 1+, {ret or ctrl-ed jmp/call}"
pub fn filter_stack_set_regs<'a>(gadgets: &[gadget::Gadget<'a>]) -> Vec<gadget::Gadget<'a>> {
    gadgets
        .par_iter()
        .filter(|g| {
            if let Some((tail_instr, mut preceding_instrs)) = g.instrs.split_last() {
                if (semantics::is_ret(tail_instr) || semantics::is_jop_gadget_tail(tail_instr))
                    && (!preceding_instrs.is_empty())
                {
                    // Allow "leave" preceding tail, if any
                    if let Some((second_to_last, remaining)) = preceding_instrs.split_last() {
                        if second_to_last.mnemonic == zydis::enums::Mnemonic::LEAVE {
                            preceding_instrs = remaining;
                        }
                    }

                    // Preceded exclusively by pop instrs
                    let pop_chain = preceding_instrs.iter().all(|i| {
                        i.mnemonic == zydis::enums::Mnemonic::POP
                            && semantics::is_single_reg_write(i)
                    });

                    if pop_chain {
                        return true;
                    }
                }
            }
            false
        })
        .cloned()
        .collect()
}

// TODO: use drain_filter() once on stable
/// Parallel filter to gadget's whose addresses don't contain specified bytes
pub fn filter_bad_addr_bytes<'a>(
    gadgets: &[gadget::Gadget<'a>],
    bad_bytes: &[u8],
) -> Vec<gadget::Gadget<'a>> {
    let mut good_addr_gadgets = gadgets.to_vec();

    good_addr_gadgets.par_iter_mut().for_each(|g| {
        let tmp_set: BTreeSet<_> = g
            .full_matches
            .iter()
            .filter(|addr| addr.to_le_bytes().iter().all(|b| !bad_bytes.contains(b)))
            .cloned()
            .collect();

        g.full_matches = tmp_set;

        let tmp_map: BTreeMap<_, _> = g
            .partial_matches
            .iter()
            .filter(|(addr, _)| addr.to_le_bytes().iter().all(|b| !bad_bytes.contains(b)))
            .map(|(addr, bins)| (*addr, bins.clone()))
            .collect();

        g.partial_matches = tmp_map;
    });

    good_addr_gadgets
        .into_iter()
        .filter(|g| !g.full_matches.is_empty() || !g.partial_matches.is_empty())
        .collect()
}
