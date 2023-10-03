use rayon::prelude::*;

use crate::semantics;
use crate::{Gadget, GadgetAnalysis};

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a, P>(gadgets: P) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            let regs_overwritten = GadgetAnalysis::new(g).regs_overwritten();
            if regs_overwritten.contains(&iced_x86::Register::RSP)
                || regs_overwritten.contains(&iced_x86::Register::ESP)
                || regs_overwritten.contains(&iced_x86::Register::SP)
            {
                return true;
            }
            false
        })
        .collect()
}

/// Parallel filter to gadgets that may be suitable JOP dispatchers
pub fn filter_dispatcher<'a, P>(gadgets: P) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            if let Some((tail_instr, preceding_instrs)) = g.instrs.split_last() {
                if semantics::is_jop_gadget_tail(tail_instr) {
                    // Predictable update of dispatch register
                    let dispatch_reg = tail_instr.op0_register();
                    for i in preceding_instrs {
                        if semantics::is_reg_rw(i, &dispatch_reg) {
                            return true;
                        }
                    }
                }
            }
            false
        })
        .collect()
}

/// Parallel filter to gadgets of the form "pop {reg} * 1+, {ret or ctrl-ed jmp/call}"
pub fn filter_reg_pop_only<'a, P>(gadgets: P) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            if let Some((tail_instr, mut preceding_instrs)) = g.instrs.split_last() {
                if (semantics::is_ret(tail_instr) || semantics::is_jop_gadget_tail(tail_instr))
                    && (!preceding_instrs.is_empty())
                {
                    // Allow "leave" preceding tail, if any
                    if let Some((second_to_last, remaining)) = preceding_instrs.split_last() {
                        if second_to_last.mnemonic() == iced_x86::Mnemonic::Leave {
                            preceding_instrs = remaining;
                        }
                    }

                    // Preceded exclusively by pop instrs
                    let pop_chain = preceding_instrs.iter().all(|instr| {
                        instr.mnemonic() == iced_x86::Mnemonic::Pop
                            || instr.mnemonic() == iced_x86::Mnemonic::Popa
                    });

                    if pop_chain && !preceding_instrs.is_empty() {
                        return true;
                    }
                }
            }
            false
        })
        .collect()
}

/// Parallel filter to gadgets that write parameter registers or stack push any register
pub fn filter_set_params<'a, P>(gadgets: P, param_regs: &[iced_x86::Register]) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            for instr in &g.instrs {
                // Stack push all regs
                if instr.mnemonic() == iced_x86::Mnemonic::Pusha
                    || instr.mnemonic() == iced_x86::Mnemonic::Pushad
                {
                    return true;
                }

                // Stack push any reg
                if instr.mnemonic() == iced_x86::Mnemonic::Push {
                    if let Ok(op_kind) = instr.try_op_kind(0) {
                        if op_kind == iced_x86::OpKind::Register {
                            return true;
                        }
                    }
                }

                // Sets param reg
                for reg in param_regs {
                    if semantics::is_reg_set(instr, reg) {
                        return true;
                    }
                }
            }
            false
        })
        .collect()
}

/// Parallel filter to gadgets that don't dereference any registers (if `opt_regs.is_none()`),
/// or don't dereference specific registers (if `opt_regs.is_some()`).
/// Doesn't count the stack pointer unless explicitly provided in `opt_regs`.
pub fn filter_no_deref<'a, P>(gadgets: P, opt_regs: Option<&[iced_x86::Register]>) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            let mut regs_derefed = GadgetAnalysis::new(g).regs_dereferenced();
            match opt_regs {
                Some(regs) => regs.iter().all(|r| !regs_derefed.contains(r)),
                None => {
                    // Don't count stack pointer
                    regs_derefed.retain(|r| r != &iced_x86::Register::RSP);
                    regs_derefed.retain(|r| r != &iced_x86::Register::ESP);
                    regs_derefed.retain(|r| r != &iced_x86::Register::SP);

                    regs_derefed.is_empty()
                }
            }
        })
        .collect()
}

/// Parallel filter to gadgets that write any register (if `opt_regs.is_none()`),
/// or write specific registers (if `opt_regs.is_some()`).
pub fn filter_regs_overwritten<'a, P>(gadgets: P, opt_regs: Option<&[iced_x86::Register]>) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .filter(|g| {
            let regs_overwritten = GadgetAnalysis::new(g).regs_overwritten();
            match opt_regs {
                Some(regs) => regs.iter().all(|r| regs_overwritten.contains(r)),
                None => !regs_overwritten.is_empty(),
            }
        })
        .collect()
}

/// Parallel filter to gadget's whose addresses don't contain specified bytes
pub fn filter_bad_addr_bytes<'a, P>(gadgets: P, bad_bytes: &[u8]) -> P
where
    P: IntoParallelIterator<Item = Gadget<'a>> + FromParallelIterator<Gadget<'a>>,
{
    gadgets
        .into_par_iter()
        .map(|mut g| {
            g.full_matches = g
                .full_matches
                .iter()
                .filter(|addr| addr.to_le_bytes().iter().all(|b| !bad_bytes.contains(b)))
                .copied()
                .collect();

            g.partial_matches = g
                .partial_matches
                .iter()
                .filter(|(addr, _)| addr.to_le_bytes().iter().all(|b| !bad_bytes.contains(b)))
                .map(|(addr, bins)| (*addr, bins.clone()))
                .collect();
            g
        })
        .filter(|g| !g.full_matches.is_empty() || !g.partial_matches.is_empty())
        .collect()
}
