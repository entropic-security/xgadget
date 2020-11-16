use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;

use crate::gadget;
use crate::semantics;

/// Parallel filter to gadgets that write the stack pointer
pub fn filter_stack_pivot<'a>(gadgets: &[gadget::Gadget<'a>]) -> Vec<gadget::Gadget<'a>> {
    let rsp_write = iced_x86::UsedRegister::new(iced_x86::Register::RSP, iced_x86::OpAccess::Write);
    let esp_write = iced_x86::UsedRegister::new(iced_x86::Register::ESP, iced_x86::OpAccess::Write);
    let sp_write = iced_x86::UsedRegister::new(iced_x86::Register::SP, iced_x86::OpAccess::Write);

    gadgets
        .par_iter()
        .filter(|g| {
            for instr in &g.instrs {
                let mut info_factory = iced_x86::InstructionInfoFactory::new();

                let info = info_factory
                    .info_options(&instr, iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE);

                if info.used_registers().contains(&rsp_write)
                    || info.used_registers().contains(&esp_write)
                    || info.used_registers().contains(&sp_write)
                {
                    return true;
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
                    // JOP tail should always have a single reg or reg-based deref operand
                    debug_assert!(
                        (tail_instr.op_count() == 1)
                            && ((tail_instr.op_kind(0) == iced_x86::OpKind::Register)
                                || ((tail_instr.op0_kind() == iced_x86::OpKind::Memory)
                                    && (tail_instr.memory_base() != iced_x86::Register::None)))
                    );

                    // Predictable update of dispatch register
                    let dispatch_reg = tail_instr.op0_register();
                    for i in preceding_instrs {
                        if semantics::is_reg_rw(&i, &dispatch_reg) {
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

// TODO: benchmark vs less precise regex: r"^(?:pop)(?:.*(?:pop))*.*ret"
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
                        if second_to_last.mnemonic() == iced_x86::Mnemonic::Leave {
                            preceding_instrs = remaining;
                        }
                    }

                    // Preceded exclusively by pop instrs
                    let pop_chain = preceding_instrs.iter().all(|instr| {
                        instr.mnemonic() == iced_x86::Mnemonic::Pop
                            || instr.mnemonic() == iced_x86::Mnemonic::Popa
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
