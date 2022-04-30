use rustc_hash::FxHashSet as HashSet;

use crate::binary;
use crate::gadget;
use crate::semantics;

#[derive(Debug)]
pub(crate) struct FESSData<'a> {
    bin_name: &'a str,
    rop_full_cnt: usize,
    rop_partial_cnt: usize,
    jop_full_cnt: usize,
    jop_partial_cnt: usize,
    sys_full_cnt: usize,
    sys_partial_cnt: usize,
}

impl<'a> FESSData<'a> {
    pub(crate) fn from_gadget_list(
        bin: &'a binary::Binary,
        gadget_set: &HashSet<gadget::Gadget>,
    ) -> Self {
        let mut fess_data = FESSData {
            bin_name: &bin.name(),
            rop_full_cnt: 0,
            rop_partial_cnt: 0,
            jop_full_cnt: 0,
            jop_partial_cnt: 0,
            sys_full_cnt: 0,
            sys_partial_cnt: 0,
        };

        for g in gadget_set {
            if let Some(i) = g.last_instr() {
                // TODO: should this tagging logic stored in Gadget obj instead of re-computed here?
                // Or maybe split out into a function used by both this and iterative_decode?
                if semantics::is_ret(i) {
                    if !g.full_matches.is_empty() {
                        fess_data.rop_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        fess_data.rop_partial_cnt += 1;
                    }
                } else if semantics::is_jop_gadget_tail(i) {
                    if !g.full_matches.is_empty() {
                        fess_data.jop_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        fess_data.jop_partial_cnt += 1;
                    }
                } else if semantics::is_sys_gadget_tail_bin_sensitive(i, bin) {
                    if !g.full_matches.is_empty() {
                        fess_data.sys_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        fess_data.sys_partial_cnt += 1;
                    }
                }
            }
        }

        fess_data
    }
}
