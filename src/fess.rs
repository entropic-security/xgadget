use rustc_hash::FxHashSet as HashSet;

use crate::binary;
use crate::gadget;
use crate::semantics;

#[cfg(feature = "cli-bin")]
use std::error::Error;

#[cfg(feature = "cli-bin")]
use crate::search;

#[cfg(feature = "cli-bin")]
use cli_table::{format::Justify, Cell, CellStruct, Style, Table, TableDisplay};

#[cfg(feature = "cli-bin")]
use num_format::{Locale, ToFormattedString};

// Crate-internal API --------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct FESSData<'a> {
    bin_name: &'a str,
    rop_full_cnt: usize,
    rop_part_cnt: usize,
    jop_full_cnt: usize,
    jop_part_cnt: usize,
    sys_full_cnt: usize,
    sys_part_cnt: usize,
}

impl<'a> FESSData<'a> {
    pub(crate) fn from_gadget_list(
        bin: &'a binary::Binary,
        gadget_set: &HashSet<gadget::Gadget>,
    ) -> Self {
        let mut fess_data = FESSData {
            bin_name: &bin.name(),
            rop_full_cnt: 0,
            rop_part_cnt: 0,
            jop_full_cnt: 0,
            jop_part_cnt: 0,
            sys_full_cnt: 0,
            sys_part_cnt: 0,
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
                        fess_data.rop_part_cnt += 1;
                    }
                } else if semantics::is_jop_gadget_tail(i) {
                    if !g.full_matches.is_empty() {
                        fess_data.jop_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        fess_data.jop_part_cnt += 1;
                    }
                } else if semantics::is_sys_gadget_tail_bin_sensitive(i, bin) {
                    if !g.full_matches.is_empty() {
                        fess_data.sys_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        fess_data.sys_part_cnt += 1;
                    }
                }
            }
        }

        fess_data
    }
}

// CLI Binary API ------------------------------------------------------------------------------------------------------

#[cfg(feature = "cli-bin")]
macro_rules! build_row {
    ($hdr:literal, $tbl:ident, $data:ident) => {{
        let mut val = vec![$hdr.cell()];
        val.append(
            &mut $tbl
                .iter()
                .enumerate()
                .map(|(i, fd)| {
                    if (i == 0) && (fd.$data == 0) {
                        "-".cell().justify(Justify::Right)
                    } else {
                        fd.$data.to_formatted_string(&Locale::en).cell().justify(Justify::Right)
                    }
                })
                .collect::<Vec<CellStruct>>(),
        );
        val
    }};
}

// TODO: table coloring and percentages
#[cfg(feature = "cli-bin")]
pub fn gen_fess_tbl(
    bins: &[binary::Binary],
    max_len: usize,
    config: search::SearchConfig,
) -> Result<TableDisplay, Box<dyn Error>> {
    // Collect data
    let mut fess_tbl = Vec::new();
    let fess_config = config | search::SearchConfig::PART;
    let _ = search::find_gadgets_multi_bin(&bins, max_len, fess_config, Some(&mut fess_tbl))?;

    // Build upper left header
    let mut tbl_hdr = vec!["Gadget Type".cell().bold(true)];
    tbl_hdr.append(
        &mut fess_tbl
            .iter()
            .map(|fd| fd.bin_name.cell().bold(true))
            .collect::<Vec<CellStruct>>(),
    );

    // Build rows
    let rop_full = build_row!("ROP (full)", fess_tbl, rop_full_cnt);
    let rop_part = build_row!("ROP (part)", fess_tbl, rop_part_cnt);
    let jop_full = build_row!("JOP (full)", fess_tbl, jop_full_cnt);
    let jop_part = build_row!("JOP (part)", fess_tbl, jop_part_cnt);
    let sys_full = build_row!("SYS (full)", fess_tbl, sys_full_cnt);
    let sys_part = build_row!("SYS (part)", fess_tbl, sys_part_cnt);

    // Build table
    let tbl = vec![rop_full, rop_part, jop_full, jop_part, sys_full, sys_part]
        .table()
        .title(tbl_hdr)
        .bold(true);

    Ok(tbl.display()?)
}
