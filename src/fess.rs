//! Fast Exploit Similarity Score (FESS)

use rustc_hash::FxHashSet as HashSet;

use crate::binary;
use crate::gadget;
use crate::semantics;

#[cfg(feature = "cli-bin")]
use std::error::Error;

#[cfg(feature = "cli-bin")]
use crate::search;

#[cfg(feature = "cli-bin")]
use cli_table::{format::Justify, Cell, CellStruct, Color, Style, Table, TableDisplay};

#[cfg(feature = "cli-bin")]
use num_format::{Locale, ToFormattedString};

// Crate-internal API --------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct FESSData<'a> {
    #[allow(dead_code)] // Only read for feature "cli-bin"
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
            bin_name: bin.name(),
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

// Codes from: https://github.com/fidian/ansi#--color-codes
// Note crate "cli-table" uses the "termcolor" crate, not "colored" crate
// So table output does slightly different coloring than rest of xgadget
#[cfg(feature = "cli-bin")]
macro_rules! build_row {
    ($hdr:literal, $tbl:ident, $data:ident, $color:ident) => {{
        // Select row color
        let row_color = if $hdr.contains("ROP") && $hdr.contains("full") {
            Color::Green
        } else if $hdr.contains("ROP") && $hdr.contains("part") {
            Color::Ansi256(10) // Bright Green
        } else if $hdr.contains("JOP") && $hdr.contains("full") {
            Color::Blue
        } else if $hdr.contains("JOP") && $hdr.contains("part") {
            Color::Ansi256(12) // Bright Blue
        } else if $hdr.contains("SYS") && $hdr.contains("full") {
            Color::Cyan
        } else if $hdr.contains("SYS") && $hdr.contains("part") {
            Color::Ansi256(14) // Bright Cyan
        } else {
            Color::White
        };

        // Determine baseline count
        let base_cnt = if $hdr.contains("ROP") {
            $tbl[0].rop_full_cnt
        } else if $hdr.contains("JOP") {
            $tbl[0].jop_full_cnt
        } else if $hdr.contains("SYS") {
            $tbl[0].sys_full_cnt
        } else {
            panic!("FESS table cannot determine baseline count!");
        };

        // Compute row data
        let mut val = if $color {
            vec![$hdr.cell().foreground_color(Some(row_color))]
        } else {
            vec![$hdr.cell()]
        };

        val.append(
            &mut $tbl
                .iter()
                .enumerate()
                .map(|(i, fd)| {
                    // No partial matches in first column
                    if (i == 0) && (fd.$data == 0) {
                        if $color {
                            "-".cell()
                                .justify(Justify::Right)
                                .foreground_color(Some(row_color))
                        } else {
                            "-".cell().justify(Justify::Right)
                        }
                    // Append percentage diff (non-first columns)
                    } else {
                        let curr_cnt = fd.$data;
                        let data = if i == 0 {
                            curr_cnt.to_formatted_string(&Locale::en)
                        } else {
                            format!(
                                "{} ({:.2}%)",
                                curr_cnt.to_formatted_string(&Locale::en),
                                (((curr_cnt as f64) / (base_cnt as f64)) * 100.0)
                            )
                        };

                        if $color {
                            data.cell()
                                .justify(Justify::Right)
                                .foreground_color(Some(row_color))
                        } else {
                            data.cell().justify(Justify::Right)
                        }
                    }
                })
                .collect::<Vec<CellStruct>>(),
        );

        val
    }};
}

/// Generate Fast Exploit Similarity Score (FESS) table
#[cfg(feature = "cli-bin")]
pub fn gen_fess_tbl(
    bins: &[binary::Binary],
    max_len: usize,
    config: search::SearchConfig,
    color: bool,
) -> Result<TableDisplay, Box<dyn Error>> {
    // Collect data
    let mut fess_tbl_data = Vec::new();
    let fess_config = config | search::SearchConfig::PART;
    let _ = search::find_gadgets_multi_bin(bins, max_len, fess_config, Some(&mut fess_tbl_data))?;

    // Build upper left header
    let mut tbl_hdr = vec!["Gadget Type".cell().bold(true)];
    tbl_hdr.append(
        &mut fess_tbl_data
            .iter()
            .enumerate()
            .map(|(i, fd)| {
                if i == 0 {
                    format!("{} {}", fd.bin_name, "(base)").cell().bold(true)
                } else {
                    format!("{} {}", fd.bin_name, "(diff)").cell().bold(true)
                }
            })
            .collect::<Vec<CellStruct>>(),
    );

    // Build rows
    let rop_full = build_row!("ROP (full)", fess_tbl_data, rop_full_cnt, color);
    let rop_part = build_row!("ROP (part)", fess_tbl_data, rop_part_cnt, color);
    let jop_full = build_row!("JOP (full)", fess_tbl_data, jop_full_cnt, color);
    let jop_part = build_row!("JOP (part)", fess_tbl_data, jop_part_cnt, color);
    let sys_full = build_row!("SYS (full)", fess_tbl_data, sys_full_cnt, color);
    let sys_part = build_row!("SYS (part)", fess_tbl_data, sys_part_cnt, color);

    // Build table
    let tbl = vec![rop_full, rop_part, jop_full, jop_part, sys_full, sys_part]
        .table()
        .title(tbl_hdr)
        .bold(true);

    Ok(tbl.display()?)
}
