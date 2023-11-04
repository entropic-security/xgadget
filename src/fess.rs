//! Fast Exploit Similarity Score (FESS)

use rustc_hash::FxHashSet as HashSet;

use crate::binary;
use crate::gadget;
use crate::semantics;

#[cfg(feature = "cli-bin")]
use crate::Error;

#[cfg(feature = "cli-bin")]
use crate::search;

#[cfg(feature = "cli-bin")]
use tabled::{Table, Tabled};

// Crate-internal API --------------------------------------------------------------------------------------------------

// Used for percentage diff cell formatting
#[derive(Default, Copy, Clone)]
pub(crate) struct GadgetTotals {
    rop_full_cnt: usize,
    rop_part_cnt: usize,
    jop_full_cnt: usize,
    jop_part_cnt: usize,
    sys_full_cnt: usize,
    sys_part_cnt: usize,
}

#[derive(Tabled, Default)]
pub(crate) struct FESSColumn<'a> {
    #[cfg(feature = "cli-bin")]
    #[tabled(display_with("Self::display_bin_name", self))]
    bin_name: &'a str,
    #[tabled(skip)]
    idx: usize,
    #[tabled(skip)]
    base: Option<GadgetTotals>,
    #[tabled(display_with("Self::display_cell_data", self, 0))]
    rop_full_cnt: usize,
    #[tabled(display_with("Self::display_cell_data", self, 1))]
    rop_part_cnt: usize,
    #[tabled(display_with("Self::display_cell_data", self, 2))]
    jop_full_cnt: usize,
    #[tabled(display_with("Self::display_cell_data", self, 3))]
    jop_part_cnt: usize,
    #[tabled(display_with("Self::display_cell_data", self, 4))]
    sys_full_cnt: usize,
    #[tabled(display_with("Self::display_cell_data", self, 5))]
    sys_part_cnt: usize,
}

impl<'a> FESSColumn<'a> {
    pub(crate) fn get_totals(
        bin: &'a binary::Binary,
        gadget_set: &HashSet<gadget::Gadget>,
    ) -> GadgetTotals {
        let mut totals = GadgetTotals::default();

        for g in gadget_set {
            if let Some(i) = g.last_instr() {
                // TODO: should this tagging logic stored in Gadget obj instead of re-computed here?
                // Or maybe split out into a function used by both this and iterative_decode?
                if semantics::is_ret(i) {
                    if !g.full_matches.is_empty() {
                        totals.rop_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        totals.rop_part_cnt += 1;
                    }
                } else if semantics::is_jop_gadget_tail(i) {
                    if !g.full_matches.is_empty() {
                        totals.jop_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        totals.jop_part_cnt += 1;
                    }
                } else if semantics::is_sys_gadget_tail_bin_sensitive(i, bin) {
                    if !g.full_matches.is_empty() {
                        totals.sys_full_cnt += 1;
                    }
                    if !g.partial_matches.is_empty() {
                        totals.sys_part_cnt += 1;
                    }
                }
            }
        }

        totals
    }

    pub(crate) fn from_gadget_list(
        idx: usize,
        base_count: Option<GadgetTotals>,
        bin: &'a binary::Binary,
        gadget_set: &HashSet<gadget::Gadget>,
    ) -> Self {
        let mut fess_data = FESSColumn::<'_> {
            bin_name: bin.name(),
            base: base_count,
            idx,
            ..Default::default()
        };

        let GadgetTotals {
            rop_full_cnt,
            rop_part_cnt,
            jop_full_cnt,
            jop_part_cnt,
            sys_full_cnt,
            sys_part_cnt,
        } = FESSColumn::get_totals(bin, gadget_set);

        fess_data.rop_full_cnt = rop_full_cnt;
        fess_data.rop_part_cnt = rop_part_cnt;
        fess_data.jop_full_cnt = jop_full_cnt;
        fess_data.jop_part_cnt = jop_part_cnt;
        fess_data.sys_full_cnt = sys_full_cnt;
        fess_data.sys_part_cnt = sys_part_cnt;

        fess_data
    }

    fn display_bin_name(&self) -> String {
        format!(
            "{} ({})",
            self.bin_name,
            match self.idx {
                0 => "base",
                _ => "diff",
            }
        )
    }

    fn display_cell_data(&self, cell_switch: usize) -> String {
        use num_format::{Locale, ToFormattedString};

        let fmt_num = |n| match n {
            0 => "-".to_string(),
            _ => n.to_formatted_string(&Locale::en),
        };

        let fmt_diff_num = |n, b| match n {
            0 => "-".to_string(),
            _ => format!(
                "{} ({:.2}%)",
                n.to_formatted_string(&Locale::en),
                (((n as f64) / (b as f64)) * 100.0)
            ),
        };

        match self.idx {
            // First/base binary
            0 => match cell_switch {
                0 => fmt_num(self.rop_full_cnt),
                1 => fmt_num(self.rop_part_cnt),
                2 => fmt_num(self.jop_full_cnt),
                3 => fmt_num(self.jop_part_cnt),
                4 => fmt_num(self.sys_full_cnt),
                5 => fmt_num(self.sys_part_cnt),
                _ => unreachable!(),
            },
            // Remaining diff binaries
            _ => {
                let base = self
                    .base
                    .expect("columns after fist must have a base count to diff against");

                match cell_switch {
                    0 => fmt_diff_num(self.rop_full_cnt, base.rop_full_cnt),
                    1 => fmt_diff_num(self.rop_part_cnt, base.rop_full_cnt),
                    2 => fmt_diff_num(self.jop_full_cnt, base.jop_full_cnt),
                    3 => fmt_diff_num(self.jop_part_cnt, base.jop_full_cnt),
                    4 => fmt_diff_num(self.sys_full_cnt, base.sys_full_cnt),
                    5 => fmt_diff_num(self.sys_part_cnt, base.sys_full_cnt),
                    _ => unreachable!(),
                }
            }
        }
    }
}

// CLI Binary API ------------------------------------------------------------------------------------------------------

/// Generate Fast Exploit Similarity Score (FESS) table
#[cfg(feature = "cli-bin")]
pub fn gen_fess_tbl(
    bins: &[binary::Binary],
    max_len: usize,
    config: search::SearchConfig,
) -> Result<(Table, usize), Error> {
    use colored::Colorize;
    use tabled::settings::{format::Format, object::Segment, Alignment, Modify, Style};

    // Collect data
    let mut fess_tbl_cols = Vec::new();
    let fess_config = config | search::SearchConfig::PART;
    let found_count =
        search::find_gadgets_multi_bin(bins, max_len, fess_config, Some(&mut fess_tbl_cols))?.len();

    // Check column count
    debug_assert_eq!(bins.len(), fess_tbl_cols.len());

    // Check `idx` init
    debug_assert!(fess_tbl_cols
        .iter()
        .enumerate()
        .all(|(idx, col)| idx == col.idx));

    // Check `base` init
    debug_assert!(fess_tbl_cols
        .iter()
        .enumerate()
        .all(|(idx, col)| match idx {
            0 => col.base.is_none(),
            _ => col.base.is_some(),
        }));

    let left_header = &[
        "Gadget Type",
        "ROP (full)",
        "ROP (part)",
        "JOP (full)",
        "JOP (part)",
        "SYS (full)",
        "SYS (part)",
    ];

    let mut table = Table::builder(&fess_tbl_cols)
        .set_header(left_header.iter().copied())
        .clone()
        .index()
        .column(0)
        .transpose()
        .build();

    table
        .with(Style::modern())
        // Format top header
        .with(
            Modify::new(Segment::new(0..1, 0..))
                .with(Alignment::center())
                .with(Format::content(|s| s.red().bold().italic().to_string())),
        )
        // Format left header
        .with(
            Modify::new(Segment::new(0.., 0..1))
                .with(Alignment::center())
                .with(Format::content(|s| s.bold().italic().to_string())),
        )
        // Format result data cells
        .with(
            Modify::new(Segment::new(1..2, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.green().to_string())),
        )
        .with(
            Modify::new(Segment::new(2..3, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.bright_green().to_string())),
        )
        .with(
            Modify::new(Segment::new(3..4, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.blue().to_string())),
        )
        .with(
            Modify::new(Segment::new(4..5, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.bright_blue().to_string())),
        )
        .with(
            Modify::new(Segment::new(5..6, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.cyan().to_string())),
        )
        .with(
            Modify::new(Segment::new(6..7, 0..))
                .with(Alignment::right())
                .with(Format::content(|s| s.bright_cyan().to_string())),
        );

    Ok((table, found_count))
}
