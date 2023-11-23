use core::iter::FromIterator;
use std::sync::OnceLock;

use rustc_hash::FxHashSet as HashSet;

use super::gadget::Gadget;

// Gadget Analysis -----------------------------------------------------------------------------------------------------

// Internal per-instruction meta-information.
// Populated at construction time.
#[derive(Clone, Debug)]
struct InstrMetaInfo {
    op_regs: HashSet<iced_x86::Register>,
    mem_base: iced_x86::Register,
    mnemonic: iced_x86::Mnemonic,
    used_regs: HashSet<iced_x86::UsedRegister>,
    used_mem: HashSet<iced_x86::UsedMemory>,
}

/// Determines gadget register usage properties.
///
/// Lazy construct by calling [`Gadget::analysis`] (cache initial analysis for multiple usages/filters).
/// Internal lazy-eval for state common to queries (cache post-analysis operations for multiple public API calls).
#[derive(Clone, Debug)]
pub struct GadgetAnalysis {
    instr_info: Vec<InstrMetaInfo>,
    total_used_regs: OnceLock<HashSet<iced_x86::UsedRegister>>,
    total_used_mem: OnceLock<HashSet<iced_x86::UsedMemory>>,
}

impl GadgetAnalysis {
    // GadgetAnalysis Public API ---------------------------------------------------------------------------------------

    /// Init gadget analysis.
    pub(crate) fn new(gadget: &Gadget) -> Self {
        let mut info_factory = iced_x86::InstructionInfoFactory::new();

        GadgetAnalysis {
            instr_info: gadget
                .instrs
                .iter()
                .map(|instr| {
                    let info = info_factory.info(instr);
                    let mut op_regs = HashSet::default();

                    for op_idx in 0..instr.op_count() {
                        if let Ok(iced_x86::OpKind::Register) = instr.try_op_kind(op_idx) {
                            op_regs.insert(instr.op_register(op_idx));
                        }
                    }

                    InstrMetaInfo {
                        used_regs: info.used_registers().iter().cloned().collect(),
                        used_mem: info.used_memory().iter().cloned().collect(),
                        mem_base: instr.memory_base(),
                        mnemonic: instr.mnemonic(),
                        op_regs,
                    }
                })
                .collect(),
            total_used_regs: OnceLock::new(),
            total_used_mem: OnceLock::new(),
        }
    }

    /// Get register usage info, across all instructions.
    ///
    /// ## Note
    ///
    /// * Lazy - caches result on first call
    pub fn used_regs(&self) -> impl ExactSizeIterator<Item = &iced_x86::UsedRegister> + '_ {
        self.total_used_regs
            .get_or_init(|| {
                self.instr_info
                    .iter()
                    .flat_map(|info| info.used_regs.iter().copied())
                    .collect::<HashSet<_>>()
            })
            .iter()
    }

    /// Get memory usage info, across all instructions.
    ///
    /// ## Note
    ///
    /// * Lazy - caches result on first call
    pub fn used_mem(&self) -> impl ExactSizeIterator<Item = &iced_x86::UsedMemory> + '_ {
        self.total_used_mem
            .get_or_init(|| {
                self.instr_info
                    .iter()
                    .flat_map(|info| info.used_mem.iter().copied())
                    .collect::<HashSet<_>>()
            })
            .iter()
    }

    /// Get registers read by gadget.
    ///
    /// ## Note
    ///
    /// * Includes conditional reads.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_read(&self) -> HashSet<iced_x86::Register> {
        self.used_regs()
            .filter(|ur| {
                matches!(
                    ur.access(),
                    iced_x86::OpAccess::Read
                        | iced_x86::OpAccess::CondRead
                        | iced_x86::OpAccess::ReadWrite
                        | iced_x86::OpAccess::ReadCondWrite
                )
            })
            .map(|ur| ur.register())
            .chain(
                self.used_mem()
                    .filter(|um| um.base() != iced_x86::Register::None)
                    .map(|um| um.base()),
            )
            .chain(
                self.used_mem()
                    .filter(|um| um.index() != iced_x86::Register::None)
                    .map(|um| um.index()),
            )
            .collect()
    }

    /// Get registers overwritten by gadget (written without reading previous value).
    ///
    /// * If `include_sub_regs == true` the smaller variant of a register will count as an overwrite of the larger,
    /// e.g. will report `eax`-overwrite for `rax`.
    ///
    /// ## Note
    ///
    /// * Excludes conditional writes.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_overwritten(&self, include_sub_regs: bool) -> HashSet<iced_x86::Register> {
        self.instr_info
            .iter()
            .flat_map(|info| {
                info.used_regs
                    .iter()
                    .filter(move |ur| {
                        ((ur.access() == iced_x86::OpAccess::ReadWrite && info.mnemonic == iced_x86::Mnemonic::Xchg)
                        || (ur.access() == iced_x86::OpAccess::Write))
                            && !matches!(
                                info.mem_base,
                                iced_x86::Register::RIP | iced_x86::Register::EIP,
                            )
                            // Written directly or via sub-register name,
                            // as reported by lib (not `get_reg_family`)
                            && if include_sub_regs {
                                true
                            // Written directly (named operand)
                            } else {
                                info.op_regs.contains(&ur.register())
                            }
                    })
                    .map(|ur| ur.register())
            })
            .collect()
    }

    /// Get registers updated by gadget (read and then written).
    ///
    /// ## Note
    ///
    /// * Excludes conditional writes.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_updated(&self) -> HashSet<iced_x86::Register> {
        self.used_regs()
            .filter(|ur| ur.access() == iced_x86::OpAccess::ReadWrite)
            .map(|ur| ur.register())
            .filter(|r| !self.regs_overwritten(true).contains(r))
            .collect()
    }

    /// Get registers dereferenced by gadget.
    ///
    /// ## Note
    ///
    /// * Includes conditional writes.
    /// * Includes conditional reads.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_dereferenced(&self) -> HashSet<iced_x86::Register> {
        HashSet::from_iter(
            self.regs_dereferenced_mem_read()
                .into_iter()
                .chain(self.regs_dereferenced_mem_write()),
        )
    }

    /// Get registers dereferenced for memory read by gadget.
    ///
    /// ## Note
    ///
    /// * Includes conditional reads.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_dereferenced_mem_read(&self) -> HashSet<iced_x86::Register> {
        Self::unique_regs_dereferenced(self.used_mem().filter(|um| {
            matches!(
                um.access(),
                iced_x86::OpAccess::Read
                    | iced_x86::OpAccess::CondRead
                    | iced_x86::OpAccess::ReadWrite
                    | iced_x86::OpAccess::ReadCondWrite
            )
        }))
    }

    /// Get registers dereferenced for memory write by gadget.
    ///
    /// ## Note
    ///
    /// * Includes conditional writes.
    /// * Partially lazy - caches part of result calculation on first call.
    pub fn regs_dereferenced_mem_write(&self) -> HashSet<iced_x86::Register> {
        Self::unique_regs_dereferenced(self.used_mem().filter(|um| {
            matches!(
                um.access(),
                iced_x86::OpAccess::Write
                    | iced_x86::OpAccess::CondWrite
                    | iced_x86::OpAccess::ReadWrite
                    | iced_x86::OpAccess::ReadCondWrite
            )
        }))
    }

    // GadgetAnalysis Private API --------------------------------------------------------------------------------------

    // Private helper for deref reg collection.
    fn unique_regs_dereferenced<'a>(
        used_mem: impl Iterator<Item = &'a iced_x86::UsedMemory>,
    ) -> HashSet<iced_x86::Register> {
        let mut regs = HashSet::default();

        for um in used_mem {
            let base_reg = um.base();
            if base_reg != iced_x86::Register::None {
                regs.insert(base_reg);
            }

            let index_reg = um.index();
            if index_reg != iced_x86::Register::None {
                regs.insert(index_reg);
            }
        }

        regs
    }
}
