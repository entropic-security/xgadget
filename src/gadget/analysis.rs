use core::iter::FromIterator;
use std::sync::OnceLock;

use rustc_hash::FxHashSet as HashSet;

use super::gadget::Gadget;

// Gadget Analysis -----------------------------------------------------------------------------------------------------

// Internal per-instruction information
#[derive(Clone, Debug)]
struct InstrInfo {
    op_regs: HashSet<iced_x86::Register>,
    mem_base: iced_x86::Register,
    used_regs: HashSet<iced_x86::UsedRegister>,
    used_mem: HashSet<iced_x86::UsedMemory>,
}

/// Determines gadget register usage properties.
/// Lazy construct by calling [`Gadget::analysis`].
///
/// * Registers overwritten (written without reading previous value)
/// * Registers updated (read and then written, within single instruction)
/// * Registers dereferenced for read
/// * Registers dereferenced for write
///
/// # Limitations
/// * Current logic does not account for all cases of conditional behavior
#[derive(Clone, Debug)]
pub struct GadgetAnalysis {
    instr_info: Vec<InstrInfo>,
    total_used_regs: OnceLock<HashSet<iced_x86::UsedRegister>>,
    total_used_mem: OnceLock<HashSet<iced_x86::UsedMemory>>,
}

impl GadgetAnalysis {
    // GadgetAnalysis Public API ---------------------------------------------------------------------------------------

    /// Init gadget analysis
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

                    InstrInfo {
                        used_regs: info.used_registers().into_iter().cloned().collect(),
                        used_mem: info.used_memory().into_iter().cloned().collect(),
                        mem_base: instr.memory_base(),
                        op_regs,
                    }
                })
                .collect(),
            total_used_regs: OnceLock::new(),
            total_used_mem: OnceLock::new(),
        }
    }

    /// Get register usage info, across all instructions
    pub fn used_regs(&self) -> impl ExactSizeIterator<Item = &iced_x86::UsedRegister> + '_ {
        self.total_used_regs
            .get_or_init(|| {
                self.instr_info
                    .iter()
                    .map(|info| info.used_regs.iter().copied())
                    .flatten()
                    .collect::<HashSet<_>>()
            })
            .iter()
    }

    /// Get memory usage info, across all instructions
    pub fn used_mem(&self) -> impl ExactSizeIterator<Item = &iced_x86::UsedMemory> + '_ {
        self.total_used_mem
            .get_or_init(|| {
                self.instr_info
                    .iter()
                    .map(|info| info.used_mem.iter().copied())
                    .flatten()
                    .collect::<HashSet<_>>()
            })
            .iter()
    }

    /// Get registers read by gadget. Includes conditional reads.
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
            .collect()
    }

    /// Get registers overwritten by gadget (written without reading previous value)
    /// If `include_sub_regs == true` the smaller variant of a register will count as an overwrite of the larger,
    /// e.g. will report `eax`-overwrite for `rax`.
    pub fn regs_overwritten(&self, include_sub_regs: bool) -> HashSet<iced_x86::Register> {
        self.instr_info
            .iter()
            .map(|info| {
                info.used_regs
                    .iter()
                    .filter(move |ur| {
                        ur.access() == iced_x86::OpAccess::Write
                            && !matches!(
                                info.mem_base,
                                iced_x86::Register::RIP | iced_x86::Register::EIP,
                            )
                            // Written directly or via sub-register name
                            && if include_sub_regs {
                                true
                            // Written directly (named operand)
                            } else {
                                info.op_regs.contains(&ur.register())
                            }
                    })
                    .map(|ur| ur.register())
            })
            .flatten()
            .collect()
    }

    /// Get registers updated by gadget (read and then written)
    pub fn regs_updated(&self) -> HashSet<iced_x86::Register> {
        self.used_regs()
            .filter(|ur| ur.access() == iced_x86::OpAccess::ReadWrite)
            .map(|ur| ur.register())
            // TODO: overwrite taking precedence doesn't take into account conditional behavior
            .filter(|r| !self.regs_overwritten(true).contains(r))
            .collect()
    }

    /// Get registers dereferenced by gadget
    pub fn regs_dereferenced(&self) -> HashSet<iced_x86::Register> {
        HashSet::from_iter(
            self.regs_dereferenced_read()
                .into_iter()
                .chain(self.regs_dereferenced_write()),
        )
    }

    /// Get registers dereferenced for read by gadget
    pub fn regs_dereferenced_read(&self) -> HashSet<iced_x86::Register> {
        let mem_reads = self.used_mem().filter(|um| {
            let access = um.access();
            (access == iced_x86::OpAccess::Read)
                || (access == iced_x86::OpAccess::CondRead)
                || (access == iced_x86::OpAccess::ReadWrite)
                || (access == iced_x86::OpAccess::ReadCondWrite)
        });

        Self::unique_regs_dereferenced(mem_reads)
    }

    /// Get registers dereferenced for write by gadget
    pub fn regs_dereferenced_write(&self) -> HashSet<iced_x86::Register> {
        let mem_writes = self.used_mem().filter(|um| {
            let access = um.access();
            (access == iced_x86::OpAccess::Write)
                || (access == iced_x86::OpAccess::CondWrite)
                || (access == iced_x86::OpAccess::ReadWrite)
                || (access == iced_x86::OpAccess::ReadCondWrite)
        });

        Self::unique_regs_dereferenced(mem_writes)
    }

    // GadgetAnalysis Private API --------------------------------------------------------------------------------------

    // Private helper for deref reg collection
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
