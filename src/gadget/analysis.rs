use core::iter::FromIterator;

use rustc_hash::FxHashSet as HashSet;

use super::gadget::Gadget;

// Gadget Analysis -----------------------------------------------------------------------------------------------------

/// Determines gadget register usage properties.
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
    used_regs: HashSet<iced_x86::UsedRegister>,
    used_mem: HashSet<iced_x86::UsedMemory>,
}

impl GadgetAnalysis {
    // GadgetAnalysis Public API ---------------------------------------------------------------------------------------

    /// Analyze gadget
    pub fn new(gadget: &Gadget) -> Self {
        let mut info_factory = iced_x86::InstructionInfoFactory::new();
        let mut unique_used_regs = HashSet::default();
        let mut unique_used_mem = HashSet::default();

        for instr in &gadget.instrs {
            let info = info_factory.info(instr);

            for ur in info.used_registers() {
                unique_used_regs.insert(*ur);
            }

            for um in info.used_memory() {
                unique_used_mem.insert(*um);
            }
        }

        GadgetAnalysis {
            used_regs: unique_used_regs,
            used_mem: unique_used_mem,
        }
    }

    /// Get full register usage info
    pub fn used_regs(&self) -> impl ExactSizeIterator<Item = iced_x86::UsedRegister> + '_ {
        self.used_regs.iter().copied()
    }

    /// Get full memory usage info
    pub fn used_mem(&self) -> impl ExactSizeIterator<Item = iced_x86::UsedMemory> + '_ {
        self.used_mem.iter().copied()
    }

    /// Get registers overwritten by gadget (written without reading previous value)
    pub fn regs_overwritten(&self) -> HashSet<iced_x86::Register> {
        self.used_regs
            .iter()
            .filter(|ur| ur.access() == iced_x86::OpAccess::Write)
            .map(|ur| ur.register())
            .collect()
    }

    /// Get registers updated by gadget (read and then written)
    pub fn regs_updated(&self) -> HashSet<iced_x86::Register> {
        self.used_regs
            .iter()
            .filter(|ur| ur.access() == iced_x86::OpAccess::ReadWrite)
            .map(|ur| ur.register())
            // TODO: overwrite taking precedence doesn't take into account conditional behavior
            .filter(|r| !self.regs_overwritten().contains(r))
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
        let mem_reads = self.used_mem.iter().filter(|um| {
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
        let mem_writes = self.used_mem.iter().filter(|um| {
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

// TODO: add a simple test case here
