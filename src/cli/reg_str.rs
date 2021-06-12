use rustc_hash::FxHashMap as HashMap;

// Dynamic Init --------------------------------------------------------------------------------------------------------

lazy_static! {
    static ref STR_REG_MAP: HashMap<String, iced_x86::Register> = {
        let mut srm = HashMap::default();

        for reg in iced_x86::Register::values() {
            if reg != iced_x86::Register::None {
                let reg_str = format!("{:?}", reg).to_uppercase();

                // Skip iced_x86 sentinels
                if reg_str.contains("DONTUSE") {
                    continue;
                }

                // Secondary key: R8L-R15L -> R8B-R15B
                if (iced_x86::Register::R8L <= reg) && (reg <= iced_x86::Register::R15L) {
                    srm.insert(reg_str.replace("L", "B"), reg);
                }

                srm.insert(reg_str, reg);
            }
        }

        srm
    };
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Case-insensitive string to register enum conversion
pub fn str_to_reg(rs: &str) -> Option<iced_x86::Register> {
    match STR_REG_MAP.get(&rs.to_uppercase()) {
        Some(reg) => Some(*reg),
        None => None,
    }
}

// Test ----------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_strs() {
        const ICED_X86_REG_TOTAL: usize = 256;
        const ICED_X86_REG_TOTAL_VALID: usize = 248;

        let mut count = 0;
        let mut valid_count = 0;

        for reg in iced_x86::Register::values() {
            let reg_str = format!("{:?}", reg);
            count += 1;

            if reg != iced_x86::Register::None {
                println!("{}", reg_str);
                match str_to_reg(&reg_str) {
                    Some(map_reg) => {
                        valid_count += 1;
                        assert_eq!(reg, map_reg);
                    }
                    None => assert!(reg_str.to_uppercase().contains("DONTUSE")),
                }
            }
        }

        assert_eq!(count, ICED_X86_REG_TOTAL);
        assert_eq!(valid_count, ICED_X86_REG_TOTAL_VALID);
    }
}
