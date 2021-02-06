use rustc_hash::FxHashMap as HashMap;

// Dynamic Init --------------------------------------------------------------------------------------------------------

lazy_static! {
    static ref STR_REG_MAP: HashMap<String, iced_x86::Register> = {
        let mut srm = HashMap::default();

        for reg in iced_x86::Register::values() {
            if reg != iced_x86::Register::None {
                let reg_str = format!("{:?}", reg).to_uppercase();

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
        let mut count = 0;
        for reg in iced_x86::Register::values() {
            let reg_str = format!("{:?}", reg);
            count += 1;

            if reg != iced_x86::Register::None {
                println!("{}", reg_str);
                assert_eq!(reg, str_to_reg(&reg_str).unwrap());
            }
        }
        assert_eq!(count, 249);
    }
}
