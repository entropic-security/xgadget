#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

use lazy_static::lazy_static;
use rustc_hash::FxHashMap as HashMap;

// Dynamic Init --------------------------------------------------------------------------------------------------------

#[cfg(test)]
static SECONDARY_KEY_CNT: AtomicU8 = AtomicU8::new(0);

lazy_static! {
    static ref STR_REG_MAP: HashMap<String, iced_x86::Register> = {
        iced_x86::Register::values()
            .filter(|r| *r != iced_x86::Register::None)
            .map(|r| (format!("{:?}", r).to_uppercase(), r))
            // Skip `iced_x86` sentinels
            .filter(|(rs, _)| !rs.contains("DONTUSE"))
            .flat_map(|(rs, r)| {
                // Secondary key: R8L-R15L -> R8B-R15B
                if (iced_x86::Register::R8L <= r) && (r <= iced_x86::Register::R15L) {
                    #[cfg(test)]
                    SECONDARY_KEY_CNT.fetch_add(1, Ordering::SeqCst);

                    [(rs.clone(), r), (rs.replace('L', "B"), r)].to_vec()
                } else {
                    [(rs, r)].to_vec()
                }
            })
            .collect()
    };
}

// Public API ----------------------------------------------------------------------------------------------------------

/// Case-insensitive string to register enum conversion
pub fn str_to_reg(rs: &str) -> Option<iced_x86::Register> {
    STR_REG_MAP.get(&rs.to_uppercase()).copied()
}

// Test ----------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use xgadget::binary::ICED_X86_REG_TOTAL;
    use xgadget::binary::ICED_X86_REG_TOTAL_VALID;

    #[test]
    fn test_reg_strs() {
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
        assert_eq!(
            STR_REG_MAP.len(),
            ICED_X86_REG_TOTAL_VALID + usize::from(SECONDARY_KEY_CNT.load(Ordering::SeqCst))
        );
    }
}
