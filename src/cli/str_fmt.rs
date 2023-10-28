#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

use colored::{ColoredString, Colorize};
use lazy_static::lazy_static;
use rustc_hash::FxHashMap as HashMap;

// Dynamic Init --------------------------------------------------------------------------------------------------------

#[cfg(test)]
static SECONDARY_KEY_CNT: AtomicU8 = AtomicU8::new(0);

// TODO: Add a mnemonic map for coloring those as well!

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

/// Apply custom coloring rules to a `clap` help menu item.
/// Cannot do this for `[default: x64]` postfix - those are clap generated.
pub fn cli_help_fmt(help_desc: &str, has_default: bool, fess_entry: bool) -> String {
    use std::io::Write;
    const PUNCTUATION_SET: &[char; 14] = &[
        '[', ']', '{', '}', '(', ')', ':', '\'', '.', ',', '+', '*', '/', '\\',
    ];

    let working_buf_to_string = |buf: &[char]| {
        let token: String = buf.into_iter().collect();
        match token.as_str() {
            // Arg-like tokens
            "x8086" | "x86" | "x64" | "LEN" => token.bright_blue(),
            // Search type tokens
            "ROP" | "JOP" | "SYS" | "SYSCALL" => token.cyan(),
            // FESS feature advertisement
            "Fast" | "Exploit" | "Similarity" | "Score" => match fess_entry {
                true => token.red(),
                false => token.normal(),
            },
            "FESS" => match fess_entry {
                true => token.bold().red(),
                false => token.normal(),
            },
            // All other words
            other => match STR_REG_MAP.contains_key(other) {
                // Register name
                true => match other {
                    "rsp" | "esp" | "sp" => other.red(),
                    _ => other.yellow(),
                },
                // Anything else
                false => token.normal(),
            },
        }
    };

    let flush_working_buf = |sink: &mut Vec<ColoredString>, buf: &mut Vec<char>| {
        if !buf.is_empty() {
            sink.push(working_buf_to_string(&buf));
            buf.clear();
        }
    };

    let mut tokens = Vec::new();
    let mut working_buf = Vec::new();

    for c in help_desc.chars() {
        if PUNCTUATION_SET.contains(&c) {
            flush_working_buf(&mut tokens, &mut working_buf);
            tokens.push(c.to_string().bright_magenta());
        } else if c.is_whitespace() {
            flush_working_buf(&mut tokens, &mut working_buf);
            tokens.push(c.to_string().normal());
        } else {
            working_buf.push(c);
        }
    }
    flush_working_buf(&mut tokens, &mut working_buf);

    // Separator before `clap`'s non-colored default
    if has_default {
        tokens.push(" |".green());
    }

    // Cannot `join"("")` a `Vec<ColoredString>`
    let mut f = Vec::new();
    for token in tokens {
        write!(f, "{}", token).unwrap();
    }
    String::from_utf8(f).unwrap()
}

// Test ----------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use xgadget::ICED_X86_REG_TOTAL;
    use xgadget::ICED_X86_REG_TOTAL_VALID;

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
