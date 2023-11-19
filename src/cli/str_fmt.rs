#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

use colored::{ColoredString, Colorize};
use lazy_static::lazy_static;
use rustc_hash::FxHashMap as HashMap;

// Dynamic Init --------------------------------------------------------------------------------------------------------

#[cfg(test)]
static SECONDARY_KEY_CNT: AtomicU8 = AtomicU8::new(0);

lazy_static! {
    pub static ref STR_REG_MAP: HashMap<String, iced_x86::Register> = {
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

lazy_static! {
    pub static ref VERSION_STR: String = format!("v{}", clap::crate_version!());
}

lazy_static! {
    pub static ref ABOUT_STR: String = format!(
        "{} {}{}\n\n{}\t{}\n{}\t{} logical{} {} physical",
        clap::crate_name!().green(),
        "v".bright_magenta(),
        cli_rule_fmt(clap::crate_version!(), false, false),
        "About:".to_string().cyan(),
        cli_rule_fmt(clap::crate_description!(), false, false),
        "Cores:".to_string().cyan(),
        num_cpus::get().to_string().red(),
        ",".bright_magenta(),
        num_cpus::get_physical().to_string().red(),
    );
}

use clap::builder::{styling::AnsiColor, Styles};
lazy_static! {
    pub static ref CMD_COLOR: Styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Cyan.on_default())
        .valid(AnsiColor::Green.on_default())
        .error(AnsiColor::Red.on_default())
        .invalid(AnsiColor::Red.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::BrightBlue.on_default().bold());
}

macro_rules! gen_help_str {
    ($(($static_name:ident, $has_default:expr, $fess_entry:expr, $help_str:literal $(,)?)),* $(,)?) => {
        $(
            lazy_static! {
                pub static ref $static_name: String = cli_rule_fmt(
                    $help_str,
                    $has_default,
                    $fess_entry,
                );
            }
        )*
    }
}

gen_help_str!(
    (
        HELP_BIN_PATHS,
        false,
        false,
        "1+ binaries to gadget search. If > 1: gadgets common to all",
    ),
    (
        HELP_ARCH,
        true,
        false,
        "For raw (no header) files: specify arch ('x8086', 'x86', or 'x64')",
    ),
    (
        HELP_ATT,
        false,
        false,
        "Display gadgets using AT&T syntax (otherwise Intel syntax)",
    ),
    (
        HELP_EXTENDED_FMT,
        false,
        false,
        "Print in terminal-wide format (otherwise only used for partial match search)",
    ),
    (
        HELP_MAX_LEN,
        true,
        false,
        "Gadgets up to LEN instrs long. If 0: all gadgets, any length",
    ),
    (
        HELP_ROP,
        false,
        false,
        "Search for ROP gadgets only (otherwise ROP, JOP, and SYSCALL)",
    ),
    (
        HELP_JOP,
        false,
        false,
        "Search for JOP gadgets only (otherwise ROP, JOP, and SYSCALL)",
    ),
    (
        HELP_SYS,
        false,
        false,
        "Search for SYSCALL gadgets only (otherwise ROP, JOP, and SYSCALL)",
    ),
    (
        HELP_ALL,
        false,
        false,
        "Include low-quality gadgets (containing branches, calls, interrupts, etc)",
    ),
    (
        HELP_PARTIAL_MACH,
        false,
        false,
        "Include cross-variant partial matches (otherwise: full matches only)",
    ),
    (
        HELP_STACK_PIVOT,
        false,
        false,
        "Filter to gadgets that write the stack ptr (otherwise: all)",
    ),
    (
        HELP_DISPATCHER,
        false,
        false,
        "Filter to potential JOP 'dispatcher' gadgets (otherwise: all)",
    ),
    (
        HELP_REG_POP,
        false,
        false,
        "Filter to 'pop {reg} * 1+, {ret or ctrl-ed jmp/call}' gadgets (otherwise: all)",
    ),
    (
        HELP_REG_NO_READ,
        false,
        false,
        "Filter to gadgets that don't read any regs (no args) or specific regs (flag args)",
    ),
    (
        HELP_REG_OVERWRITE,
        false,
        false,
        "Filter to gadgets that control any reg (no args) or specific regs (flag args)",
    ),
    (
        HELP_PARAM_CTRL,
        false,
        false,
        "Filter to gadgets that control function parameters (otherwise: all)",
    ),
    (
        HELP_BAD_BYTES,
        false,
        false,
        "Filter to gadgets whose addrs don't contain given bytes (otherwise: all)",
    ),
    (
        HELP_USER_REGEX,
        false,
        false,
        "Filter to gadgets matching a regular expression",
    ),
    (
        HELP_CHECKSEC,
        false,
        false,
        "Run checksec on the 1+ binaries instead of gadget search",
    ),
    (
        HELP_FESS,
        false,
        true,
        "Compute Fast Exploit Similarity Score (FESS) table for 2+ binaries",
    ),
    (
        HELP_IMPORTS,
        false,
        false,
        "List imported symbols in 1+ binaries",
    ),
);

// Public API ----------------------------------------------------------------------------------------------------------

/// Case-insensitive string to register enum conversion
pub fn str_to_reg(rs: &str) -> Option<iced_x86::Register> {
    STR_REG_MAP.get(&rs.to_uppercase()).copied()
}

/// Apply custom coloring rules to a `clap` help menu item or misc summary string.
/// Cannot do this for help postfix (e.g. `[default: x64]`) - those are clap generated.
pub fn cli_rule_fmt(help_desc: &str, has_default: bool, fess_entry: bool) -> String {
    use std::io::Write;
    const PUNCTUATION_SET: &[char; 17] = &[
        '[', ']', '{', '}', '(', ')', ':', '\'', '-', '.', ',', '+', '*', '/', '\\', '>', '<',
    ];

    let working_buf_to_string = |buf: &[char]| {
        let token: String = buf.iter().collect();
        match token.as_str() {
            // Arg-like tokens
            "x8086" | "x86" | "x64" | "LEN" => token.bold().bright_blue(),
            // Flag-like tokens
            "ROP" | "JOP" | "SYS" | "SYSCALL" | "AT&T" | "checksec" => token.green(),
            // Select mnemonics
            "jmp" | "call" | "ret" | "pop" => token.cyan(),
            // FESS feature advertisement
            "Fast" | "Exploit" | "Similarity" | "Score" => match fess_entry {
                true => token.red(),
                false => token.normal(),
            },
            "FESS" => match fess_entry {
                true => token.bold().red(),
                false => token.normal(),
            },
            _ => {
                // Register names
                if str_to_reg(&token).is_some() {
                    match token.as_str() {
                        "rsp" | "esp" | "sp" => token.to_lowercase().red(),
                        _ => token.to_lowercase().yellow(),
                    }
                // All other words
                } else {
                    token.normal()
                }
            }
        }
    };

    let flush_working_buf = |sink: &mut Vec<ColoredString>, buf: &mut Vec<char>| {
        if !buf.is_empty() {
            sink.push(working_buf_to_string(buf));
            buf.clear();
        }
    };

    let mut tokens = Vec::new();
    let mut working_buf = Vec::new();

    for c in help_desc.chars() {
        if PUNCTUATION_SET.contains(&c) {
            flush_working_buf(&mut tokens, &mut working_buf);
            tokens.push(c.to_string().bold().bright_magenta());
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
        tokens.push(" |".bold().yellow());
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

    /// Total number of named registers
    const ICED_X86_REG_TOTAL: usize = 256;

    /// Total number of unique named registers
    const ICED_X86_REG_TOTAL_UNIQUE: usize = 248;

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
        assert_eq!(valid_count, ICED_X86_REG_TOTAL_UNIQUE);
        assert_eq!(
            STR_REG_MAP.len(),
            ICED_X86_REG_TOTAL_UNIQUE + usize::from(SECONDARY_KEY_CNT.load(Ordering::SeqCst))
        );
    }
}
