use shroudb_acl::{AclRequirement, Scope};

/// Parsed Cipher wire protocol command.
#[derive(Debug)]
pub enum CipherCommand {
    /// Authenticate this connection with a token.
    Auth {
        token: String,
    },

    // Keyring management
    KeyringCreate {
        name: String,
        algorithm: String,
        rotation_days: Option<u32>,
        drain_days: Option<u32>,
        convergent: bool,
    },
    KeyringList,

    // Encryption operations
    Encrypt {
        keyring: String,
        plaintext: String,
        context: Option<String>,
        key_version: Option<u32>,
        convergent: bool,
    },
    Decrypt {
        keyring: String,
        ciphertext: String,
        context: Option<String>,
    },
    Rewrap {
        keyring: String,
        ciphertext: String,
        context: Option<String>,
    },
    GenerateDataKey {
        keyring: String,
        bits: Option<u32>,
    },

    // Signing operations
    Sign {
        keyring: String,
        data: String,
    },
    VerifySignature {
        keyring: String,
        data: String,
        signature: String,
    },

    // Key lifecycle
    Rotate {
        keyring: String,
        force: bool,
        dryrun: bool,
    },
    KeyInfo {
        keyring: String,
    },

    // Operational
    Health,
    Ping,
    CommandList,
}

impl CipherCommand {
    /// The ACL requirement for this command.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            CipherCommand::Auth { .. }
            | CipherCommand::Health
            | CipherCommand::Ping
            | CipherCommand::CommandList => AclRequirement::None,

            // Listing keyring names is not sensitive
            CipherCommand::KeyringList => AclRequirement::None,

            // Keyring creation is a structural change → admin
            CipherCommand::KeyringCreate { .. } => AclRequirement::Admin,

            // Read operations
            CipherCommand::Decrypt { keyring, .. }
            | CipherCommand::VerifySignature { keyring, .. }
            | CipherCommand::KeyInfo { keyring, .. } => AclRequirement::Namespace {
                ns: format!("cipher.{keyring}.*"),
                scope: Scope::Read,
                tenant_override: None,
            },

            // Write operations
            CipherCommand::Encrypt { keyring, .. }
            | CipherCommand::Rewrap { keyring, .. }
            | CipherCommand::GenerateDataKey { keyring, .. }
            | CipherCommand::Sign { keyring, .. }
            | CipherCommand::Rotate { keyring, .. } => AclRequirement::Namespace {
                ns: format!("cipher.{keyring}.*"),
                scope: Scope::Write,
                tenant_override: None,
            },
        }
    }
}

/// Parse raw RESP3 command arguments into a CipherCommand.
pub fn parse_command(args: &[&str]) -> Result<CipherCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "AUTH" => {
            if args.len() < 2 {
                return Err("AUTH <token>".into());
            }
            Ok(CipherCommand::Auth {
                token: args[1].to_string(),
            })
        }
        "KEYRING" => parse_keyring(args),
        "ENCRYPT" => parse_encrypt(args),
        "DECRYPT" => parse_decrypt(args),
        "REWRAP" => parse_rewrap(args),
        "GENERATE_DATA_KEY" => parse_generate_data_key(args),
        "SIGN" => parse_sign(args),
        "VERIFY_SIGNATURE" => parse_verify_signature(args),
        "ROTATE" => parse_rotate(args),
        "KEY_INFO" => parse_key_info(args),
        "HEALTH" => Ok(CipherCommand::Health),
        "PING" => Ok(CipherCommand::Ping),
        "COMMAND" => Ok(CipherCommand::CommandList),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_keyring(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 2 {
        return Err("KEYRING requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 4 {
                return Err(
                    "KEYRING CREATE <name> <algorithm> [ROTATION_DAYS <n>] [DRAIN_DAYS <n>] [CONVERGENT]"
                        .into(),
                );
            }
            let rotation_days = find_option(args, "ROTATION_DAYS")
                .map(|v| v.parse::<u32>())
                .transpose()
                .map_err(|e| format!("invalid ROTATION_DAYS: {e}"))?;
            let drain_days = find_option(args, "DRAIN_DAYS")
                .map(|v| v.parse::<u32>())
                .transpose()
                .map_err(|e| format!("invalid DRAIN_DAYS: {e}"))?;
            let convergent = has_flag(args, "CONVERGENT");

            Ok(CipherCommand::KeyringCreate {
                name: args[2].to_string(),
                algorithm: args[3].to_string(),
                rotation_days,
                drain_days,
                convergent,
            })
        }
        "LIST" => Ok(CipherCommand::KeyringList),
        sub => Err(format!("unknown KEYRING subcommand: {sub}")),
    }
}

fn parse_encrypt(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 3 {
        return Err(
            "ENCRYPT <keyring> <plaintext_b64> [CONTEXT <aad>] [KEY_VERSION <v>] [CONVERGENT]"
                .into(),
        );
    }
    let context = find_option(args, "CONTEXT").map(String::from);
    let key_version = find_option(args, "KEY_VERSION")
        .map(|v| v.parse::<u32>())
        .transpose()
        .map_err(|e| format!("invalid KEY_VERSION: {e}"))?;
    let convergent = has_flag(args, "CONVERGENT");

    Ok(CipherCommand::Encrypt {
        keyring: args[1].to_string(),
        plaintext: args[2].to_string(),
        context,
        key_version,
        convergent,
    })
}

fn parse_decrypt(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 3 {
        return Err("DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]".into());
    }
    let context = find_option(args, "CONTEXT").map(String::from);
    Ok(CipherCommand::Decrypt {
        keyring: args[1].to_string(),
        ciphertext: args[2].to_string(),
        context,
    })
}

fn parse_rewrap(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 3 {
        return Err("REWRAP <keyring> <ciphertext> [CONTEXT <aad>]".into());
    }
    let context = find_option(args, "CONTEXT").map(String::from);
    Ok(CipherCommand::Rewrap {
        keyring: args[1].to_string(),
        ciphertext: args[2].to_string(),
        context,
    })
}

fn parse_generate_data_key(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 2 {
        return Err("GENERATE_DATA_KEY <keyring> [BITS <128|256|512>]".into());
    }
    let bits = find_option(args, "BITS")
        .map(|v| v.parse::<u32>())
        .transpose()
        .map_err(|e| format!("invalid BITS: {e}"))?;
    Ok(CipherCommand::GenerateDataKey {
        keyring: args[1].to_string(),
        bits,
    })
}

fn parse_sign(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 3 {
        return Err("SIGN <keyring> <data_b64>".into());
    }
    Ok(CipherCommand::Sign {
        keyring: args[1].to_string(),
        data: args[2].to_string(),
    })
}

fn parse_verify_signature(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 4 {
        return Err("VERIFY_SIGNATURE <keyring> <data_b64> <signature_hex>".into());
    }
    Ok(CipherCommand::VerifySignature {
        keyring: args[1].to_string(),
        data: args[2].to_string(),
        signature: args[3].to_string(),
    })
}

fn parse_rotate(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 2 {
        return Err("ROTATE <keyring> [FORCE] [DRYRUN]".into());
    }
    let force = has_flag(args, "FORCE");
    let dryrun = has_flag(args, "DRYRUN");
    Ok(CipherCommand::Rotate {
        keyring: args[1].to_string(),
        force,
        dryrun,
    })
}

fn parse_key_info(args: &[&str]) -> Result<CipherCommand, String> {
    if args.len() < 2 {
        return Err("KEY_INFO <keyring>".into());
    }
    Ok(CipherCommand::KeyInfo {
        keyring: args[1].to_string(),
    })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

/// Check if a flag is present in the args.
fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encrypt_command() {
        let cmd = parse_command(&["ENCRYPT", "payments", "SGVsbG8="]).unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::Encrypt {
                keyring,
                plaintext,
                context: None,
                key_version: None,
                convergent: false,
            } if keyring == "payments" && plaintext == "SGVsbG8="
        ));
    }

    #[test]
    fn parse_encrypt_with_options() {
        let cmd = parse_command(&[
            "ENCRYPT",
            "payments",
            "SGVsbG8=",
            "CONTEXT",
            "user-123",
            "KEY_VERSION",
            "3",
            "CONVERGENT",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::Encrypt {
                context: Some(_),
                key_version: Some(3),
                convergent: true,
                ..
            }
        ));
    }

    #[test]
    fn parse_decrypt_command() {
        let cmd = parse_command(&["DECRYPT", "payments", "abc:def"]).unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::Decrypt {
                keyring,
                ciphertext,
                context: None,
            } if keyring == "payments" && ciphertext == "abc:def"
        ));
    }

    #[test]
    fn parse_keyring_create() {
        let cmd = parse_command(&[
            "KEYRING",
            "CREATE",
            "payments",
            "aes-256-gcm",
            "ROTATION_DAYS",
            "30",
            "CONVERGENT",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::KeyringCreate {
                name,
                algorithm,
                rotation_days: Some(30),
                convergent: true,
                ..
            } if name == "payments" && algorithm == "aes-256-gcm"
        ));
    }

    #[test]
    fn parse_keyring_list() {
        let cmd = parse_command(&["KEYRING", "LIST"]).unwrap();
        assert!(matches!(cmd, CipherCommand::KeyringList));
    }

    #[test]
    fn parse_rotate_with_flags() {
        let cmd = parse_command(&["ROTATE", "payments", "FORCE", "DRYRUN"]).unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::Rotate {
                keyring,
                force: true,
                dryrun: true,
            } if keyring == "payments"
        ));
    }

    #[test]
    fn parse_sign_command() {
        let cmd = parse_command(&["SIGN", "signing", "SGVsbG8="]).unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::Sign { keyring, data } if keyring == "signing" && data == "SGVsbG8="
        ));
    }

    #[test]
    fn parse_verify_signature() {
        let cmd = parse_command(&["VERIFY_SIGNATURE", "signing", "SGVsbG8=", "abcdef"]).unwrap();
        assert!(matches!(
            cmd,
            CipherCommand::VerifySignature { keyring, data, signature }
            if keyring == "signing" && data == "SGVsbG8=" && signature == "abcdef"
        ));
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, CipherCommand::Health));
    }

    #[test]
    fn parse_ping() {
        let cmd = parse_command(&["PING"]).unwrap();
        assert!(matches!(cmd, CipherCommand::Ping));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(parse_command(&["NOPE"]).is_err());
    }

    #[test]
    fn empty_command_errors() {
        assert!(parse_command(&[]).is_err());
    }
}
