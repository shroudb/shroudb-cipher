use anyhow::Context;
use clap::Parser;
use shroudb_cipher_client::CipherClient;

#[derive(Parser)]
#[command(name = "shroudb-cipher-cli", about = "Cipher CLI")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:6599", env = "CIPHER_ADDR")]
    addr: String,

    /// Command to execute. If omitted, starts interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut client = CipherClient::connect(&cli.addr)
        .await
        .with_context(|| format!("failed to connect to {}", cli.addr))?;

    if cli.command.is_empty() {
        interactive(&mut client).await
    } else {
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

async fn execute(client: &mut CipherClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await.context("health check failed")?;
            println!("OK");
        }
        "PING" => {
            println!("PONG");
        }
        "KEYRING" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "CREATE" if args.len() >= 4 => {
                let resp = client
                    .keyring_create(args[2], args[3], None, None, has_flag(args, "CONVERGENT"))
                    .await
                    .context("keyring create failed")?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            "LIST" => {
                let names = client.keyring_list().await.context("keyring list failed")?;
                for name in names {
                    println!("{name}");
                }
            }
            _ => anyhow::bail!("usage: KEYRING CREATE|LIST ..."),
        },
        "ENCRYPT" if args.len() >= 3 => {
            let context = find_option(args, "CONTEXT");
            let convergent = has_flag(args, "CONVERGENT");
            let result = client
                .encrypt(args[1], args[2], context, None, convergent)
                .await
                .context("encrypt failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ciphertext": result.ciphertext,
                    "key_version": result.key_version,
                }))?
            );
        }
        "DECRYPT" if args.len() >= 3 => {
            let context = find_option(args, "CONTEXT");
            let result = client
                .decrypt(args[1], args[2], context)
                .await
                .context("decrypt failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "plaintext": result.plaintext,
                }))?
            );
        }
        "REWRAP" if args.len() >= 3 => {
            let context = find_option(args, "CONTEXT");
            let result = client
                .rewrap(args[1], args[2], context)
                .await
                .context("rewrap failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ciphertext": result.ciphertext,
                    "key_version": result.key_version,
                }))?
            );
        }
        "GENERATE_DATA_KEY" if args.len() >= 2 => {
            let bits = find_option(args, "BITS")
                .map(|b| b.parse::<u32>())
                .transpose()?;
            let result = client
                .generate_data_key(args[1], bits)
                .await
                .context("generate data key failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "plaintext_key": result.plaintext_key,
                    "wrapped_key": result.wrapped_key,
                    "key_version": result.key_version,
                }))?
            );
        }
        "SIGN" if args.len() >= 3 => {
            let result = client.sign(args[1], args[2]).await.context("sign failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "signature": result.signature,
                    "key_version": result.key_version,
                }))?
            );
        }
        "VERIFY_SIGNATURE" if args.len() >= 4 => {
            let valid = client
                .verify_signature(args[1], args[2], args[3])
                .await
                .context("verify failed")?;
            println!("{}", if valid { "valid" } else { "invalid" });
        }
        "ROTATE" if args.len() >= 2 => {
            let force = has_flag(args, "FORCE");
            let result = client
                .rotate(args[1], force)
                .await
                .context("rotate failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "rotated": result.rotated,
                    "key_version": result.key_version,
                    "previous_version": result.previous_version,
                }))?
            );
        }
        "KEY_INFO" if args.len() >= 2 => {
            let info = client.key_info(args[1]).await.context("key info failed")?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        _ => anyhow::bail!("unknown command: {}", args.join(" ")),
    }

    Ok(())
}

async fn interactive(client: &mut CipherClient) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    eprint!("cipher> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("cipher> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("cipher> ");
    }
    Ok(())
}

/// Split a command line by whitespace, preserving JSON objects in braces.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;

    for ch in input.chars() {
        match ch {
            '{' | '[' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' | ']' => {
                brace_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if brace_depth == 0 => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_simple() {
        let args = shell_split("ENCRYPT payments SGVsbG8=");
        assert_eq!(args, vec!["ENCRYPT", "payments", "SGVsbG8="]);
    }

    #[test]
    fn shell_split_with_context() {
        let args = shell_split("ENCRYPT payments SGVsbG8= CONTEXT user-123");
        assert_eq!(
            args,
            vec!["ENCRYPT", "payments", "SGVsbG8=", "CONTEXT", "user-123"]
        );
    }
}
