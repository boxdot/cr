use cr::des;

use anyhow::{anyhow, Context as _};
use argh::FromArgs;

use std::convert::TryInto as _;
use std::io::{self, Read as _};

#[derive(FromArgs)]
/// Encrypt and decrypt hex strings
struct Args {
    /// 64bit key as hex string
    #[argh(option, short = 'k')]
    key: String,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let plaintext = hex_to_u64(&buffer.trim()).context("invalid plaintext")?;
    let key = hex_to_u64(&args.key).context("invalid key")?;

    let ciphertext = des::encrypt(plaintext, key);
    println!("{}", hex::encode(ciphertext.to_le_bytes()));

    Ok(())
}

fn hex_to_u64(s: &str) -> anyhow::Result<u64> {
    let bytes_vec = hex::decode(s)?;
    let bytes: [u8; 8] = bytes_vec
        .try_into()
        .map_err(|v: Vec<_>| anyhow!("expected a hex string of 8 bytes but it was {}", v.len()))?;
    Ok(u64::from_le_bytes(bytes))
}
