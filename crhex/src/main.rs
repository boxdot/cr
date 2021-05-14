use cr;

use anyhow::{anyhow, bail, Context as _};
use argh::FromArgs;

use std::convert::TryInto as _;
use std::io::{self, Read as _};
use std::str::FromStr;

#[derive(FromArgs)]
/// Encrypt and decrypt hex strings
struct Args {
    /// 64bit key as hex string
    #[argh(option, short = 'k')]
    key: String,
    /// algorithm to use for encryption [avalaible: des, aes128]
    #[argh(option, short = 'a')]
    algorithm: Algorithm,
}

enum Algorithm {
    Des,
    Aes128,
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "des" => Self::Des,
            "aes128" => Self::Aes128,
            _ => bail!("unknown algorithm: {}", s),
        })
    }
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let ciphertext = match args.algorithm {
        Algorithm::Des => {
            let plaintext = hex_to_u64(&buffer.trim()).context("invalid plaintext")?;
            let key = hex_to_u64(&args.key).context("invalid key")?;
            cr::des::encrypt(plaintext, key).to_le_bytes().to_vec()
        }
        Algorithm::Aes128 => {
            let plaintext = hex_to_array(&buffer.trim()).context("invalid plaintext")?;
            let key = hex_to_array(&args.key).context("invalid key")?;
            cr::aes::encrypt_128(plaintext, key).to_vec()
        }
    };

    println!("{}", hex::encode(&ciphertext));

    Ok(())
}

fn hex_to_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let bytes_vec = hex::decode(s)?;
    Ok(bytes_vec.try_into().map_err(|v: Vec<_>| {
        anyhow!(
            "expected a hex string of {} bytes but it was {}",
            N,
            v.len()
        )
    })?)
}

fn hex_to_u64(s: &str) -> anyhow::Result<u64> {
    hex_to_array(s).map(u64::from_le_bytes)
}
