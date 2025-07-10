//! key.rs – deterministic high‑strength key material generator
//!
//! Build stand‑alone with:
//!   cargo run --release --features keygen -- keygen 10MiB my.key
//!
//! Integrated into votp’s CLI as the `keygen` sub‑command.

#![cfg(feature = "keygen")]

use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    process,
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake3;
use clap::{Args, ValueEnum};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// **Updated defaults**
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
const DEFAULT_ARGON2_TIME_COST: u32 = 3;

/// A global salt would break OTP‑like guarantees – we force a random user salt.
const MIN_SALT_LEN_B64: usize = 12; // 9 bytes raw

#[derive(Copy, Clone, ValueEnum)]
pub enum StreamAlgo {
    Blake3,
    Chacha,
}

impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamAlgo::Blake3 => write!(f, "blake3"),
            StreamAlgo::Chacha => write!(f, "chacha"),
        }
    }
}

/// CLI for the `keygen` sub‑command
#[derive(Args)]
#[command(
    about = "Deterministic cryptographic key generator (NOT a perfect OTP)",
    after_help = "Size suffixes: <n>[kb|mb|gb|kib|mib|gib] (case‑insensitive)\n\
                  A unique, random salt *must* be supplied with --salt BASE64."
)]
pub struct KeyArgs {
    /// Key size (e.g. 10kb, 5mb, 1gb)
    pub size: String,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    pub output: String,

    /// Output stream algorithm
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    pub algo: StreamAlgo,

    /// Mandatory salt (base64)
    #[arg(short, long)]
    pub salt: Option<String>,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    pub argon2_memory: u32,

    /// Argon2 time cost
    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME_COST)]
    pub argon2_time: u32,

    /// Argon2 parallelism (0 = auto)
    #[arg(long, default_value_t = 0)]
    pub argon2_par: u32,

    /// Convenience helper: generate a fresh base‑64 salt of N bytes and exit
    #[arg(long = "gen-salt")]
    pub gen_salt: Option<usize>,
}

/* ------------------------------------------------------------------------- */

/// **Zero‑on‑drop** BufWriter wrapper – prevents stray key material
struct ZeroizingWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> ZeroizingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner: BufWriter::new(inner),
        }
    }
}

impl<W: Write> Write for ZeroizingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for ZeroizingWriter<W> {
    fn drop(&mut self) {
        self.inner.buffer_mut().zeroize(); // scrub even on panic
    }
}

/// Generate a random salt, print it and exit.
fn gen_and_print_salt(n: usize) -> ! {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    println!("{}", B64.encode(&buf));
    process::exit(0);
}

/// Parallelism helper (0 = auto).
fn effective_parallelism(user: u32) -> u32 {
    if user != 0 {
        return user;
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

pub fn run(k: KeyArgs) -> io::Result<()> {
    /* ---------- optional salt generator fast‑path --------------------- */
    if let Some(n) = k.gen_salt {
        gen_and_print_salt(n);
    }

    /* ---------- parse size ------------------------------------------- */
    let size = parse_size(&k.size).unwrap_or_else(|e| {
        eprintln!("❌ {e}");
        process::exit(1);
    });

    /* ---------- password + confirm (constant‑time compare) ----------- */
    let pwd1: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Enter password: ")?);
    let pwd2: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Confirm password: ")?);

    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    /* ---------- salt -------------------------------------------------- */
    let salt_b64: Zeroizing<String> = Zeroizing::new(k.salt.unwrap_or_else(|| {
        eprintln!("❌ A unique base‑64 salt is required (use --salt).");
        process::exit(1);
    }));

    if salt_b64.len() < MIN_SALT_LEN_B64 {
        eprintln!("❌ Salt too short – need ≥{MIN_SALT_LEN_B64} base‑64 chars (~9 bytes).");
        process::exit(1);
    }

    let salt_bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(match B64.decode(&*salt_b64) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("❌ Salt is not valid base64");
                process::exit(1);
            }
        });

    /* ---------- salt entropy hint (soft) ----------------------------- */
    {
        use std::collections::HashSet;
        if HashSet::<u8>::from_iter(salt_bytes.iter().copied()).len() <= 4 {
            eprintln!("⚠️  Salt appears low‑entropy; consider --gen-salt.");
        }
    }

    /* ---------- derive 32‑byte seed ---------------------------------- */
    let par_eff = effective_parallelism(k.argon2_par);
    println!(
        "📦 Generating {size} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        k.algo, k.argon2_memory, k.argon2_time, par_eff
    );

    let start = Instant::now();
    let mut seed = derive_seed(&pwd1, &salt_bytes, k.argon2_memory, k.argon2_time, par_eff);

    /* ---------- stream generator ------------------------------------- */
    let result = match k.algo {
        StreamAlgo::Blake3 => write_blake3(&k.output, &seed, size),
        StreamAlgo::Chacha => write_chacha(&k.output, &seed, size),
    };

    /* ---------- clean‑up --------------------------------------------- */
    seed.zeroize();
    result?;
    println!("✅ Key written to '{}' in {:.2?}", k.output, start.elapsed());
    Ok(())
}

/* ========== internal helpers =========================================== */

fn derive_seed(
    password: &Zeroizing<String>,
    salt_bytes: &[u8],
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    if mem > 4 * 1024 * 1024 {
        eprintln!("❌ argon2-memory ({mem} KiB) exceeds 4 GiB limit.");
        process::exit(1);
    }

    let params = match Params::new(mem, time, par, None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ invalid Argon2 parameters: {e}");
            process::exit(1);
        }
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_bytes, &mut seed)
        .unwrap_or_else(|e| {
            eprintln!("❌ Argon2id hashing failed: {e}");
            process::exit(1);
        });
    seed
}

fn write_blake3(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(path, size, |buf| xof.fill(buf))
}

fn write_chacha(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(path, size, |buf| rng.fill_bytes(buf))
}

fn stream_to_file<F>(path: &str, mut remaining: usize, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    let file = File::create(path)?;

    /* ---- restrict permissions: owner read/write only (Unix) ---------- */
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    // A proper Windows ACL fix would use the windows‑acl crate; omitted for brevity.

    let mut w = ZeroizingWriter::new(file);

    // Zeroized‑on‑drop buffer keeps key material out of RAM dumps
    let mut buf = Zeroizing::new([0u8; 8192]);

    while remaining != 0 {
        let n = remaining.min(buf.len());
        fill(&mut buf[..n]);
        w.write_all(&buf[..n])?;
        remaining -= n;
    }
    w.flush()
}

/// Parse sizes like “5mb”, “2MiB”, “123”.  Accepts `_` separators.
fn parse_size(arg: &str) -> Result<usize, String> {
    let s = arg.trim().to_lowercase().replace('_', "");

    let (num, mul): (&str, u128) = if let Some(n) = s.strip_suffix("gib") {
        (n, 1024u128.pow(3))
    } else if let Some(n) = s.strip_suffix("mib") {
        (n, 1024u128.pow(2))
    } else if let Some(n) = s.strip_suffix("kib") {
        (n, 1024u128)
    } else if let Some(n) = s.strip_suffix("gb") {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1_000)
    } else {
        (s.as_str(), 1)
    };

    let n: u128 = num
        .parse()
        .map_err(|_| format!("Invalid number in size specifier: '{arg}'"))?;
    let bytes = n
        .checked_mul(mul)
        .ok_or_else(|| format!("Size overflow for: '{arg}'"))?;
    usize::try_from(bytes)
        .map_err(|_| format!("Size too large for this platform: '{arg}'"))
}
