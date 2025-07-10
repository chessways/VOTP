//! votp 2.1 – versatile one‑time‑pad XOR transformer
//!            + deterministic key generator (`--features keygen`)

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
#[cfg(unix)]
use libc; // for O_NOFOLLOW
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::Instant,
};

use zeroize::Zeroize;                    // ← needed for buf.zeroize()

#[cfg(feature = "progress")]
use indicatif::{ProgressBar, ProgressStyle};

#[cfg(feature = "verify")]
use atty;
#[cfg(feature = "verify")]
use sha2::{Digest, Sha256};
#[cfg(feature = "verify")]
use subtle::ConstantTimeEq;

#[cfg(unix)]
use filetime::{set_file_times, FileTime};
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[cfg(feature = "keygen")]
mod key;
mod util;                                 // ← new helper module

const BUF_CAP: usize = 64 * 1024; // 64 KiB
const TMP_PREFIX: &str = ".votp-tmp-";
const DEFAULT_KEY_FILE: &str = "key.key";

/* ─────────────────────────────── Helpers ─────────────────────────────── */

/// True when the error represents a cross‑device rename failure
fn is_cross_device(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    if err.kind() == ErrorKind::CrossDeviceLink {
        return true;
    }
    matches!(err.raw_os_error(), Some(18 | 17)) // EXDEV
}

/* ------------------ Hardened output‑file creation --------------------- */

fn create_output(out_path: &PathBuf) -> Result<std::fs::File> {
    let mut opt = OpenOptions::new();
    opt.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        // Reject symlinks and set close‑on‑exec.
        opt.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let f = opt
        .open(out_path)
        .with_context(|| format!("creating output '{}'", out_path.display()))?;

    // Lock first, then validate identity (Unix only; Windows skip).
    FileExt::lock_exclusive(&f).context("locking output file for exclusive access")?;

    #[cfg(unix)]
    {
        let ino_before = f.metadata()?.ino();
        let ino_after = std::fs::metadata(out_path)?.ino();
        if ino_before != ino_after {
            bail!("Output file changed after locking – aborting.");
        }
    }

    // Tighten ACLs on Windows so only owner + Administrators may read/write.
    #[cfg(windows)]
    util::tighten_dacl(out_path)
        .with_context(|| format!("setting restrictive ACL on '{}'", out_path.display()))?;

    Ok(f)
}

/* ─────────────────────────────── CLI ─────────────────────────────────── */

#[derive(Subcommand, Debug)]
enum Command {
    /// One‑time‑pad XOR transform (default when no sub‑command is given)
    #[command(name = "xor", alias = "enc")]
    Xor(XorArgs),

    /// Deterministic key generator (requires `--features keygen`)
    #[cfg(feature = "keygen")]
    Keygen(key::KeyArgs),
}

#[derive(Parser, Debug)]
#[command(author, version, about, disable_help_subcommand = true)]
struct Cli {
    /// Optional sub‑command; if omitted we treat arguments as `xor` flags.
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Parser, Debug)]
/// Flags for the XOR transformer
struct XorArgs {
    /// Input file (use '-' for STDIN; '--in-place' forbidden with STDIN)
    #[arg(short, long)]
    input: PathBuf,

    /// Key file (falls back to $OTP_KEY, then 'key.key')
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// Output file (use '-' for STDOUT). Ignored with --in-place.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Encrypt/decrypt in place (atomic replace of INPUT)
    #[arg(long, conflicts_with = "output")]
    in_place: bool,

    /// Require key length ≥ data length
    #[arg(long, conflicts_with = "strict_len")]
    min_len: bool,

    /// Require key length == data length (classical OTP discipline)
    #[arg(long)]
    strict_len: bool,

    /// Print/verify SHA‑256 (needs --features verify)
    #[cfg(feature = "verify")]
    #[arg(long)]
    expect: Option<String>,

    /// Show a live progress bar
    #[cfg(feature = "progress")]
    #[arg(long)]
    progress: bool,
}

/* ───────────────────────────── main() ─────────────────────────────────── */

fn main() -> Result<()> {
    // Back‑compat: if first arg looks like a sub‑command run the sub‑parser.
    let first = std::env::args().nth(1);
    let looks_like_sub = matches!(first.as_deref(), Some("xor") | Some("keygen"));

    if looks_like_sub {
        let cli = Cli::parse();
        match cli.cmd.expect("sub‑command present") {
            Command::Xor(args) => run_xor(args),
            #[cfg(feature = "keygen")]
            Command::Keygen(kargs) => key::run(kargs).map_err(|e| anyhow!(e)),
        }
    } else {
        let args = XorArgs::parse();
        run_xor(args)
    }
}

/* ─────────────────── One‑Time‑Pad transformer (XOR) ───────────────────── */

fn run_xor(args: XorArgs) -> Result<()> {
    let t0 = Instant::now();

    /* -------- resolve key path ----------------------------------------- */
    let key_path = args
        .key
        .or_else(|| std::env::var_os("OTP_KEY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));

    if !key_path.exists() {
        bail!("key file '{}' does not exist", key_path.display());
    }

    /* -------- source metadata (skip for STDIN) -------------------------- */
    let (data_len, src_meta_opt) = if args.input == PathBuf::from("-") {
        (0, None)
    } else {
        let m = fs::metadata(&args.input)
            .with_context(|| format!("reading metadata for '{}'", args.input.display()))?;
        (m.len(), Some(m))
    };

    /* -------- pre‑capture input xattrs (Unix, optional) ---------------- */
    #[cfg(feature = "xattrs")]
    let saved_xattrs: Vec<(std::ffi::OsString, Vec<u8>)> = if args.input != PathBuf::from("-") {
        xattr::list(&args.input)
            .unwrap_or_default()
            .filter_map(|attr| {
                xattr::get(&args.input, &attr)
                    .ok()
                    .flatten()
                    .map(|val| (attr, val))
            })
            .collect()
    } else {
        Vec::new()
    };

    /* -------- key length checks ---------------------------------------- */
    let key_len = fs::metadata(&key_path)
        .with_context(|| format!("reading metadata for key '{}'", key_path.display()))?
        .len();

    if data_len != 0 && args.strict_len && key_len != data_len {
        bail!("--strict-len: key {} ≠ data {}", key_len, data_len);
    }
    if data_len != 0 && args.min_len && key_len < data_len {
        bail!("--min-len: key {} < data {}", key_len, data_len);
    }

    /* -------- warn on short‑key mode ----------------------------------- */
    if data_len != 0 && key_len != data_len && !args.min_len && !args.strict_len {
        eprintln!(
            "⚠️  Key length ({key_len} bytes) differs from data length \
({data_len} bytes). The key will repeat – cipher is **NOT** OTP‑strong."
        );
    }

    /* -------- prepare streams ------------------------------------------ */

    // Key reader (shared lock)
    let mut key_file = File::open(&key_path)
        .with_context(|| format!("opening key '{}'", key_path.display()))?;
    FileExt::lock_shared(&key_file).context("locking key file")?;

    #[cfg(feature = "xattrs")]
    let mut dest_path_for_attrs: Option<PathBuf> = None;

    /* ----- writer: tmp file for --in-place, else out_path -------------- */
    let (mut writer, tmp_path): (Box<dyn Write>, Option<PathBuf>) = if args.in_place {
        let dir = args
            .input
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory of input"))?;
        let tmp = tempfile::Builder::new()
            .prefix(TMP_PREFIX)
            .tempfile_in(dir)
            .context("creating temporary file")?;

        if let Some(ref meta) = src_meta_opt {
            fs::set_permissions(tmp.path(), meta.permissions())
                .context("copying permissions to temp file")?;
        }

        let (handle, path) = tmp.keep().context("persisting temporary file")?;
        FileExt::lock_exclusive(&handle).context("locking temporary output file")?;

        #[cfg(windows)]
        util::tighten_dacl(path.as_path())
            .with_context(|| format!("setting restrictive ACL on '{}'", path.display()))?;

        #[cfg(feature = "xattrs")]
        {
            dest_path_for_attrs = Some(args.input.clone());
        }
        (Box::new(handle), Some(path))
    } else {
        let out_path = args
            .output
            .clone()
            .ok_or_else(|| anyhow!("--output or --in-place must be supplied"))?;
        if out_path == PathBuf::from("-") {
            (Box::new(std::io::stdout().lock()), None)
        } else {
            let f = create_output(&out_path)?;
            #[cfg(feature = "xattrs")]
            {
                dest_path_for_attrs = Some(out_path.clone());
            }
            (Box::new(f), None)
        }
    };

    /* ----- reader: stdin or file --------------------------------------- */
    let mut reader: Box<dyn Read> = if args.input == PathBuf::from("-") {
        Box::new(std::io::stdin().lock())
    } else {
        let f = OpenOptions::new()
            .read(true)
            .open(&args.input)
            .with_context(|| format!("opening input '{}'", args.input.display()))?;
        FileExt::lock_exclusive(&f).with_context(|| "locking input file for exclusive access")?;
        Box::new(f)
    };

    /* -------- optional progress bar ------------------------------------ */
    #[cfg(feature = "progress")]
    let bar = if args.progress {
        let pb = ProgressBar::new(data_len);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})",
            )
            .unwrap(),
        );
        Some(pb)
    } else {
        None
    };

    /* -------- streaming XOR loop --------------------------------------- */
    let mut data_buf = vec![0u8; BUF_CAP];
    let mut key_buf = vec![0u8; BUF_CAP];

    #[cfg(feature = "verify")]
    let mut hasher_opt = if args.expect.is_some() {
        Some(Sha256::new())
    } else {
        None
    };

    loop {
        let n = reader.read(&mut data_buf)?;
        if n == 0 {
            break;
        }
        fill_key_slice(&mut key_file, &mut key_buf[..n])?;
        for (d, k) in data_buf[..n].iter_mut().zip(&key_buf[..n]) {
            *d ^= *k;
        }

        #[cfg(feature = "verify")]
        if let Some(ref mut h) = hasher_opt {
            h.update(&data_buf[..n]);
        }

        writer.write_all(&data_buf[..n])?;
        data_buf[..n].zeroize();
        key_buf[..n].zeroize();

        #[cfg(feature = "progress")]
        if let Some(ref pb) = bar {
            pb.inc(n as u64);
        }
    }
    writer.flush()?;

    #[cfg(feature = "progress")]
    if let Some(pb) = bar {
        pb.finish_and_clear();
    }

    /* -------- durability fences & in‑place swap ------------------------ */
    if let Some(ref tmp) = tmp_path {
        let f = OpenOptions::new().write(true).open(tmp)?;
        f.sync_all()?;
        if let Some(parent) = tmp.parent() {
            if let Ok(d) = File::open(parent) {
                let _ = d.sync_all();
            }
        }

        #[cfg(windows)]
        {
            let mut perms = fs::metadata(&args.input)?.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                fs::set_permissions(&args.input, perms)?;
            }
        }

        match fs::rename(&tmp, &args.input) {
            Ok(_) => {}
            Err(e) if is_cross_device(&e) => {
                fs::copy(&tmp, &args.input).context("cross‑device copy")?;

                {
                    let dest = OpenOptions::new().write(true).open(&args.input)?;
                    dest.sync_all()?;
                }
                if let Some(parent) = args.input.parent() {
                    if let Ok(dir) = File::open(parent) {
                        let _ = dir.sync_all();
                    }
                }

                fs::remove_file(&tmp)?;
            }
            Err(e) => return Err(e.into()),
        }

        #[cfg(unix)]
        if let Some(src_meta) = src_meta_opt {
            let atime = FileTime::from_last_access_time(&src_meta);
            let mtime = FileTime::from_last_modification_time(&src_meta);
            set_file_times(&args.input, atime, mtime).context("restoring timestamps")?;
        }
    }

    /* -------- restore xattrs (Unix, optional) -------------------------- */
    #[cfg(feature = "xattrs")]
    if let Some(ref dest) = dest_path_for_attrs {
        for (attr, val) in &saved_xattrs {
            let _ = xattr::set(dest, attr, val);
        }
    }

    /* -------- optional SHA‑256 verification ---------------------------- */
    #[cfg(feature = "verify")]
    if let Some(hasher) = hasher_opt {
        let digest = format!("{:x}", hasher.finalize());

        match args.expect {
            Some(expected) => {
                let got = digest.to_lowercase();
                let want = expected.to_lowercase();
                if got.len() != want.len()
                    || got.as_bytes().ct_eq(want.as_bytes()).unwrap_u8() == 0
                {
                    bail!("SHA‑256 mismatch! expected {want}, got {got}");
                }
                eprintln!("✓ SHA‑256 verified");
            }
            None => {
                if atty::is(atty::Stream::Stderr) {
                    eprintln!("SHA‑256(output) = {digest}");
                }
            }
        }
    }

    eprintln!("✓ done in {:.2?}", t0.elapsed());
    Ok(())
}

/* ───────────────────────────── Helpers ─────────────────────────────────── */

/// Fill `dest` with bytes from `key`, rewinding on EOF.
fn fill_key_slice<R: Read + Seek>(key: &mut R, dest: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < dest.len() {
        let n = key.read(&mut dest[filled..])?;
        if n == 0 {
            key.seek(SeekFrom::Start(0))?;
            let n2 = key.read(&mut dest[filled..])?;
            if n2 == 0 {
                bail!("key file is empty or became unreadable during processing");
            }
            filled += n2;
        } else {
            filled += n;
        }
    }
    Ok(())
}
