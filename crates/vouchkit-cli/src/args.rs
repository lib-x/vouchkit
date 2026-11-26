use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::PathBuf;
use vouchkit_core::{AppVersion, FeatureSlots, Id};

#[derive(Parser)]
#[command(
    name = "vouch",
    version,
    about = "Offline author tools for vouchkit licenses"
)]
pub(crate) struct Cli {
    /// Owner-only file containing a master key passphrase for unattended use.
    #[arg(long, global = true, value_name = "FILE")]
    pub(crate) passphrase_file: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate a master or delegate key pair.
    Keygen(Keygen),
    /// Sign a limited delegation certificate.
    Delegate(Delegate),
    /// Issue an offline license or an activation entitlement.
    Issue(Issue),
    /// Generate Rust source for a build-specific tag profile.
    Profile(Profile),
    /// Encrypt a resource with a derived feature key.
    SealAsset(SealAsset),
    /// Show the contents of an unverified license.
    Inspect {
        /// Inline token or path to an armored license.
        input: OsString,
    },
    /// Verify a license and report its authorization state.
    Verify(Verify),
    /// Publish an updated signed revocation list.
    Revoke(Revoke),
    /// Read the issuance ledger.
    Ledger {
        #[command(subcommand)]
        action: LedgerCommand,
    },
}

#[derive(Args)]
pub(crate) struct Keygen {
    #[arg(long, value_enum)]
    pub(crate) kind: KeyKind,
    /// Required for a master key.
    #[arg(long)]
    pub(crate) key_id: Option<u8>,
    #[arg(long, default_value = ".")]
    pub(crate) out_dir: PathBuf,
    /// Write an unencrypted master seed to master.key.
    #[arg(long)]
    pub(crate) insecure_plaintext: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum KeyKind {
    Master,
    Delegate,
}

#[derive(Args)]
pub(crate) struct Delegate {
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long)]
    pub(crate) delegate_pub: PathBuf,
    #[arg(long)]
    pub(crate) product: String,
    #[arg(long, default_value_t = 90)]
    pub(crate) valid_days: u64,
    /// Maximum lease lifetime, including its grace period.
    #[arg(long, value_parser = duration, default_value = "35d")]
    pub(crate) max_lease: u64,
    #[arg(long)]
    pub(crate) max_tier: u8,
    /// Hexadecimal mask for slots 0–31.
    #[arg(long, value_parser = feature_mask, default_value = "0")]
    pub(crate) feature_mask: u32,
    /// Additional decimal slot IDs or inclusive ranges, such as 64,100-108.
    #[arg(long, value_parser = slot_range, value_delimiter = ',')]
    pub(crate) feature_slots: Vec<(u16, u16)>,
    #[arg(long)]
    pub(crate) out: PathBuf,
    #[arg(long, default_value = "issued.jsonl")]
    pub(crate) ledger: PathBuf,
}

#[derive(Args)]
pub(crate) struct Issue {
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long, value_enum)]
    pub(crate) class: IssueClass,
    #[arg(long)]
    pub(crate) product: String,
    #[arg(long)]
    pub(crate) subject: String,
    #[arg(long)]
    pub(crate) tier: u8,
    /// Hexadecimal mask for slots 0–31.
    #[arg(long, value_parser = feature_mask, default_value = "0")]
    pub(crate) features: u32,
    /// Additional decimal slot IDs or inclusive ranges, such as 64,100-108.
    #[arg(long, value_parser = slot_range, value_delimiter = ',')]
    pub(crate) feature_slots: Vec<(u16, u16)>,
    /// Seconds, or a duration suffixed by s, m, h, d or w.
    #[arg(long, value_parser = duration)]
    pub(crate) expires: Option<u64>,
    /// Earliest usable Unix time.
    #[arg(long)]
    pub(crate) not_before: Option<u64>,
    /// Offline grace for a standalone license with an expiry.
    #[arg(long, default_value_t = 0)]
    pub(crate) grace_secs: u32,
    #[arg(long, value_parser = max_version)]
    pub(crate) max_version: Option<AppVersion>,
    /// Number of seats for an entitlement. Defaults to one.
    #[arg(long)]
    pub(crate) max_devices: Option<u8>,
    /// Optional Base64 device public key for a standalone license.
    #[arg(long)]
    pub(crate) device_pub: Option<String>,
    #[arg(long)]
    pub(crate) tags: bool,
    /// Comma-separated resource key feature IDs.
    #[arg(long, value_delimiter = ',')]
    pub(crate) unlock: Vec<u16>,
    #[arg(long, value_enum, default_value = "token")]
    pub(crate) format: OutputFormat,
    /// Write to this file in place of stdout.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long, default_value = "issued.jsonl")]
    pub(crate) ledger: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum IssueClass {
    Standalone,
    Entitlement,
}

impl IssueClass {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Entitlement => "entitlement",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum OutputFormat {
    Token,
    File,
}

#[derive(Args)]
pub(crate) struct Profile {
    #[arg(long)]
    pub(crate) key: PathBuf,
    /// Two or more comma-separated slot IDs in the range 0–7.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) slots: Vec<u8>,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct SealAsset {
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long)]
    pub(crate) product: String,
    #[arg(long)]
    pub(crate) feature: u16,
    #[arg(long = "in")]
    pub(crate) input: PathBuf,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct Verify {
    /// Inline token or path to an armored license.
    pub(crate) input: OsString,
    /// Trusted master public key. Repeat during key rotation.
    #[arg(long, required = true)]
    pub(crate) pubkey: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) product: String,
    #[arg(long, value_parser = version, default_value = "0.0.0")]
    pub(crate) app_version: AppVersion,
    #[arg(long)]
    pub(crate) crl: Option<PathBuf>,
    /// Local device key for validating a bound license.
    #[arg(long)]
    pub(crate) device_key: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct Revoke {
    #[arg(long)]
    pub(crate) key: PathBuf,
    /// Also trust a previous master public key when continuing a CRL.
    #[arg(long)]
    pub(crate) pubkey: Vec<PathBuf>,
    #[arg(long, default_value = "issued.jsonl")]
    pub(crate) ledger: PathBuf,
    #[arg(long, value_parser = id)]
    pub(crate) license: Vec<Id>,
    /// Authenticate a lease token or file and revoke the individual lease.
    #[arg(long, value_name = "TOKEN_OR_FILE")]
    pub(crate) lease: Vec<OsString>,
    #[arg(long, value_parser = id)]
    pub(crate) entitlement: Vec<Id>,
    #[arg(long, value_parser = id, requires = "since")]
    pub(crate) cert: Vec<Id>,
    /// Earliest revoked issuance timestamp, inclusive.
    #[arg(long, requires = "cert")]
    pub(crate) since: Option<u64>,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Subcommand)]
pub(crate) enum LedgerCommand {
    /// Print each issued license and delegation record as JSON.
    List {
        #[arg(long, default_value = "issued.jsonl")]
        ledger: PathBuf,
    },
}

pub(crate) fn slots(mask: u32, additional: &[(u16, u16)]) -> Result<FeatureSlots> {
    let legacy = FeatureSlots::from(mask);
    let mut ranges = Vec::from(legacy.ranges());
    ranges.extend_from_slice(additional);
    Ok(FeatureSlots::try_from_ranges(&ranges)?)
}

fn slot_range(input: &str) -> Result<(u16, u16)> {
    let (first, last) = input.split_once('-').unwrap_or((input, input));
    let first = first.parse().context("invalid first feature slot")?;
    let last = last.parse().context("invalid last feature slot")?;
    ensure!(first <= last, "feature slot range must be ascending");
    Ok((first, last))
}

fn id(input: &str) -> Result<Id> {
    let mut bytes = [0; 16];
    hex::decode_to_slice(input, &mut bytes).context("expected a 32-character hexadecimal ID")?;
    Ok(bytes)
}

fn feature_mask(input: &str) -> Result<u32> {
    let input = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    u32::from_str_radix(input, 16).context("expected a 32-bit hexadecimal feature mask")
}

fn duration(input: &str) -> Result<u64> {
    let amount_end = input.bytes().take_while(u8::is_ascii_digit).count();
    let (amount, suffix) = input.split_at(amount_end);
    let factor = match suffix {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => bail!("duration must use s, m, h, d or w"),
    };
    let amount: u64 = amount.parse().context("invalid duration")?;
    let seconds = amount.checked_mul(factor).context("duration too large")?;
    ensure!(seconds != 0, "duration must be positive");
    Ok(seconds)
}

fn version(input: &str) -> Result<AppVersion> {
    parse_version(input, VersionKind::Exact)
}

fn max_version(input: &str) -> Result<AppVersion> {
    parse_version(input, VersionKind::Maximum)
}

enum VersionKind {
    Exact,
    Maximum,
}

fn parse_version(input: &str, kind: VersionKind) -> Result<AppVersion> {
    let fields: Vec<_> = input.splitn(4, '.').collect();
    let [major, minor, patch] = fields.as_slice() else {
        bail!("expected three version components");
    };
    let major = major.parse().context("invalid major version")?;
    let wildcard = |part: &str| part.eq_ignore_ascii_case("x") || part == "*";
    if matches!(kind, VersionKind::Maximum) && wildcard(minor) {
        ensure!(
            wildcard(patch),
            "a wildcard minor version requires a wildcard patch"
        );
        return Ok((major, u16::MAX, u16::MAX));
    }
    let minor = minor.parse().context("invalid minor version")?;
    let patch = if matches!(kind, VersionKind::Maximum) && wildcard(patch) {
        u16::MAX
    } else {
        patch.parse().context("invalid patch version")?
    };
    Ok((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::{duration, max_version, slot_range, slots, version};
    use anyhow::Result;

    #[test]
    fn duration_parsing_rejects_zero_and_overflow() -> Result<()> {
        assert_eq!(duration("35d")?, 3_024_000);
        assert_eq!(duration("14")?, 14);
        assert!(duration("0s").is_err());
        assert!(duration("18446744073709551615d").is_err());
        assert!(duration("1.5h").is_err());
        Ok(())
    }

    #[test]
    fn wildcard_version_is_only_valid_for_a_maximum() -> Result<()> {
        assert_eq!(max_version("2.x.x")?, (2, u16::MAX, u16::MAX));
        assert_eq!(max_version("2.3.*")?, (2, 3, u16::MAX));
        assert!(max_version("2.x.3").is_err());
        assert!(version("2.x.x").is_err());
        assert!(version("2.5").is_err());
        Ok(())
    }

    #[test]
    fn decimal_slots_merge_with_low_mask() -> Result<()> {
        let additional = [slot_range("7-8")?, slot_range("40")?, slot_range("41-48")?];
        assert_eq!(slots(1 << 6, &additional)?.ranges(), &[(6, 8), (40, 48)]);
        assert!(slot_range("8-7").is_err());
        assert!(slot_range("65536").is_err());
        Ok(())
    }
}
