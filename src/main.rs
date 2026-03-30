use std::process;

use clap::{ArgGroup, Parser};
use rusty_smb_scan::{
    backend::platform::PlatformBackend,
    credentials::{AuthMethod, Credentials},
    output::{render, OutputFormat},
    scanner::{ScanConfig, Scanner},
};

/// Enumerate SMB shares and probe read/write access.
#[derive(Parser, Debug)]
#[command(
    name = "rusty-smb-scan",
    version,
    about = "Enumerate SMB shares and check access",
    long_about = None,
)]
#[command(group(
    ArgGroup::new("auth")
        .required(false)
        .args(["username", "null_session", "kerberos"])
))]
struct Cli {
    /// Target host(s). May be specified multiple times.
    #[arg(long, short = 'H', required = true, num_args = 1..)]
    host: Vec<String>,

    /// Username for password or NTLM-hash auth.
    #[arg(short = 'u', long)]
    username: Option<String>,

    /// Password for password auth.
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Domain or workgroup (default: WORKGROUP).
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// NTLM hash in `LM:NT` or just `NT` hex format (pass-the-hash).
    #[arg(long, value_name = "LM:NT")]
    hash: Option<String>,

    /// Use a null / anonymous session.
    #[arg(long)]
    null_session: bool,

    /// Use the Kerberos ticket cache (KRB5CCNAME). Requires --username and --domain.
    #[arg(long)]
    kerberos: bool,

    /// Include hidden shares (names ending with $, excluding admin shares).
    #[arg(long)]
    include_hidden: bool,

    /// Include administrative shares (ADMIN$, C$, IPC$, …).
    #[arg(long)]
    include_admin: bool,

    /// Also probe write access (creates and deletes a temporary file per share).
    #[arg(long)]
    check_write: bool,

    /// Per-host timeout in seconds.
    #[arg(short = 't', long, default_value = "10")]
    timeout: u64,

    /// Output format: table, json, or csv.
    #[arg(short = 'o', long, default_value = "table")]
    output: String,
}

fn main() {
    let cli = Cli::parse();

    let auth = match build_auth(&cli) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let creds = Credentials::new(auth).with_workgroup(
        cli.domain.clone().unwrap_or_else(|| "WORKGROUP".into()),
    );

    if let Err(e) = creds.validate() {
        eprintln!("error: {e}");
        process::exit(1);
    }

    let format: OutputFormat = match cli.output.parse() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let config = ScanConfig {
        timeout_secs: cli.timeout,
        include_hidden: cli.include_hidden,
        include_admin: cli.include_admin,
        check_write: cli.check_write,
    };

    let scanner = Scanner::new(PlatformBackend::new(), config);
    let results = scanner.scan(&cli.host, &creds);

    // Print non-fatal errors to stderr.
    for r in &results {
        for e in &r.errors {
            eprintln!("[{}] warning: {e}", r.host);
        }
    }

    match render(&results, &format) {
        Ok(output) => print!("{output}"),
        Err(e) => {
            eprintln!("error rendering output: {e}");
            process::exit(1);
        }
    }
}

fn build_auth(cli: &Cli) -> rusty_smb_scan::error::Result<AuthMethod> {
    use rusty_smb_scan::error::SmbError;

    if cli.null_session {
        return Ok(AuthMethod::Null);
    }

    if cli.kerberos {
        let username = cli
            .username
            .clone()
            .ok_or_else(|| SmbError::InvalidCredentials("--username required with --kerberos".into()))?;
        let realm = cli
            .domain
            .clone()
            .ok_or_else(|| SmbError::InvalidCredentials("--domain (realm) required with --kerberos".into()))?;
        return Ok(AuthMethod::Kerberos { username, realm });
    }

    if let Some(hash_str) = &cli.hash {
        let username = cli
            .username
            .clone()
            .ok_or_else(|| SmbError::InvalidCredentials("--username required with --hash".into()))?;
        let (lm, nt) = parse_hash_pair(hash_str);
        return Ok(AuthMethod::NtlmHash {
            username,
            lm_hash: lm,
            nt_hash: nt,
            domain: cli.domain.clone(),
        });
    }

    if let Some(username) = cli.username.clone() {
        let password = cli.password.clone().unwrap_or_default();
        return Ok(AuthMethod::Password {
            username,
            password,
            domain: cli.domain.clone(),
        });
    }

    // Default: null session
    Ok(AuthMethod::Null)
}

fn parse_hash_pair(s: &str) -> (String, String) {
    if let Some((lm, nt)) = s.split_once(':') {
        (lm.to_string(), nt.to_string())
    } else {
        ("".to_string(), s.to_string())
    }
}
