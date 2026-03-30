# rusty-smb-scan

Enumerate SMB shares on one or more hosts and probe read/write access per share. Supports SMB1/SMB2 auto-negotiation, multiple authentication methods, and three output formats.

Runs on **Linux**, **macOS**, and **Windows**.

---

## Features

- **Share enumeration** — lists all visible shares on a host
- **Access probing** — tests read access (listing) and optionally write access (creates + deletes a probe file)
- **Multiple auth methods** — password, pass-the-hash (NTLM), Kerberos, null/guest session
- **Hidden & admin share support** — opt-in via flags
- **Multi-host scanning** — scan several hosts in one invocation
- **Per-host timeout** — never hangs on an unreachable host
- **Output formats** — human-readable table, JSON, CSV

---

## Installation

### Prerequisites

**Linux / macOS**

```bash
# Debian / Ubuntu
sudo apt install pkg-config libsmbclient-dev

# Fedora / RHEL
sudo dnf install libsmbclient-devel

# macOS (Homebrew)
brew install samba
```

**Windows** — no extra dependencies; uses Win32 APIs (`NetShareEnum`, `WNetAddConnection2A`) that ship with Windows.

### Build from source

```bash
git clone https://github.com/yourname/rusty-smb-scan
cd rusty-smb-scan
cargo build --release
# binary at: target/release/rusty-smb-scan
```

---

## Usage

```
rusty-smb-scan [OPTIONS] --host <HOST>...

Options:
  -H, --host <HOST>...       Target host(s). May be specified multiple times
  -u, --username <USERNAME>  Username for password or NTLM-hash auth
  -p, --password <PASSWORD>  Password for password auth
  -d, --domain <DOMAIN>      Domain or workgroup (default: WORKGROUP)
      --hash <LM:NT>         NTLM hash in LM:NT or just NT hex format (pass-the-hash)
      --null-session         Use a null / anonymous session
      --kerberos             Use the Kerberos ticket cache (KRB5CCNAME)
      --include-hidden       Include hidden shares (names ending with $)
      --include-admin        Include administrative shares (ADMIN$, C$, IPC$, ...)
      --check-write          Also probe write access
  -t, --timeout <SECS>       Per-host timeout in seconds [default: 10]
  -o, --output <FMT>         Output format: table | json | csv [default: table]
  -h, --help                 Print help
  -V, --version              Print version
```

---

## Examples

### Password auth (default table output)

```bash
rusty-smb-scan -H 192.168.1.10 -u alice -p s3cr3t
```

```
+---------------+----------+------+--------+--------------+
| Host          | Share    | Type | Access | Comment      |
+---------------+----------+------+--------+--------------+
| 192.168.1.10  | public   | disk | read   | Public files |
| 192.168.1.10  | uploads  | disk | none   |              |
+---------------+----------+------+--------+--------------+
```

### Include admin shares and probe write access

```bash
rusty-smb-scan -H fileserver -u admin -p pass --include-admin --check-write -o table
```

### Pass-the-hash (NTLM)

```bash
# NT hash only
rusty-smb-scan -H 10.0.0.5 -u alice --hash 8846f7eaee8fb117ad06bdd830b7586c

# LM:NT pair
rusty-smb-scan -H 10.0.0.5 -u alice --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### Kerberos (Linux — reads `KRB5CCNAME`)

```bash
kinit alice@CORP.LOCAL
rusty-smb-scan -H dc01.corp.local --kerberos -u alice -d CORP.LOCAL
```

### Kerberos (Windows — uses existing TGT/TGS automatically)

On a domain-joined Windows machine, `--kerberos` passes `NULL` credentials to `WNetAddConnection2A`, which tells Windows to use the current session's ticket cache. No `kinit` required.

```cmd
rusty-smb-scan.exe -H dc01.corp.local --kerberos
```

### Null session

```bash
rusty-smb-scan -H 192.168.1.10 --null-session
```

### Multiple hosts

```bash
rusty-smb-scan -H 192.168.1.10 -H 192.168.1.11 -H 192.168.1.12 -u bob -p pass
```

### JSON output (pipe-friendly)

```bash
rusty-smb-scan -H fileserver -u alice -p pass -o json | jq '.hosts[].shares[].name'
```

### CSV output

```bash
rusty-smb-scan -H fileserver -u alice -p pass --include-admin -o csv > shares.csv
```

---

## Authentication methods

| Flag | Method | Notes |
|---|---|---|
| `-u`/`-p` | Password (NTLMv2) | Standard credential auth |
| `--hash` | Pass-the-hash | NTLM hash; Windows experimental (see below) |
| `--kerberos` | Kerberos | Linux: reads `KRB5CCNAME`; Windows: uses existing TGT |
| `--null-session` | Anonymous | Empty credentials; some servers allow share listing |
| *(none)* | Null (default) | Falls back to null session if no auth flags given |

### Pass-the-hash on Windows

`WNetAddConnection2A` does not accept raw NT hashes directly — it only takes plaintext passwords. Full pass-the-hash on Windows requires LSA token injection (`LsaLogonUser`) which is not yet implemented. The `--hash` flag works fully on Linux via libsmbclient.

---

## Platform notes

### Linux / macOS

Uses [`pavao`](https://crates.io/crates/pavao) (libsmbclient bindings). Share comments are populated. SMB protocol version is auto-negotiated by libsmbclient (SMB1 through SMB3).

### Windows

Uses native Win32 APIs:
- **`NetShareEnum`** (level 1) for share enumeration — runs under the current Windows security context, so Kerberos TGT/TGS is used automatically for domain targets.
- **`WNetAddConnection2A`** / **`WNetCancelConnection2W`** for credential injection when probing access. Connections are cleaned up via a RAII guard even on error.
- Read access: `std::fs::read_dir` over UNC paths (`\\host\share`)
- Write access: creates and deletes `\\host\share\__rusty_smb_probe_<timestamp>.tmp`

---

## Running tests

### Unit tests (no network required)

```bash
cargo test
```

### Integration tests (requires a real SMB server)

```bash
export SMB_TEST_HOST=192.168.1.10
export SMB_TEST_USER=testuser
export SMB_TEST_PASS=testpass
export SMB_TEST_DOMAIN=WORKGROUP
export SMB_TEST_READABLE_SHARE=public
export SMB_TEST_WRITABLE_SHARE=uploads

cargo test --features integration-tests -- --include-ignored
```

| Variable | Required | Purpose |
|---|---|---|
| `SMB_TEST_HOST` | Yes | Target SMB server |
| `SMB_TEST_USER` | Yes | Username |
| `SMB_TEST_PASS` | Yes | Password |
| `SMB_TEST_DOMAIN` | No | Domain/workgroup (default: `WORKGROUP`) |
| `SMB_TEST_READABLE_SHARE` | No | Share that must have read access |
| `SMB_TEST_WRITABLE_SHARE` | No | Share that must have write access |
| `SMB_TEST_NT_HASH` | No | `LM:NT` hex for pass-the-hash tests |
| `SMB_TEST_NONEXISTENT_HOST` | No | IP that should time out (default: `10.255.255.1`) |

---

## Architecture

```
src/
├── main.rs              CLI entry point (clap)
├── error.rs             SmbError enum
├── credentials.rs       AuthMethod + Credentials + validation
├── share.rs             Share, ShareType, AccessLevel
├── scanner.rs           Scanner<B: SmbBackend> — orchestrates scans, enforces timeouts
├── backend/
│   ├── mod.rs           SmbBackend trait (mockable for unit tests)
│   ├── libsmb.rs        Linux/macOS backend (pavao / libsmbclient)
│   ├── windows.rs       Windows backend (Win32 NetShareEnum + WNet)
│   └── platform.rs      PlatformBackend type alias
└── output/
    ├── mod.rs           OutputFormat enum
    ├── table.rs         tabled
    ├── json.rs          serde_json
    └── csv.rs           csv crate
```

The `SmbBackend` trait is the central abstraction. All scanner logic is tested against a `MockSmbBackend` (generated by `mockall`) — no network required for unit tests.

---

## License

MIT
