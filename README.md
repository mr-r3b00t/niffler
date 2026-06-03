# Invoke-ShareDiscoveryAudit

A pure **PowerShell 5.1** (UTF-8, no external modules) script for **data‑access discovery audits**. It enumerates Active Directory computers, discovers their SMB file shares, walks folder/file metadata, and flags potentially sensitive files by name/extension — enriching each finding with **file owner and ACL exposure** so you can understand *who can reach the data*.

It runs with the rights of an ordinary domain user from a domain‑joined workstation, or with **alternate credentials** against a domain/host you are not joined to.

> ⚠️ **Authorized use only.** This tool is for sanctioned data‑governance / security audits. Share enumeration and file access are logged by domain controllers and file servers and can resemble reconnaissance. Run only with written authorization and coordinate with your SOC before scanning broadly.

---

## Highlights

- **No RSAT / ActiveDirectory module** — AD enumeration uses LDAP via `System.DirectoryServices.DirectorySearcher`.
- **Sees what the user sees** — share enumeration uses the SRVSVC `NetShareEnum` API (the same call `net view \\host` makes).
- **Read‑only** — captures file *names and metadata* only. File *content* is never read unless you explicitly pass `-InspectConfigContent`.
- **Alternate credentials** — authenticates LDAP and SMB (`WNetAddConnection2` to `IPC$`) as any user.
- **Risk context** — every flagged file gets its **owner**, full **ACL**, and a **broad‑access flag** (Everyone / Authenticated Users / Domain Users / Domain Computers / BUILTIN\Users).
- **Parallel** host scanning via a runspace pool, with per‑host timeouts and bounded recursion depth.
- **DNS fallback** — resolves AD hostnames via the domain DNS server when the auditing host isn't using the domain's DNS.
- **UTF‑8 (no BOM)** output: CSV + JSON + a running log.

---

## Requirements

- Windows PowerShell **5.1**
- Network reachability to targets on **TCP/445** (ICMP optional)
- Credentials with at least read access to the shares of interest

---

## Quick start

```powershell
# Domain-joined, integrated auth, servers only
.\Invoke-ShareDiscoveryAudit.ps1 -TargetType Servers -Verbose

# Authenticated against a specific domain/DC, all computer types
.\Invoke-ShareDiscoveryAudit.ps1 -Domain demo.local -Server 192.168.119.144 `
    -Username 'auditor@demo.local' -Password 'P@ssw0rd' -TargetType All

# Single host / IP, with credentials
.\Invoke-ShareDiscoveryAudit.ps1 -Target 192.168.119.144 `
    -Username 'administrator' -Password 'P@ssw0rd' -IncludeAdminShares
```

---

## Parameters

### Targeting
| Parameter | Description |
|---|---|
| `-Target <host[]>` | Scan these host(s)/IP(s) **directly**, skipping AD discovery. |
| `-Domain <dns>` | DNS domain name to enumerate via LDAP (e.g. `corp.example.com`). |
| `-Server <host/ip>` | Specific DC / LDAP server to bind against. Also used as the DNS fallback server. |
| `-DnsServer <host/ip>` | Resolve AD hostnames via this DNS server (defaults to `-Server`). Needed when the auditing host doesn't use the domain's DNS. |
| `-SearchBase <DN>` | Scope the LDAP search to a distinguished name (e.g. `OU=Servers,DC=corp,DC=example,DC=com`). |
| `-TargetType <All\|Servers\|Workstations>` | Which AD computer class to enumerate. Default **All**. `Servers` = OS contains "Server"; `Workstations` = has an OS set that is not a server OS. |
| `-ComputerListPath <file>` | Read a newline‑delimited host list instead of querying AD (`#` comments allowed). |

### Authentication
| Parameter | Description |
|---|---|
| `-Credential <pscredential>` | Alternate credentials (preferred). |
| `-Username <user>` | Convenience: build a credential from user/pass. Use `user@domain` or `DOMAIN\user` for domain accounts. |
| `-Password <pass>` | Convenience (lab use; prefer `-Credential`). If omitted with `-Username`, you'll be prompted. |

### Scope / behavior
| Parameter | Default | Description |
|---|---|---|
| `-IncludeAdminShares` | off | Test admin/IPC shares (`C$`, `ADMIN$`, …). Only useful with admin credentials; also lets you reach SYSVOL/NETLOGON content via `C$`. |
| `-MaxDepth <n>` | `4` | Max directory recursion depth per share. `-1` = unlimited. |
| `-HostTimeoutSeconds <n>` | `120` | Per‑host wall‑clock budget for the file walk. |
| `-ThrottleLimit <n>` | `8` | Max concurrent host scans. |
| `-InspectConfigContent` | off | **Reads content** of *name‑matched* config files and adds a keyword hint. Only enable if your authorization covers reading file contents. |
| `-ScanContent` | off | **Deep content scan** (reads bytes): runs secret/PII rules over eligible text files regardless of filename. See *Content detection* below. Reads content — authorization required. |
| `-ContentRuleSet <Minimal\|Standard\|Aggressive>` | `Standard` | Which `-ScanContent` rules run, trading false positives for coverage. |
| `-MaxInspectBytes <n>` | `262144` | Byte cap per file for `-InspectConfigContent` / `-ScanContent`. |
| `-ExcludeName <pat[]>` | *(see below)* | Extra filename wildcards to skip entirely, added to the built-in noise list. |
| `-OutputDirectory <path>` | `.\ShareAudit_<timestamp>` | Where results are written. |

---

## Output

A timestamped folder (`ShareAudit_yyyyMMdd_HHmmss`) containing:

| File | Contents |
|---|---|
| `00_summary.json` | Run summary: counts, severity/category breakdown, **BroadlyExposed** count. |
| `01_targets.csv` | Targets enumerated (name, OS). |
| `02_shares.csv` | Discovered disk shares per host (`ComputerName` + `IPAddress`, UNC path). |
| `03_file_inventory.csv` | Every file walked, with metadata + **Owner** (`ComputerName` + `IPAddress`). |
| `04_sensitive_findings.csv` / `.json` | Flagged files with `ComputerName` + `IPAddress`, **Owner, BroadAccess, full ACL**, category, severity, `MatchType` (Name/Content), pattern, and a redacted `ContentHint`. |

> `ComputerName` is the AD/DNS hostname; `IPAddress` is the resolved address actually scanned. When auditing from a host without the domain's DNS, names are resolved via the DC and the UNC paths use the IP — but the friendly name is preserved in its own column.
| `05_access_errors.csv` | Paths that couldn't be read (access denied, timeouts). |
| `audit.log` | Timestamped run log (operator, auth mode, resolutions, findings). |

### Example finding
```
[High] \\192.168.119.145\share\secrets\passwords.txt.txt
      Owner       : BUILTIN\Administrators
      BroadAccess : Everyone
      ACL         : Allow:...-500=FullControl | Allow:BUILTIN\Administrators=FullControl |
                    Allow:Everyone=ReadAndExecute, Synchronize | Allow:NT AUTHORITY\SYSTEM=FullControl
```

---

## Sensitive‑file categories

Matching is **case‑insensitive wildcard** on the file name/extension. Categories and example patterns:

| Category | Severity | Examples |
|---|---|---|
| Credential‑Store | High | `*password*`, `*.kdbx`, `*secret*`, `unattend.xml`, `*.vnc` |
| Keys‑Certificates | High | `id_rsa`, `*.pem`, `*.pfx`, `*.ppk`, `*.jks`, `*.ovpn`, `.npmrc` |
| Cloud‑Secrets | High | `*.env`, `credentials`, `*.tfvars`, `*serviceaccount*.json` |
| Config‑WithSecrets | Medium | `web.config`, `appsettings*.json`, `*.ini`, `wp-config.php` |
| Script‑WithSecrets | Medium | `*.ps1`, `*.bat`, `*.vbs`, `*.sh`, `login.*` |
| Database | High | `*.bak`, `*.mdf`, `*.sql`, `*.bacpac`, `*.sqlite`, `*.mdb` |
| Email‑Archive | Medium | `*.pst`, `*.ost`, `*.msg`, `*.eml` |
| PII‑HR‑Finance | Medium | `*ssn*`, `*payroll*`, `*salary*`, `*invoice*`, `*w2*`, `*hipaa*` |
| Classified‑Marking | Medium | `*confidential*`, `*restricted*`, `*nda*`, `*sensitive*` |
| VPN‑Profile | High | `*.ovpn`, `wg*.conf`/`*wireguard*`, `ipsec.conf`/`ipsec.secrets`, `*.pcf` (Cisco), `*.pbk`/`rasphone.pbk` (RRAS), `*.tblk`, `*.mobileconfig`, `*anyconnect*`, `*globalprotect*`, `*forticlient*` |
| Remote‑Access | Low | `*.rdp`, `*.rdg`, `*.ica`, `*.sdtid` |

> The categories above are matched by **filename**. To catch renamed / misspelled / plainly‑named files, add `-ScanContent` (below).

### Exclusions & ambiguous extensions

- **Noise files** are skipped entirely (no inventory, no findings): `Thumbs.db`, `ehthumbs.db`, `desktop.ini`, `.DS_Store`. Add more with `-ExcludeName '*.tmp','~$*'`.
- **`.key` is ambiguous** — a TLS/SSH private key *or* an Apple **Keynote/iWork** document. Since real keys are tiny text files and Keynote files are ZIP packages (almost always > 100 KB), a `.key` file **over ~100 KB is treated as a document and not flagged**. This is decided on **file size only — no content is read** — so the read‑only guarantee holds. Small `.key` files are still flagged as potential private keys (and, with `-ScanContent`, confirmed by the `PrivateKeyBlock` content rule).

---

## Content detection (`-ScanContent`)

With `-ScanContent`, the tool also reads the *bytes* of eligible text files and matches secret/PII rules **regardless of filename** — so a WireGuard config named `home.conf`, a renamed `sallary.txt`, or a password buried in a `.config` are all caught.

- **Eligibility:** an extension allowlist (`.conf`, `.config`, `.ini`, `.env`, `.xml`, `.json`, `.yml`, `.ps1`, `.txt`, `.pem`, `.ovpn`, `.pcf`, `.pbk`, …) plus extensionless files, capped at `-MaxInspectBytes` (default 256 KB), with a **null‑byte probe** that skips binaries. Archives and Office formats are excluded.
- **Rules:** private‑key blocks (`-----BEGIN … PRIVATE KEY-----`, PuTTY), **WireGuard** keys, **IPsec** PSKs, **Cisco** type‑7, connection‑string passwords, generic `password=`/`api_key=` assignments, **AWS/Azure/Slack/GitHub/JWT** tokens, **US SSNs**, and **credit‑card numbers validated with the Luhn checksum** (to cut false positives).
- **Redaction:** matched values are **masked** before being written (e.g. `pas********!!`, `411***11`) so the report never stores the raw secret.
- **Output:** content findings appear in `04_sensitive_findings.csv` with `MatchType = Content`, `Pattern = content:<RuleName>`, and a redacted sample in `ContentHint` (`<count>x <masked>`). They get the same Owner / ACL / BroadAccess enrichment as name findings.

### Rule sets (`-ContentRuleSet`)

Each rule is tiered by confidence; the switch picks how aggressively to match:

| Set | Rules | What it adds | Use when |
|---|---|---|---|
| `Minimal` | 8 + Luhn cards | High‑confidence only: private keys, AWS/Azure/Slack/GitHub tokens, WireGuard keys, Luhn‑valid cards | Large/noisy shares; you only want near‑certain hits |
| `Standard` *(default)* | 15 + Luhn cards | + VPN PSKs, Cisco type‑7, connection‑string & API‑key assignments, JWTs, **keyword‑anchored SSNs** | Most audits |
| `Aggressive` | 17 + Luhn cards | + generic `password=` assignments and **bare `NNN‑NN‑NNNN` SSNs** | Deep sweeps where misses cost more than false positives |

The Luhn‑validated credit‑card check always runs with `-ScanContent`. SSNs in `Standard` require an adjacent `SSN`/`social security` keyword (so `order 123‑45‑6789 ref` is ignored); `Aggressive` flags any structurally‑valid SSN.

---

## How it works

1. **Targets** — from `-Target`, `-ComputerListPath`, or an LDAP query (filtered by `-TargetType`, optionally credentialed against `-Server`/`-Domain`).
2. **Resolve** — each AD hostname is resolved; if the local resolver fails, it falls back to the domain DNS server and scans by IP.
3. **Reach + authenticate** — ICMP or TCP/445 liveness, then (if credentials given) an authenticated `IPC$` session via `WNetAddConnection2`.
4. **Enumerate shares** — `NetShareEnum` (disk shares; admin/special shares skipped unless `-IncludeAdminShares`).
5. **Walk** — breadth‑first metadata walk per share (depth/time bounded), parallelized across hosts.
6. **Flag + enrich** — name/extension match → capture owner, ACL, and broad‑access exposure.
7. **Write** — CSV/JSON/log; authenticated SMB sessions are torn down on exit.

---

## Limitations & notes

- **UNC Hardening (MS15‑011/014).** `NETLOGON` and `SYSVOL` require Kerberos mutual authentication. When authenticating with **NTLM to a local account** or **by IP**, those two shares return *access denied* even with admin rights. To read them:
  1. Run from a domain‑joined machine with a **domain** account (Kerberos), **or**
  2. With admin creds, add `-IncludeAdminShares` and read via `C$`: `\\host\C$\Windows\SYSVOL\sysvol\<domain>\`.
- **DNS.** Auditing from a non‑domain‑joined host requires `-DnsServer`/`-Server` so AD FQDNs resolve (handled automatically when `-Server` is supplied).
- **Name‑based matching by default** — misspelled/renamed files are missed unless you add `-ScanContent` (content rules + Luhn‑validated cards/SSNs). Content scanning is size‑capped (default 256 KB), so secrets beyond that offset in very large files aren't reached.
- **One credential per server per session** — Windows allows a single credential set per remote host; the script reuses one authenticated session per host.
- **`-TargetType`** applies to AD enumeration only; it's ignored for `-Target` / `-ComputerListPath` (OS class is unknown without an AD lookup).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `unreachable (no ICMP, 445 closed)` | Host down or firewalled; or AD FQDN not resolvable — supply `-Server`/`-DnsServer`. |
| `IPC$ auth failed (rc=1326)` | Bad credentials. Use `user@domain` or `DOMAIN\user` for domain accounts. |
| `IPC$ auth failed (rc=67)` | Bad network name / SMB not reachable. |
| NETLOGON/SYSVOL `access denied` | UNC Hardening — see *Limitations*. |
| Empty `Owner`/`Access` on findings | Ensure you're on the current script version (older builds had an array‑unwrap bug). |

---

## Example end‑to‑end (lab)

```powershell
.\Invoke-ShareDiscoveryAudit.ps1 -Domain demo.local -Server 192.168.119.144 `
    -Username 'james.bond@demo.local' -Password '<password>' `
    -TargetType All -MaxDepth 5
```
```
SensitiveFindings : 3
BroadlyExposed    : 3
BySeverity        : High=2 Medium=1
ByCategory        : Credential-Store=2 Config-WithSecrets=1
```
