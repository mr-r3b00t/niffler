#Requires -Version 5.1
<#
.SYNOPSIS
    Data Access Discovery Audit - enumerates AD computers/servers, discovers SMB
    file shares, walks folder/file metadata, and flags potentially sensitive files
    by name/extension pattern.

.DESCRIPTION
    Defensive / governance tooling for an AUTHORIZED data-access discovery audit.

    Runs with the rights of a normal domain user from a domain-joined workstation:
      * AD enumeration uses LDAP via System.DirectoryServices.DirectorySearcher
        (no RSAT / ActiveDirectory module required).
      * Share enumeration uses the SRVSVC NetShareEnum API (the same call that
        `net view \\host` makes) so it sees exactly the shares the user can see.
      * File walking uses standard UNC access - it only reads NAMES and METADATA,
        never file content, unless -InspectConfigContent or -ScanContent is set.

    The script is strictly READ-ONLY. It creates/modifies nothing on remote hosts.

.PARAMETER SearchBase
    Optional LDAP distinguished name to scope the computer search
    (e.g. "OU=Servers,DC=corp,DC=example,DC=com"). Defaults to the current domain.

.PARAMETER TargetType
    Which AD computer class to enumerate: All (default), Servers (operatingSystem
    contains "Server"), or Workstations (has an OS set that is not a server OS).

.PARAMETER ComputerListPath
    Skip AD enumeration and read a newline-delimited host list from this file.

.PARAMETER OutputDirectory
    Where result CSV/JSON/log files are written. Default: .\ShareAudit_<timestamp>.

.PARAMETER MaxDepth
    Maximum directory recursion depth per share. Default 4. Use -1 for unlimited.

.PARAMETER HostTimeoutSeconds
    Per-host wall-clock budget for the file walk. Default 120.

.PARAMETER ThrottleLimit
    Max concurrent host scans (runspace pool). Default 8.

.PARAMETER IncludeAdminShares
    Test admin/IPC shares (C$, ADMIN$, ...) too. OFF by default ("do not test"):
    a normal user cannot read them and probing only generates noise / Access
    Denied events. Enable it when scanning with administrative credentials - it
    also lets you reach SYSVOL/NETLOGON content via C$ (see NOTES on UNC Hardening).

.PARAMETER InspectConfigContent
    Opt-in: for matched config files (web.config, *.config, *.env, *.ini) read the
    file and flag lines containing connectionString/password/secret keywords.
    This reads file CONTENT - only enable when your audit authorization covers it.

.PARAMETER ScanContent
    Opt-in deep content scan. Reads the bytes of eligible text files (extension-
    gated, size-capped, binary-guarded) and matches secret/PII rules regardless of
    filename - private keys, WireGuard/IPsec/Cisco VPN material, cloud tokens (AWS/
    Azure/Slack/GitHub/JWT), connection-string passwords, SSNs, and Luhn-valid card
    numbers. Catches renamed/misspelled/plainly-named files that name matching
    misses. Evidence is REDACTED in output. Reads file CONTENT - authorization
    required.

.PARAMETER ContentRuleSet
    Which -ScanContent rules to run (trades false positives for coverage):
      Minimal    - high-confidence only (private keys, cloud tokens, WireGuard keys,
                   Luhn-valid cards). Lowest noise.
      Standard   - Minimal + VPN PSKs, connection-string/API-key assignments, JWTs,
                   keyword-anchored SSNs. Default.
      Aggressive - Standard + broad rules: generic password= and bare NNN-NN-NNNN
                   SSNs. Highest coverage, more false positives.

.PARAMETER MaxInspectBytes
    Cap on bytes read per file for -InspectConfigContent and -ScanContent. Default 262144.

.EXAMPLE
    .\Invoke-ShareDiscoveryAudit.ps1 -TargetType Servers -Verbose

.EXAMPLE
    .\Invoke-ShareDiscoveryAudit.ps1 -ComputerListPath .\targets.txt -MaxDepth 6 `
        -ScanContent

.NOTES
    Authorization: run ONLY with written authorization for the target environment.
    Activity (share enum, file access) is logged by domain controllers and file
    servers; coordinate with the SOC before running broadly.

    UNC Hardening (MS15-011/MS15-014): the NETLOGON and SYSVOL shares require
    Kerberos mutual authentication + signing. When you authenticate with NTLM to
    a LOCAL account (e.g. -Username administrator) from a non-domain-joined host,
    or address the server by IP, those two shares return "Network access is
    denied" / "does not exist" even with admin rights. Two ways to read their
    content anyway:
      1. Run from a domain-joined machine with a DOMAIN account (Kerberos), OR
      2. With admin creds, add -IncludeAdminShares and read the data via C$:
         \\host\C$\Windows\SYSVOL\sysvol\<domain>\  (logon scripts, GPP, etc.)
    Other (non-hardened) shares authenticate fine over NTLM by IP.
#>
[CmdletBinding()]
param(
    # -- Targeting -----------------------------------------------------------
    [string[]] $Target,            # scan these host(s)/IP(s) directly, skip AD discovery
    [string]   $Domain,            # DNS domain name to enumerate via LDAP (e.g. corp.example.com)
    [string]   $Server,            # specific DC / LDAP server (host or IP) to bind against
    [string]   $DnsServer,         # resolve AD hostnames via this DNS server (defaults to -Server);
                                    # needed when auditing from a host not using the domain's DNS
    [string]   $SearchBase,
    [ValidateSet('All', 'Servers', 'Workstations')]
    [string]   $TargetType = 'All',   # which AD computer class to enumerate
    [string]   $ComputerListPath,

    # -- Authentication ------------------------------------------------------
    [pscredential] $Credential,    # alternate credentials (preferred)
    [string]   $Username,          # convenience: build a credential from plain user/pass
    [string]   $Password,          # convenience: lab use only (prefer -Credential)

    # -- Output / scope ------------------------------------------------------
    [string]   $OutputDirectory,
    [int]      $MaxDepth = 4,
    [int]      $HostTimeoutSeconds = 120,
    [ValidateRange(1, 64)]
    [int]      $ThrottleLimit = 8,
    [switch]   $IncludeAdminShares,
    [switch]   $InspectConfigContent,
    [switch]   $ScanContent,        # deep content scan: read eligible text files and match
                                    # secret/PII rules regardless of filename (reads CONTENT)
    [ValidateSet('Minimal', 'Standard', 'Aggressive')]
    [string]   $ContentRuleSet = 'Standard',  # which -ScanContent rules to run (FP vs coverage)
    [int]      $MaxInspectBytes = 262144
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------- #
# UTF-8 (no BOM) writer - keeps output "native" UTF8 across PS5 / external tools
# --------------------------------------------------------------------------- #
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8File {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

# --------------------------------------------------------------------------- #
# Credential assembly - accept -Credential, or build one from -Username/-Password
# --------------------------------------------------------------------------- #
if (-not $Credential -and $Username) {
    if ($Password) {
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    } else {
        $secure = (Get-Credential -UserName $Username -Message 'Enter password').Password
    }
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $secure)
}
$script:UseAltCreds = [bool]$Credential

# --------------------------------------------------------------------------- #
# Output location + logging
# --------------------------------------------------------------------------- #
if (-not $OutputDirectory) {
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $OutputDirectory = Join-Path (Get-Location) "ShareAudit_$stamp"
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$script:LogPath = Join-Path $OutputDirectory 'audit.log'

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'FIND')]
        [string]$Level = 'INFO'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message
    # append as UTF-8
    $sw = New-Object System.IO.StreamWriter($script:LogPath, $true, $script:Utf8NoBom)
    try { $sw.WriteLine($line) } finally { $sw.Dispose() }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'FIND'  { Write-Host $line -ForegroundColor Cyan }
        default { Write-Verbose $line }
    }
}

# --------------------------------------------------------------------------- #
# Sensitive-file pattern catalogue
#   Category -> @{ Names = wildcard filename patterns; Ext = extensions }
#   Patterns are case-insensitive wildcard (-like) matches against the file name.
# --------------------------------------------------------------------------- #
$script:Patterns = @(
    [pscustomobject]@{ Category = 'Credential-Store'; Severity = 'High'
        Names = @('*password*', '*passwd*', '*pwd*', '*credential*', '*creds*',
                  '*secret*', '*apikey*', '*api_key*', '*.kdbx', '*.kdb',
                  '*keepass*', '*.psafe3', '*login*', 'unattend.xml',
                  'autounattend.xml', 'sysprep.inf', 'vnc.ini', '*.vnc') }
    [pscustomobject]@{ Category = 'Keys-Certificates'; Severity = 'High'
        Names = @('id_rsa', 'id_rsa.*', 'id_dsa', 'id_ecdsa', 'id_ed25519',
                  '*.pem', '*.ppk', '*.pfx', '*.p12', '*.key', '*.jks',
                  '*.keystore', '.npmrc', '.dockercfg',
                  'credentials', '*.pgpass') }
    [pscustomobject]@{ Category = 'Cloud-Secrets'; Severity = 'High'
        Names = @('*.env', '.env*', 'credentials', '*aws*credential*',
                  '*azure*cred*', '*.tfvars', 'terraform.tfstate',
                  'serviceaccount*.json', 'client_secret*.json') }
    [pscustomobject]@{ Category = 'Config-WithSecrets'; Severity = 'Medium'
        Names = @('web.config', 'app.config', '*.config', 'appsettings*.json',
                  '*.ini', 'php.ini', 'wp-config.php', 'settings.py',
                  'context.xml', 'application*.yml', 'application*.yaml',
                  'datasources.xml', 'jboss-*.xml') }
    [pscustomobject]@{ Category = 'Script-WithSecrets'; Severity = 'Medium'
        Names = @('*.ps1', '*.psm1', '*.bat', '*.cmd', '*.vbs', '*.sh',
                  '*.py', '*.pl', 'login.*', 'logon.*', 'mapdrive*.*') }
    [pscustomobject]@{ Category = 'Database'; Severity = 'High'
        Names = @('*.bak', '*.mdf', '*.ldf', '*.sql', '*.bacpac', '*.dacpac',
                  '*.sqlite', '*.sqlite3', '*.db', '*.mdb', '*.accdb',
                  '*backup*.zip', '*dump*.sql') }
    [pscustomobject]@{ Category = 'Email-Archive'; Severity = 'Medium'
        Names = @('*.pst', '*.ost', '*.msg', '*.eml', '*.mbox') }
    [pscustomobject]@{ Category = 'PII-HR-Finance'; Severity = 'Medium'
        Names = @('*ssn*', '*social*security*', '*passport*', '*payroll*',
                  '*salary*', '*salaries*', '*invoice*', '*bank*detail*',
                  '*nationalid*', '*tax*id*', '*w2*', '*1099*', '*pii*',
                  '*gdpr*', '*pci*', '*hipaa*', '*medical*', '*employee*record*') }
    [pscustomobject]@{ Category = 'Classified-Marking'; Severity = 'Medium'
        Names = @('*confidential*', '*restricted*', '*proprietary*',
                  '*internal*only*', '*do*not*distribute*', '*nda*',
                  '*sensitive*', '*private*') }
    [pscustomobject]@{ Category = 'VPN-Profile'; Severity = 'High'
        # VPN configs commonly embed credentials / PSKs / private keys / obfuscated
        # passwords and define routes into the network.
        Names = @('*.ovpn',                                   # OpenVPN
                  'wg*.conf', '*wireguard*', '*.sswan',       # WireGuard / strongSwan
                  'ipsec.conf', 'ipsec.secrets', 'racoon.conf', # IPsec (PSKs!)
                  '*.pcf',                                     # Cisco VPN Client (group pwd)
                  '*.pbk', 'rasphone.pbk',                     # Windows RAS / RRAS phonebook
                  '*.tblk',                                    # Tunnelblick bundle
                  '*.mobileconfig', '*.nmconnection',          # Apple / NetworkManager profiles
                  '*anyconnect*', '*globalprotect*', '*forticlient*', # vendor clients
                  '*.vpnconfig', '*vpn*profile*', '*vpn*config*', '*openvpn*') }
    [pscustomobject]@{ Category = 'Remote-Access'; Severity = 'Low'
        Names = @('*.rdp', '*.rdg', '*.ica', '*.sdtid') }
)

# Keyword regex used only when -InspectConfigContent is supplied
$script:SecretContentRegex = '(?i)(connectionstring|password\s*=|passwd|pwd\s*=|secret|api[_-]?key|client[_-]?secret|access[_-]?key|private[_-]?key|bearer\s)'

# --------------------------------------------------------------------------- #
# Content-scan rules (used only with -ScanContent). Each rule matches file
# CONTENT regardless of name. Evidence is redacted before it is written out.
# Single-quoted regex strings keep PowerShell from interpreting $ and ` .
#
# Tier controls which rules run via -ContentRuleSet:
#   Minimal    = high-confidence, low false-positive (specific token/key formats)
#   Standard   = Minimal + medium-confidence rules (default)
#   Aggressive = Standard + broad/noisy rules (generic password=, bare SSNs)
# --------------------------------------------------------------------------- #
$script:ContentRules = @(
    [pscustomobject]@{ Name = 'PrivateKeyBlock';   Tier = 'Minimal';    Category = 'Keys-Certificates';  Severity = 'High'
        Regex = '-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----' }
    [pscustomobject]@{ Name = 'PuttyKeyFile';      Tier = 'Minimal';    Category = 'Keys-Certificates';  Severity = 'High'
        Regex = '(?i)PuTTY-User-Key-File' }
    [pscustomobject]@{ Name = 'WireGuardKey';      Tier = 'Minimal';    Category = 'VPN-Profile';        Severity = 'High'
        Regex = '(?im)^\s*(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{42,}=' }
    [pscustomobject]@{ Name = 'AwsAccessKeyId';    Tier = 'Minimal';    Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = '\bAKIA[0-9A-Z]{16}\b' }
    [pscustomobject]@{ Name = 'AwsSecretKey';      Tier = 'Minimal';    Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = '(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}' }
    [pscustomobject]@{ Name = 'AzureStorageKey';   Tier = 'Minimal';    Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = '(?i)AccountKey=[A-Za-z0-9+/]{86}==' }
    [pscustomobject]@{ Name = 'SlackToken';        Tier = 'Minimal';    Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = 'xox[baprs]-[A-Za-z0-9-]{10,}' }
    [pscustomobject]@{ Name = 'GitHubToken';       Tier = 'Minimal';    Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = '\bgh[pousr]_[A-Za-z0-9]{36,}\b' }
    [pscustomobject]@{ Name = 'WireGuardPeer';     Tier = 'Standard';   Category = 'VPN-Profile';        Severity = 'Medium'
        Regex = '(?im)^\s*\[(?:Interface|Peer)\]\s*$' }
    [pscustomobject]@{ Name = 'IPsecPSK';          Tier = 'Standard';   Category = 'VPN-Profile';        Severity = 'High'
        Regex = '(?i)\bPSK\s+\S{3,}' }
    [pscustomobject]@{ Name = 'CiscoType7';        Tier = 'Standard';   Category = 'VPN-Profile';        Severity = 'Medium'
        Regex = '(?i)\b(?:password|secret)\s+7\s+[0-9A-Fa-f]{4,}' }
    [pscustomobject]@{ Name = 'ConnStringPassword';Tier = 'Standard';   Category = 'Config-WithSecrets'; Severity = 'High'
        Regex = '(?i)(?:data source|server|initial catalog)\s*=[^\r\n]{0,80}?(?:password|pwd)\s*=\s*\S{2,}' }
    [pscustomobject]@{ Name = 'ApiKeyAssignment';  Tier = 'Standard';   Category = 'Cloud-Secrets';      Severity = 'High'
        Regex = '(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*\S{12,}' }
    [pscustomobject]@{ Name = 'JwtToken';          Tier = 'Standard';   Category = 'Cloud-Secrets';      Severity = 'Medium'
        Regex = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}' }
    [pscustomobject]@{ Name = 'USSocialSecurity';  Tier = 'Standard';   Category = 'PII-HR-Finance';     Severity = 'Medium'
        # requires an SSN/social keyword next to the number -> far fewer false positives
        Regex = '(?i)(?:ssn|social[\s._-]*security|soc[\s._-]*sec)\b[^0-9\r\n]{0,15}\d{3}-\d{2}-\d{4}\b' }
    [pscustomobject]@{ Name = 'GenericPassword';   Tier = 'Aggressive'; Category = 'Credential-Store';   Severity = 'Medium'
        Regex = '(?im)\b(?:password|passwd|pwd)\b\s*[:=]\s*\S{4,}' }
    [pscustomobject]@{ Name = 'USSocialSecurityLoose'; Tier = 'Aggressive'; Category = 'PII-HR-Finance'; Severity = 'Medium'
        # any NNN-NN-NNNN with no keyword context (noisy: matches some IDs/phone fragments)
        Regex = '\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b' }
)
# credit-card detection is handled separately (regex candidates + Luhn validation),
# and always runs from the Minimal tier upward because Luhn keeps it low-false-positive.

# Extensions eligible for content scanning (plus extensionless files). Binary and
# archive/office types are intentionally excluded; a null-byte probe guards the rest.
$script:ContentExt = @('.txt','.text','.conf','.config','.cnf','.ini','.env','.properties',
    '.xml','.json','.yml','.yaml','.ps1','.psm1','.psd1','.bat','.cmd','.sh','.bash','.py',
    '.pl','.php','.rb','.js','.ts','.sql','.md','.markdown','.csv','.tsv','.log','.reg','.tf',
    '.tfvars','.secrets','.pcf','.ovpn','.pbk','.nmconnection','.mobileconfig','.pem','.key',
    '.ppk','.crt','.cer','.netrc','.htpasswd','.gitconfig')

function Get-FileFindings {
    <# returns the matching pattern objects for a given file name (may be 0..n) #>
    param([string]$Name)
    $hits = @()
    foreach ($p in $script:Patterns) {
        foreach ($pat in $p.Names) {
            if ($Name -like $pat) {
                $hits += [pscustomobject]@{
                    Category = $p.Category; Severity = $p.Severity; Pattern = $pat
                }
                break  # one hit per category is enough
            }
        }
    }
    return $hits
}

# --------------------------------------------------------------------------- #
# 1. AD computer enumeration via LDAP (no ActiveDirectory module needed)
# --------------------------------------------------------------------------- #
# null-safe read of a single SearchResult property (avoids StrictMode null-index)
function Get-SrProp {
    param($Props, $Name)
    try {
        $c = $Props[$Name]
        if ($c -and $c.Count -gt 0) { return [string]$c[0] }
    } catch { }
    return ''
}

function Get-DomainComputer {
    param(
        [string]$SearchBase,
        [ValidateSet('All', 'Servers', 'Workstations')]
        [string]$TargetType = 'All',
        [string]$Domain, [string]$Server, [pscredential]$Credential
    )

    Write-AuditLog "Enumerating AD computers via LDAP (TargetType=$TargetType)..."

    # Build the LDAP prefix: a specific DC/server wins, else the domain DNS name,
    # else the workstation's own domain (default).  Server/Domain let you point at
    # a target environment you are not joined to, using -Credential.
    $user = if ($Credential) { $Credential.UserName } else { $null }
    $pass = if ($Credential) { $Credential.GetNetworkCredential().Password } else { $null }
    $prefix = 'LDAP://'
    if     ($Server) { $prefix = "LDAP://$Server/" }
    elseif ($Domain) { $prefix = "LDAP://$Domain/" }

    if (-not $SearchBase -and -not $Server -and -not $Domain -and -not $Credential) {
        # Pure integrated auth against the current domain: a default DirectorySearcher
        # binds to the current domain's defaultNamingContext as the current user, so we
        # never have to read RootDSE (whose .Properties indexer trips StrictMode).
        $search = New-Object System.DirectoryServices.DirectorySearcher
    } else {
        if ($SearchBase) {
            $rootPath = "$prefix$SearchBase"
        } else {
            # discover the default naming context from RootDSE (with creds if supplied);
            # InvokeGet returns the value directly and avoids the .Properties null-index.
            if ($Credential) { $rootDse = New-Object System.DirectoryServices.DirectoryEntry("${prefix}RootDSE", $user, $pass) }
            else             { $rootDse = New-Object System.DirectoryServices.DirectoryEntry("${prefix}RootDSE") }
            $dn = $null
            try { $dn = [string]$rootDse.InvokeGet('defaultNamingContext') } catch { }
            if (-not $dn) {
                throw "Could not read the domain naming context from '${prefix}RootDSE'. Ensure a domain controller is reachable, or pass -SearchBase / -Server / -Credential."
            }
            $rootPath = "$prefix$dn"
        }
        if ($Credential) { $entry = New-Object System.DirectoryServices.DirectoryEntry($rootPath, $user, $pass) }
        else             { $entry = New-Object System.DirectoryServices.DirectoryEntry($rootPath) }
        $search = New-Object System.DirectoryServices.DirectorySearcher($entry)
    }

    # enabled computer accounts only (bit 2 = ACCOUNTDISABLE)
    $enabled = '(!userAccountControl:1.2.840.113556.1.4.803:=2)'
    switch ($TargetType) {
        # servers: operatingSystem contains "Server"
        'Servers'      { $osClause = '(operatingSystem=*Server*)' }
        # workstations: has an OS set, but it is NOT a server OS (excludes blank-OS objects)
        'Workstations' { $osClause = '(&(operatingSystem=*)(!(operatingSystem=*Server*)))' }
        # all computer objects
        default        { $osClause = '' }
    }
    $search.Filter      = "(&(objectCategory=computer)$osClause$enabled)"
    $search.PageSize    = 1000
    $search.SizeLimit   = 0
    foreach ($a in 'dNSHostName', 'name', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp') {
        $null = $search.PropertiesToLoad.Add($a)
    }

    $results = @()
    foreach ($r in $search.FindAll()) {
        $props    = $r.Properties
        $hostName = Get-SrProp $props 'dnshostname'
        if (-not $hostName) { $hostName = Get-SrProp $props 'name' }
        if (-not $hostName) { continue }
        $results += [pscustomobject]@{
            HostName  = $hostName
            Name      = Get-SrProp $props 'name'
            OS        = Get-SrProp $props 'operatingsystem'
            OSVersion = Get-SrProp $props 'operatingsystemversion'
        }
    }
    Write-AuditLog ("AD returned {0} computer object(s)." -f $results.Count)
    return $results
}

# --------------------------------------------------------------------------- #
# 2. Share enumeration via NetShareEnum (P/Invoke) - works as a normal user
# --------------------------------------------------------------------------- #
$netApiTypeDef = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ShareEnum
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
        public string shi1_netname;
        public uint   shi1_type;
        public string shi1_remark;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetShareEnum(
        string ServerName, int level, ref IntPtr bufPtr, uint prefmaxlen,
        ref int entriesread, ref int totalentries, ref int resume_handle);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr Buffer);

    private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
    private const int  NERR_Success = 0;

    public class ShareResult
    {
        public string Name;
        public uint   Type;
        public string Remark;
    }

    public static List<ShareResult> Enumerate(string server)
    {
        var list = new List<ShareResult>();
        IntPtr buffer = IntPtr.Zero;
        int entriesRead = 0, totalEntries = 0, resume = 0;

        int res = NetShareEnum(server, 1, ref buffer, MAX_PREFERRED_LENGTH,
                               ref entriesRead, ref totalEntries, ref resume);
        if (res == NERR_Success && entriesRead > 0)
        {
            int structSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            long ptr = buffer.ToInt64();
            for (int i = 0; i < entriesRead; i++)
            {
                var si = (SHARE_INFO_1)Marshal.PtrToStructure(
                    new IntPtr(ptr), typeof(SHARE_INFO_1));
                list.Add(new ShareResult {
                    Name = si.shi1_netname, Type = si.shi1_type, Remark = si.shi1_remark });
                ptr += structSize;
            }
        }
        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        if (res != NERR_Success)
            throw new System.ComponentModel.Win32Exception(res);
        return list;
    }
}
'@

if (-not ('ShareEnum' -as [type])) {
    Add-Type -TypeDefinition $netApiTypeDef -Language CSharp
}

# --------------------------------------------------------------------------- #
# Authenticated SMB session helper (WNetAddConnection2 / WNetCancelConnection2)
#   Establishing a session to \\host\IPC$ with explicit creds means every
#   subsequent \\host\* access (NetShareEnum + UNC reads, including from child
#   runspaces in this same logon session) is authenticated as that user.
#   Note: Windows allows only ONE credential set per remote server per session.
# --------------------------------------------------------------------------- #
$mprTypeDef = @'
using System;
using System.Runtime.InteropServices;

public static class SmbConnection
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int    dwScope;
        public int    dwType;
        public int    dwDisplayType;
        public int    dwUsage;
        public string lpLocalName;
        public string lpRemoteName;
        public string lpComment;
        public string lpProvider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(
        ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private const int RESOURCETYPE_DISK = 0x1;

    // returns Win32 error code (0 = success). 1219 = conflicting credentials already exist.
    public static int Connect(string remoteName, string username, string password)
    {
        var nr = new NETRESOURCE {
            dwType = RESOURCETYPE_DISK, lpRemoteName = remoteName };
        return WNetAddConnection2(ref nr, password, username, 0);
    }

    public static int Disconnect(string remoteName)
    {
        return WNetCancelConnection2(remoteName, 0, true);
    }
}
'@

if (-not ('SmbConnection' -as [type])) {
    Add-Type -TypeDefinition $mprTypeDef -Language CSharp
}

# track hosts we have an authenticated IPC$ session to, so we can tear down at exit
$script:ConnectedHosts = New-Object System.Collections.Generic.List[string]

function Connect-SmbHost {
    param([string]$ComputerName, [pscredential]$Credential)
    if (-not $Credential) { return $true }                # nothing to do; use ambient creds
    $remote = "\\$ComputerName\IPC$"
    $user   = $Credential.UserName
    $pass   = $Credential.GetNetworkCredential().Password
    $rc = [SmbConnection]::Connect($remote, $user, $pass)
    switch ($rc) {
        0    { $script:ConnectedHosts.Add($ComputerName); return $true }
        1219 {   # ERROR_SESSION_CREDENTIAL_CONFLICT - a session already exists; drop & retry
            [void][SmbConnection]::Disconnect($remote)
            $rc2 = [SmbConnection]::Connect($remote, $user, $pass)
            if ($rc2 -eq 0) { $script:ConnectedHosts.Add($ComputerName); return $true }
            Write-AuditLog "${ComputerName}: IPC`$ auth failed (rc=$rc2) after retry" 'WARN'; return $false
        }
        default {
            $msg = (New-Object System.ComponentModel.Win32Exception($rc)).Message
            Write-AuditLog "${ComputerName}: IPC`$ auth failed (rc=$rc - $msg)" 'WARN'; return $false
        }
    }
}

function Disconnect-AllSmbHosts {
    foreach ($h in $script:ConnectedHosts) {
        [void][SmbConnection]::Disconnect("\\$h\IPC$")
    }
    if ($script:ConnectedHosts.Count) {
        Write-AuditLog ("Closed {0} authenticated SMB session(s)." -f $script:ConnectedHosts.Count)
    }
    $script:ConnectedHosts.Clear()
}

function Get-HostShare {
    # ScanAddress = the address we actually connect to (may be an IP from DNS fallback);
    # HostName / IPAddress are carried through to the output as separate columns.
    param([string]$ScanAddress, [string]$HostName, [string]$IPAddress, [switch]$IncludeAdminShares)

    # STYPE constants: 0=DISK 1=PRINTQ 2=DEVICE 3=IPC; 0x80000000 = special/admin
    $STYPE_MASK    = 0x0FFFFFFF
    $STYPE_SPECIAL = 0x80000000
    $shares = @()
    try {
        $raw = [ShareEnum]::Enumerate($ScanAddress)
    } catch {
        throw "NetShareEnum failed: $($_.Exception.Message)"
    }
    foreach ($s in $raw) {
        $baseType  = $s.Type -band $STYPE_MASK
        $isSpecial = ($s.Type -band $STYPE_SPECIAL) -ne 0
        if ($baseType -ne 0) { continue }                      # disk shares only
        if ($isSpecial -and -not $IncludeAdminShares) { continue }  # skip C$/ADMIN$
        $shares += [pscustomobject]@{
            ComputerName = $HostName
            IPAddress    = $IPAddress
            ShareName    = $s.Name
            UncPath      = "\\$ScanAddress\$($s.Name)"
            Remark       = $s.Remark
            IsAdminShare = $isSpecial
        }
    }
    return $shares
}

# --------------------------------------------------------------------------- #
# 3+4. File/folder metadata walk + pattern matching (runs inside a runspace)
#      Implemented as a self-contained scriptblock so it can be parallelised.
# --------------------------------------------------------------------------- #
$script:HostScanBlock = {
    param(
        $Computer, $IpAddress, $Shares, $Patterns, $MaxDepth, $TimeoutSeconds,
        $InspectConfigContent, $MaxInspectBytes, $SecretContentRegex,
        $ScanContent, $ContentRules, $ContentExt
    )

    $sw         = [System.Diagnostics.Stopwatch]::StartNew()
    $files      = New-Object System.Collections.Generic.List[object]
    $findings   = New-Object System.Collections.Generic.List[object]
    $errors     = New-Object System.Collections.Generic.List[object]
    $configCats = 'Config-WithSecrets'

    # redact a matched secret so the report never stores it in the clear
    function Format-Redacted {
        param($Value)
        $v = ($Value -replace '\s+', ' ').Trim()
        if ($v.Length -gt 48) { $v = $v.Substring(0, 48) }
        if ($v.Length -le 6)  { return ('*' * $v.Length) }
        return $v.Substring(0, 3) + ('*' * [Math]::Min(8, $v.Length - 5)) + $v.Substring($v.Length - 2)
    }

    function Test-Luhn {
        param([string]$Number)
        $sum = 0; $alt = $false
        for ($i = $Number.Length - 1; $i -ge 0; $i--) {
            $d = [int][string]$Number[$i]
            if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }
            $sum += $d; $alt = -not $alt
        }
        return ($sum % 10) -eq 0
    }

    # read up to MaxBytes of a file and run the content rules; returns 0..n hits
    function Get-ContentFindings {
        param($Path, $Rules, $MaxBytes)
        $out = @()
        $text = $null
        try {
            $fs = [System.IO.File]::OpenRead($Path)
            try {
                $cap = [Math]::Min([int64]$MaxBytes, $fs.Length)
                if ($cap -le 0) { return $out }
                $buf = New-Object byte[] $cap
                $read = $fs.Read($buf, 0, $buf.Length)
            } finally { $fs.Dispose() }
            $probe = [Math]::Min($read, 8192)          # null-byte probe = binary guard
            for ($i = 0; $i -lt $probe; $i++) { if ($buf[$i] -eq 0) { return $out } }
            $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
        } catch { return $out }

        foreach ($rule in $Rules) {
            try {
                $matches = [regex]::Matches($text, $rule.Regex)
                if ($matches.Count -gt 0) {
                    $out += [pscustomobject]@{
                        Category = $rule.Category; Severity = $rule.Severity; Rule = $rule.Name
                        Count = $matches.Count; Evidence = (Format-Redacted $matches[0].Value)
                    }
                }
            } catch { }
        }
        # credit-card numbers: regex candidates validated with Luhn to cut false positives
        try {
            foreach ($m in [regex]::Matches($text, '\b(?:\d[ -]?){13,19}\b')) {
                $digits = ($m.Value -replace '[^0-9]', '')
                if ($digits.Length -ge 13 -and $digits.Length -le 19 -and (Test-Luhn $digits)) {
                    $out += [pscustomobject]@{
                        Category = 'PII-HR-Finance'; Severity = 'High'; Rule = 'CreditCard-Luhn'
                        Count = 1; Evidence = (Format-Redacted $digits)
                    }
                    break
                }
            }
        } catch { }
        return $out
    }

    function Test-Name {
        param($Name, $Patterns)
        $hits = @()
        foreach ($p in $Patterns) {
            foreach ($pat in $p.Names) {
                if ($Name -like $pat) {
                    $hits += [pscustomobject]@{ Category = $p.Category; Severity = $p.Severity; Pattern = $pat }
                    break
                }
            }
        }
        return $hits
    }

    # principals that, if granted access, mean the data is broadly exposed - matched
    # by name and by well-known SID (RID 513=Domain Users, 515=Domain Computers)
    $broadRegex    = '(?i)(^|\\)(Everyone|Authenticated Users|Domain Users|Domain Computers|Users)$'
    $broadSidRegex = '(?i)^(S-1-1-0|S-1-5-7|S-1-5-11|S-1-5-32-545|S-1-5-21-.*-(513|515))$'

    # translate a SID to a friendly name, falling back to the raw SID string
    function Resolve-Sid {
        param($Sid)
        try { return $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid.Value }
    }

    # owner only - cheap, captured for every inventoried file
    function Get-OwnerSafe {
        param($Path)
        try {
            $sec = [System.IO.File]::GetAccessControl($Path, [System.Security.AccessControl.AccessControlSections]::Owner)
            return Resolve-Sid $sec.GetOwner([System.Security.Principal.SecurityIdentifier])
        } catch { return '' }
    }

    # full owner + ACL detail - captured only for flagged (sensitive) files.
    # Rules are enumerated as SIDs (never throws on an unresolvable principal) and
    # translated one-by-one, so a single bad SID can't blank the whole ACL.
    function Get-AclDetail {
        param($Path, $BroadRegex, $BroadSidRegex)
        try {
            $sec = [System.IO.File]::GetAccessControl($Path,
                [System.Security.AccessControl.AccessControlSections]::Access -bor
                [System.Security.AccessControl.AccessControlSections]::Owner)
            $owner = Resolve-Sid $sec.GetOwner([System.Security.Principal.SecurityIdentifier])
            $aces = @(); $broad = @()
            $rules = $sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($r in $rules) {
                $sid  = $r.IdentityReference
                $name = Resolve-Sid $sid
                $aces += ('{0}:{1}={2}' -f $r.AccessControlType, $name, $r.FileSystemRights)
                if ($r.AccessControlType -eq 'Allow' -and ($name -match $BroadRegex -or $sid.Value -match $BroadSidRegex)) {
                    $broad += $name
                }
            }
            return [pscustomobject]@{
                Owner       = $owner
                Access      = ($aces -join ' | ')
                BroadAccess = (($broad | Select-Object -Unique) -join ', ')
            }
        } catch {
            return [pscustomobject]@{ Owner = ''; Access = "ERROR: $($_.Exception.Message)"; BroadAccess = '' }
        }
    }

    foreach ($share in $Shares) {
        if ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            $errors.Add([pscustomobject]@{ ComputerName = $Computer; IPAddress = $IpAddress; UncPath = $share.UncPath; Error = 'Host timeout reached - walk truncated' })
            break
        }

        # breadth-first walk with explicit depth tracking (avoids Get-ChildItem -Recurse
        # blowing up on access-denied subtrees and lets us bound depth/time cleanly)
        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue([pscustomobject]@{ Path = $share.UncPath; Depth = 0 })

        while ($queue.Count -gt 0) {
            if ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                $errors.Add([pscustomobject]@{ ComputerName = $Computer; IPAddress = $IpAddress; UncPath = $share.UncPath; Error = 'Host timeout reached - walk truncated' })
                break
            }
            $node = $queue.Dequeue()

            try {
                $entries = [System.IO.DirectoryInfo]::new($node.Path).EnumerateFileSystemInfos()
            } catch {
                $errors.Add([pscustomobject]@{ ComputerName = $Computer; IPAddress = $IpAddress; UncPath = $node.Path; Error = $_.Exception.Message })
                continue
            }

            foreach ($entry in $entries) {
                try {
                    $isDir = ($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0
                    if ($isDir) {
                        if ($MaxDepth -lt 0 -or $node.Depth -lt $MaxDepth) {
                            $queue.Enqueue([pscustomobject]@{ Path = $entry.FullName; Depth = $node.Depth + 1 })
                        }
                        continue
                    }

                    $fi   = [System.IO.FileInfo]$entry
                    # @() forces an array: a single match unwraps to a scalar PSCustomObject
                    # whose $_.Count is $null (no StrictMode in the runspace), which would
                    # silently route flagged files down the no-ACL branch.
                    $hits = @(Test-Name -Name $fi.Name -Patterns $Patterns)

                    # optional deep content scan (reads bytes) on eligible text files
                    $contentHits = @()
                    if ($ScanContent) {
                        $ext = $fi.Extension.ToLowerInvariant()
                        if ($fi.Length -gt 0 -and $fi.Length -le $MaxInspectBytes -and ($ext -eq '' -or $ContentExt -contains $ext)) {
                            $contentHits = @(Get-ContentFindings -Path $fi.FullName -Rules $ContentRules -MaxBytes $MaxInspectBytes)
                        }
                    }

                    $flagged = ($hits.Count -gt 0) -or ($contentHits.Count -gt 0)

                    # flagged files get full ACL detail; everything else just the owner.
                    # capture into plain strings up front so all records reuse the same values
                    $owner = ''; $broadAccess = ''; $accessList = ''
                    if ($flagged) {
                        $acl         = Get-AclDetail -Path $fi.FullName -BroadRegex $broadRegex -BroadSidRegex $broadSidRegex
                        $owner       = [string]$acl.Owner
                        $broadAccess = [string]$acl.BroadAccess
                        $accessList  = [string]$acl.Access
                    } else {
                        $owner = Get-OwnerSafe -Path $fi.FullName
                    }

                    # record metadata for every file (the "inventory"); categories from both passes
                    $allCats = @(@($hits.Category) + @($contentHits.Category) | Where-Object { $_ } | Select-Object -Unique)
                    $rec = [pscustomobject]@{
                        ComputerName = $Computer
                        IPAddress    = $IpAddress
                        ShareName    = $share.ShareName
                        FullPath     = $fi.FullName
                        FileName     = $fi.Name
                        Extension    = $fi.Extension
                        SizeBytes    = $fi.Length
                        Owner        = $owner
                        CreatedUtc   = $fi.CreationTimeUtc
                        ModifiedUtc  = $fi.LastWriteTimeUtc
                        AccessedUtc  = $fi.LastAccessTimeUtc
                        ReadOnly     = ($fi.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0
                        Categories   = ($allCats -join ';')
                    }
                    $files.Add($rec)

                    # name-based findings
                    foreach ($h in $hits) {
                        $secretLine = ''
                        if ($InspectConfigContent -and $h.Category -eq $configCats -and $fi.Length -le $MaxInspectBytes) {
                            try {
                                $buf = [System.IO.File]::ReadAllText($fi.FullName)
                                $m = [regex]::Match($buf, $SecretContentRegex)
                                if ($m.Success) { $secretLine = "keyword:$($m.Value)" }
                            } catch { }
                        }
                        $findings.Add([pscustomobject]@{
                            ComputerName = $Computer
                            IPAddress    = $IpAddress
                            ShareName    = $share.ShareName
                            FullPath     = $fi.FullName
                            FileName     = $fi.Name
                            Category     = $h.Category
                            Severity     = $h.Severity
                            MatchType    = 'Name'
                            Pattern      = $h.Pattern
                            SizeBytes    = $fi.Length
                            Owner        = $owner
                            BroadAccess  = $broadAccess
                            Access       = $accessList
                            ModifiedUtc  = $fi.LastWriteTimeUtc
                            ContentHint  = $secretLine
                        })
                    }

                    # content-based findings (redacted evidence)
                    foreach ($c in $contentHits) {
                        $findings.Add([pscustomobject]@{
                            ComputerName = $Computer
                            IPAddress    = $IpAddress
                            ShareName    = $share.ShareName
                            FullPath     = $fi.FullName
                            FileName     = $fi.Name
                            Category     = $c.Category
                            Severity     = $c.Severity
                            MatchType    = 'Content'
                            Pattern      = "content:$($c.Rule)"
                            SizeBytes    = $fi.Length
                            Owner        = $owner
                            BroadAccess  = $broadAccess
                            Access       = $accessList
                            ModifiedUtc  = $fi.LastWriteTimeUtc
                            ContentHint  = ('{0}x {1}' -f $c.Count, $c.Evidence)
                        })
                    }
                } catch {
                    $errors.Add([pscustomobject]@{ ComputerName = $Computer; IPAddress = $IpAddress; UncPath = $entry.FullName; Error = $_.Exception.Message })
                }
            }
        }
    }

    $sw.Stop()
    return [pscustomobject]@{
        Computer = $Computer
        Files    = $files
        Findings = $findings
        Errors   = $errors
        Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #
Write-AuditLog "=== Data Access Discovery Audit started ==="
Write-AuditLog "Operator: $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
if ($script:UseAltCreds) { Write-AuditLog "Auth    : alternate credentials ($($Credential.UserName))" }
else                     { Write-AuditLog "Auth    : current logon session (integrated)" }
Write-AuditLog "Output  : $OutputDirectory"

# -- Target acquisition ------------------------------------------------------
if ($Target) {
    # Direct host/IP targeting - skip AD discovery entirely.
    Write-AuditLog ("Direct target(s): {0}" -f ($Target -join ', '))
    $targets = $Target | ForEach-Object {
        [pscustomobject]@{ HostName = $_.Trim(); Name = $_.Trim(); OS = ''; OSVersion = '' } }
} elseif ($ComputerListPath) {
    Write-AuditLog "Reading target list from $ComputerListPath"
    $targets = Get-Content -Path $ComputerListPath -Encoding UTF8 |
        ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' } |
        ForEach-Object { [pscustomobject]@{ HostName = $_; Name = $_; OS = ''; OSVersion = '' } }
} else {
    $targets = Get-DomainComputer -SearchBase $SearchBase -TargetType $TargetType `
        -Domain $Domain -Server $Server -Credential $Credential
}
$targets = @($targets | Sort-Object HostName -Unique)
Write-AuditLog ("Target count: {0}" -f $targets.Count)
$targets | Export-Csv -Path (Join-Path $OutputDirectory '01_targets.csv') -NoTypeInformation -Encoding UTF8

if ($targets.Count -eq 0) { Write-AuditLog 'No targets - exiting.' 'WARN'; return }

# TCP/445 reachability probe - ICMP is frequently filtered while SMB is open
function Test-SmbPort {
    param([string]$ComputerName, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, 445, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($iar); return $true
    } catch { return $false } finally { $client.Close() }
}

# Resolve an AD hostname to a scannable address. When auditing from a host that
# does not use the domain's DNS, AD-returned FQDNs do not resolve locally; fall
# back to querying the domain's DNS server (the DC) and scan by the resolved IP.
function Resolve-ScanAddress {
    param([string]$Name, [string]$DnsServer)
    try { [void][System.Net.Dns]::GetHostAddresses($Name); return $Name }  # resolves locally - keep the name
    catch { }
    if ($DnsServer) {
        try {
            $rec = Resolve-DnsName -Name $Name -Server $DnsServer -Type A -ErrorAction Stop |
                   Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($rec) { return $rec.IPAddress }
        } catch { }
    }
    return $Name   # nothing worked; let the liveness probe fail it
}

# Resolve a host/scan address to an IPv4 string for the report's IPAddress column.
function Resolve-IPv4 {
    param([string]$Address, [string]$DnsServer)
    if ($Address -match '^\d{1,3}(\.\d{1,3}){3}$') { return $Address }   # already an IP
    try {
        $ip = [System.Net.Dns]::GetHostAddresses($Address) |
              Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($ip) { return $ip.IPAddressToString }
    } catch { }
    if ($DnsServer) {
        try {
            $rec = Resolve-DnsName -Name $Address -Server $DnsServer -Type A -ErrorAction Stop |
                   Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($rec) { return $rec.IPAddress }
        } catch { }
    }
    return ''
}

# -- Liveness + authenticated share enumeration -----------------------------
# Use -DnsServer if given, else the LDAP -Server, to resolve AD hostnames that
# our local resolver cannot (common when not joined to the target domain).
$effectiveDns = if ($DnsServer) { $DnsServer } elseif ($Server) { $Server } else { $null }
if ($effectiveDns) { Write-AuditLog "Name resolution fallback via DNS server: $effectiveDns" }

$allShares = New-Object System.Collections.Generic.List[object]
$liveHosts = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($t in $targets) {
    $i++
    Write-Progress -Activity 'Enumerating shares' -Status $t.HostName -PercentComplete (($i / $targets.Count) * 100)

    # resolve to a scannable address (keeps the name if it resolves locally) + an IP for reporting
    $scan   = Resolve-ScanAddress -Name $t.HostName -DnsServer $effectiveDns
    $ipAddr = Resolve-IPv4 -Address $scan -DnsServer $effectiveDns
    if ($scan -ne $t.HostName) { Write-AuditLog "$($t.HostName): resolved via $effectiveDns -> $scan" }

    # reachable if it answers ICMP OR has 445 open (SMB is what we actually need)
    $alive = (Test-Connection -ComputerName $scan -Count 1 -Quiet -ErrorAction SilentlyContinue) `
             -or (Test-SmbPort -ComputerName $scan)
    if (-not $alive) {
        Write-AuditLog "$($t.HostName): unreachable (no ICMP, 445 closed) - skipping" 'WARN'
        continue
    }

    # establish an authenticated session if alternate creds were supplied
    if ($script:UseAltCreds) {
        if (-not (Connect-SmbHost -ComputerName $scan -Credential $Credential)) { continue }
    }

    try {
        # @() guards against a single-share scalar (Set-StrictMode forbids .Count on scalars)
        $shares = @(Get-HostShare -ScanAddress $scan -HostName $t.HostName -IPAddress $ipAddr -IncludeAdminShares:$IncludeAdminShares)
        if ($shares.Count -gt 0) {
            $liveHosts.Add($t)
            $shares | ForEach-Object { $allShares.Add($_) }
            Write-AuditLog ("$($t.HostName): {0} accessible disk share(s)" -f $shares.Count)
        } else {
            Write-AuditLog "$($t.HostName): no enumerable disk shares"
        }
    } catch {
        Write-AuditLog "$($t.HostName): share enum failed - $($_.Exception.Message)" 'WARN'
    }
}
Write-Progress -Activity 'Enumerating shares' -Completed
$allShares | Export-Csv -Path (Join-Path $OutputDirectory '02_shares.csv') -NoTypeInformation -Encoding UTF8
Write-AuditLog ("Total shares to scan: {0} across {1} host(s)" -f $allShares.Count, $liveHosts.Count)

if ($allShares.Count -eq 0) { Write-AuditLog 'No shares to scan - exiting.' 'WARN'; Disconnect-AllSmbHosts; return }

# -- Select content rules by tier (-ContentRuleSet) -------------------------
$tierRank      = @{ Minimal = 0; Standard = 1; Aggressive = 2 }
$activeContentRules = @($script:ContentRules | Where-Object { $tierRank[$_.Tier] -le $tierRank[$ContentRuleSet] })
if ($ScanContent) {
    Write-AuditLog ("Content scan: ON  (ruleset={0}, {1} rules + Luhn card check)" -f $ContentRuleSet, $activeContentRules.Count)
}

# -- Parallel file walk (runspace pool) -------------------------------------
$sharesByHost = $allShares | Group-Object ComputerName
$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$jobs = @()

foreach ($g in $sharesByHost) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($script:HostScanBlock).
        AddArgument($g.Name).
        AddArgument([string]$g.Group[0].IPAddress).
        AddArgument(@($g.Group)).
        AddArgument($script:Patterns).
        AddArgument($MaxDepth).
        AddArgument($HostTimeoutSeconds).
        AddArgument([bool]$InspectConfigContent).
        AddArgument($MaxInspectBytes).
        AddArgument($script:SecretContentRegex).
        AddArgument([bool]$ScanContent).
        AddArgument($activeContentRules).
        AddArgument($script:ContentExt)
    $jobs += [pscustomobject]@{ Host = $g.Name; PS = $ps; Handle = $ps.BeginInvoke() }
}

$allFiles    = New-Object System.Collections.Generic.List[object]
$allFindings = New-Object System.Collections.Generic.List[object]
$allErrors   = New-Object System.Collections.Generic.List[object]
$done = 0
foreach ($job in $jobs) {
    try {
        $r = $job.PS.EndInvoke($job.Handle)
        foreach ($out in $r) {
            $out.Files    | ForEach-Object { $allFiles.Add($_) }
            $out.Findings | ForEach-Object { $allFindings.Add($_) }
            $out.Errors   | ForEach-Object { $allErrors.Add($_) }
            Write-AuditLog ("{0}: {1} files, {2} findings, {3}s" -f $out.Computer, $out.Files.Count, $out.Findings.Count, $out.Seconds)
            foreach ($f in $out.Findings) {
                Write-AuditLog ("  [{0}] {1} -> {2}" -f $f.Severity, $f.Category, $f.FullPath) 'FIND'
            }
        }
    } catch {
        Write-AuditLog "$($job.Host): scan runspace error - $($_.Exception.Message)" 'ERROR'
    } finally {
        $job.PS.Dispose()
    }
    $done++
    Write-Progress -Activity 'Scanning shares' -Status "$done / $($jobs.Count) hosts" -PercentComplete (($done / $jobs.Count) * 100)
}
Write-Progress -Activity 'Scanning shares' -Completed
$pool.Close(); $pool.Dispose()

# -- Persist results ---------------------------------------------------------
$allFiles    | Export-Csv -Path (Join-Path $OutputDirectory '03_file_inventory.csv') -NoTypeInformation -Encoding UTF8
$allFindings | Export-Csv -Path (Join-Path $OutputDirectory '04_sensitive_findings.csv') -NoTypeInformation -Encoding UTF8
$allErrors   | Export-Csv -Path (Join-Path $OutputDirectory '05_access_errors.csv') -NoTypeInformation -Encoding UTF8

# JSON findings (UTF-8 no BOM) for downstream tooling
Write-Utf8File -Path (Join-Path $OutputDirectory '04_sensitive_findings.json') -Text ($allFindings | ConvertTo-Json -Depth 4)

# -- Summary -----------------------------------------------------------------
$summary = [pscustomobject]@{
    StartedBy          = "$env:USERDOMAIN\$env:USERNAME"
    RunFrom            = $env:COMPUTERNAME
    TargetsTotal       = $targets.Count
    HostsWithShares    = $liveHosts.Count
    SharesScanned      = $allShares.Count
    FilesInventoried   = $allFiles.Count
    SensitiveFindings  = $allFindings.Count
    NameFindings       = @($allFindings | Where-Object { $_.MatchType -eq 'Name' }).Count
    ContentFindings    = @($allFindings | Where-Object { $_.MatchType -eq 'Content' }).Count
    BroadlyExposed     = @($allFindings | Where-Object { $_.BroadAccess }).Count  # readable by Everyone/Authenticated Users/Domain Users/etc.
    AccessErrors       = $allErrors.Count
    BySeverity         = ($allFindings | Group-Object Severity | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
    ByCategory         = ($allFindings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
}
$summary | Format-List | Out-String | Write-Host
Write-Utf8File -Path (Join-Path $OutputDirectory '00_summary.json') -Text ($summary | ConvertTo-Json -Depth 4)

Disconnect-AllSmbHosts
Write-AuditLog "=== Audit complete. Results in $OutputDirectory ==="
