<#
.SYNOPSIS
    Decrypts PGP-encrypted .eml and .msg files using private keys exported from the Echoworx EMG REST API.

.DESCRIPTION
    For every .eml or .msg in -SourceFolder (top level only):
      * The message is parsed for its sender, recipients and a PGP payload: a PGP/MIME part, a
        message.pgp (or other .pgp/.gpg/.asc) attachment, or an inline PGP block.
      * Messages with no PGP payload are moved to "Not Encrypted".
      * The internal participant (a domain listed in InternalDomains.csv) is the Echoworx profile owner.
        Their private key is exported once per email address from
        POST /profiles/{profileName}/pgp-key-pair/export and imported into a temporary, isolated GnuPG
        keyring created for this run only.
      * gpg.exe decrypts the payload and the reconstructed .eml is written to "Successful". Once the
        output is confirmed non-empty, the encrypted source is deleted. Failures are moved to "Failed".
      * A CSV log and a detailed text log are written to the source folder, and a summary is shown.
    The temporary keyring, and every private key in it, is deleted when the run finishes.

    .msg files are read through Outlook COM automation. If Outlook is already running, COM may fail
    to attach (for example when this script runs elevated and Outlook does not), so you are warned first.

.EXAMPLE
    .\Invoke-EchoworxDecryption.ps1 -SourceFolder 'D:\Evidence\Batch1'

.EXAMPLE
    $pass = Read-Host 'Key bundle passphrase' -AsSecureString
    .\Invoke-EchoworxDecryption.ps1 -SourceFolder 'D:\Evidence\Batch1' -Passphrase $pass -GpgPath 'D:\Tools\GnuPG\bin\gpg.exe'
#>
[CmdletBinding()]
param(
    # Folder holding the .eml / .msg files to process
    [string]$SourceFolder,

    # Echoworx EMG environment, a key of $EchoworxEnvironments below
    [string]$Environment = 'Production',

    # Echoworx profile name used in the export URL: the internal user's email address by default.
    # {email} is replaced with that address, so a fixed name can be given instead.
    [string]$ProfileName = '{email}',

    [string]$GpgPath = 'C:\Program Files\GnuPG\bin\gpg.exe',

    # Protects the exported key bundle in transit and unlocks it in GnuPG. A random one is generated
    # for this run if you leave it out; it is never written anywhere.
    [System.Security.SecureString]$Passphrase,

    # SecretStore vault holding the API key. Empty uses the default vault.
    [string]$VaultName,

    # Unlocks a password-protected SecretStore vault. Without it, SecretStore prompts if it is locked.
    [System.Security.SecureString]$VaultPassword,

    # Defaults to InternalDomains.csv next to this script
    [string]$InternalDomainsPath,

    # Replaces the environment's URL. For testing against a mock server only.
    [string]$ApiBaseUrl,

    # Continue without asking when Outlook is already running
    [switch]$Force,

    # Used by the GUI: each result row is queued here, progress and stop requests go through $Progress
    [System.Collections.Concurrent.ConcurrentQueue[object]]$ResultQueue,
    [hashtable]$Progress,

    # No on-screen summary
    [switch]$Quiet
)

# ------------------ Environments (edit here) ------------------
# The API key for each environment is read from the SecretStore vault under SecretName.
$EchoworxEnvironments = [ordered]@{
    Production = @{ BaseUrl = 'https://securemails-admin.lloydsbanking.com'; SecretName = 'EchoworxApiKey' }
}

# Body of POST /profiles/{profileName}/pgp-key-pair/export. Change the field names here if your
# EMG API version expects different ones.
Function New-KeyExportBody {
    param([string]$EmailAddress, [string]$PlainPassphrase)
    [ordered]@{ emailAddress = $EmailAddress; passphrase = $PlainPassphrase } | ConvertTo-Json -Compress
}

# ------------------ Utilities ------------------
$ErrorActionPreference = 'Stop'
$script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
$script:Latin1 = [System.Text.Encoding]::GetEncoding(28591)   # one char per byte, so raw MIME survives string handling
$script:Utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$EmailRegex = '[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+'

Function Write-RunLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:RunLogPath) { Add-Content -LiteralPath $script:RunLogPath -Value $line -Encoding UTF8 }
    Write-Verbose $line
}

Function Get-TextEncoding {
    param([string]$Charset)
    if ([string]::IsNullOrWhiteSpace($Charset)) { return $script:Utf8 }
    $name = $Charset.Trim().Trim('"').ToLowerInvariant()
    if ($name -in 'us-ascii', 'ascii', 'utf-8', 'utf8') { return $script:Utf8 }   # ASCII is a subset; UTF-8 forgives mislabelled mail
    try { return [System.Text.Encoding]::GetEncoding($name) } catch { }
    try {
        [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
        return [System.Text.Encoding]::GetEncoding($name)
    } catch { }
    $script:Utf8
}

# Raw 8-bit header bytes: UTF-8 if they are valid UTF-8, otherwise Windows-1252
Function ConvertFrom-RawText {
    param([string]$Latin1Text)
    if ($Latin1Text -notmatch '[^\x00-\x7F]') { return $Latin1Text }
    $bytes = $script:Latin1.GetBytes($Latin1Text)
    try { return $script:Utf8Strict.GetString($bytes) } catch { }
    (Get-TextEncoding 'windows-1252').GetString($bytes)
}

Function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return $null }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# Letters and digits only (no look-alikes), so it survives JSON, stdin and any API validation
Function New-RandomPassphrase {
    param([int]$Length = 32)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $secure = New-Object System.Security.SecureString
    $buffer = New-Object byte[] 1
    $limit = 256 - (256 % $alphabet.Length)   # rejection sampling avoids modulo bias
    try {
        while ($secure.Length -lt $Length) {
            $rng.GetBytes($buffer)
            if ($buffer[0] -lt $limit) { $secure.AppendChar($alphabet[$buffer[0] % $alphabet.Length]) }
        }
    } finally { $rng.Dispose() }
    $secure.MakeReadOnly()
    $secure
}

Function Get-UniquePath {
    param([string]$Folder, [string]$FileName)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $ext = [System.IO.Path]::GetExtension($FileName)
    $candidate = Join-Path $Folder $FileName
    $n = 1
    while (Test-Path -LiteralPath $candidate) { $candidate = Join-Path $Folder ('{0}_{1}{2}' -f $base, $n, $ext); $n++ }
    $candidate
}

Function Move-ToFolder {
    param([string]$Path, [string]$Folder)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder }
    $dest = Get-UniquePath $Folder ([System.IO.Path]::GetFileName($Path))
    Move-Item -LiteralPath $Path -Destination $dest
    $dest
}

# ------------------ Internal domains ------------------
Function Read-InternalDomains {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "InternalDomains.csv was not found at '$Path'. It needs a Domain header and at least one domain." }
    $header = (Get-Content -LiteralPath $Path -TotalCount 1)
    $columns = @("$header".TrimStart([char]0xFEFF) -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    if ($columns -notcontains 'Domain') { throw "InternalDomains.csv at '$Path' has no Domain header. The first line must be: Domain" }
    $domains = @(Import-Csv -LiteralPath $Path | ForEach-Object { ([string]$_.Domain).Trim().TrimStart('@').ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if ($domains.Count -eq 0) { throw "InternalDomains.csv at '$Path' lists no domains. Add at least one under the Domain header." }
    $domains
}

Function Test-InternalAddress {
    param([string]$Address, [string[]]$Domains)
    $at = $Address.LastIndexOf('@')
    if ($at -lt 0) { return $false }
    $domain = $Address.Substring($at + 1).ToLowerInvariant()
    foreach ($d in $Domains) { if ($domain -eq $d -or $domain.EndsWith('.' + $d)) { return $true } }
    $false
}

# ------------------ RFC 2047 / RFC 2822 ------------------
Function ConvertFrom-EncodedWord {
    param([string]$Text)
    if (-not $Text -or $Text -notmatch '=\?') { return $Text }
    # Whitespace between two adjacent encoded words is not part of the text
    $Text = [regex]::Replace($Text, '(\?=)\s+(?==\?)', '$1')
    [regex]::Replace($Text, '=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=', {
        param($m)
        try {
            $charset = $m.Groups[1].Value.Split('*')[0]
            $data = $m.Groups[3].Value
            if ($m.Groups[2].Value -ieq 'B') {
                $data = $data.PadRight($data.Length + ((4 - $data.Length % 4) % 4), '=')
                $bytes = [Convert]::FromBase64String($data)
            } else {
                $q = [regex]::Replace($data.Replace('_', ' '), '=([0-9A-Fa-f]{2})', { param($h) [string][char][Convert]::ToByte($h.Groups[1].Value, 16) })
                $bytes = $script:Latin1.GetBytes($q)
            }
            (Get-TextEncoding $charset).GetString($bytes)
        } catch { $m.Value }
    })
}

# Unstructured text as RFC 2047 encoded words when it is not plain ASCII
Function ConvertTo-EncodedWord {
    param([string]$Text)
    if ($Text -notmatch '[^\x20-\x7E]') { return $Text }
    $words = New-Object System.Collections.Generic.List[string]
    $chunk = New-Object System.Text.StringBuilder
    $chunkBytes = 0
    $i = 0
    while ($i -lt $Text.Length) {
        # Keep surrogate pairs together so no word splits a character
        $len = if ([char]::IsHighSurrogate($Text[$i]) -and $i + 1 -lt $Text.Length) { 2 } else { 1 }
        $piece = $Text.Substring($i, $len)
        $n = $script:Utf8.GetByteCount($piece)
        if ($chunkBytes + $n -gt 39) {   # 39 bytes = 52 base64 chars: a 64-char word fits after "Subject: " in 78
            $words.Add('=?utf-8?B?' + [Convert]::ToBase64String($script:Utf8.GetBytes($chunk.ToString())) + '?=')
            $null = $chunk.Clear(); $chunkBytes = 0
        }
        $null = $chunk.Append($piece); $chunkBytes += $n
        $i += $len
    }
    if ($chunk.Length -gt 0) { $words.Add('=?utf-8?B?' + [Convert]::ToBase64String($script:Utf8.GetBytes($chunk.ToString())) + '?=') }
    $words -join "`r`n "
}

Function Format-MailAddress {
    param([string]$Name, [string]$Address)
    $Name = "$Name".Trim()
    if (-not $Name -or $Name -ieq $Address) { return $Address }
    if ($Name -match '[^\x20-\x7E]') { return '{0} <{1}>' -f (ConvertTo-EncodedWord $Name), $Address }
    if ($Name -match '[()<>\[\]:;@\\,."]') { return '"{0}" <{1}>' -f ($Name -replace '(["\\])', '\$1'), $Address }
    '{0} <{1}>' -f $Name, $Address
}

# Splits an address header into Name / Address pairs (commas inside quotes or <> do not split)
Function ConvertFrom-AddressList {
    param([string]$Value)
    $result = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $items = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQuote = $false; $inAngle = $false; $escape = $false
    foreach ($ch in $Value.ToCharArray()) {
        if ($escape) { $null = $sb.Append($ch); $escape = $false; continue }
        if ($ch -eq '\' -and $inQuote) { $null = $sb.Append($ch); $escape = $true; continue }
        if ($ch -eq '"') { $inQuote = -not $inQuote }
        elseif (-not $inQuote -and $ch -eq '<') { $inAngle = $true }
        elseif (-not $inQuote -and $ch -eq '>') { $inAngle = $false }
        if (-not $inQuote -and -not $inAngle -and ($ch -eq ',' -or $ch -eq ';')) { $items.Add($sb.ToString()); $null = $sb.Clear(); continue }
        $null = $sb.Append($ch)
    }
    $items.Add($sb.ToString())
    foreach ($item in $items) {
        $item = $item.Trim()
        if (-not $item) { continue }
        $item = $item -replace '^[^"<]*?:\s*', ''   # group syntax: "Team: a@b.com, c@d.com;"
        $m = [regex]::Match($item, '<\s*([^<>\s]+@[^<>\s]+)\s*>')
        if ($m.Success) {
            $name = $item.Substring(0, $m.Index).Trim().Trim('"') -replace '\\(.)', '$1'
            $result.Add([pscustomobject]@{ Name = (ConvertFrom-EncodedWord $name); Address = $m.Groups[1].Value.Trim() })
        } else {
            $m = [regex]::Match($item, $EmailRegex)
            if ($m.Success) { $result.Add([pscustomobject]@{ Name = ''; Address = $m.Value }) }
        }
    }
    $result
}

Function Format-Rfc2822Date {
    param([DateTimeOffset]$Date)
    $offset = $Date.Offset
    $sign = if ($offset -lt [TimeSpan]::Zero) { '-' } else { '+' }
    $abs = $offset.Duration()
    '{0} {1}{2:00}{3:00}' -f $Date.ToString('ddd, dd MMM yyyy HH:mm:ss', $script:Invariant), $sign, $abs.Hours, $abs.Minutes
}

$Rfc2822DatePattern = '^\s*(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s*)?\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}(?::\d{2})?\s+(?:[+-]\d{4}|UT|GMT|[ECMP][SD]T|[A-IK-Za-ik-z])\s*(?:\(.*\))?\s*$'

# Keeps a valid RFC 2822 date as it is, otherwise reformats whatever can be parsed
Function ConvertTo-Rfc2822Date {
    param([string]$Value)
    if ($Value -match $Rfc2822DatePattern) { return $Value.Trim() }
    $clean = ($Value -replace '\(.*?\)', '').Trim()
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($clean, $script:Invariant, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return Format-Rfc2822Date $parsed
    }
    $null
}

$AddressHeaders = 'From', 'To', 'Cc', 'Bcc', 'Reply-To', 'Sender', 'Resent-From', 'Resent-To', 'Resent-Cc', 'Delivered-To', 'Return-Path'

# Folds a header so no line is longer than 78 characters where there is whitespace to fold at
Function Format-FoldedHeader {
    param([string]$Name, [string]$Value)
    $lines = New-Object System.Collections.Generic.List[string]
    $current = $Name + ':'
    foreach ($segment in ($Value -split "`r`n ")) {
        foreach ($token in ($segment -split ' ')) {
            if ($current.Length + 1 + $token.Length -gt 78 -and $current.Trim() -notmatch ':$') { $lines.Add($current); $current = ' ' + $token }
            else { $current += ' ' + $token }
        }
    }
    $lines.Add($current)
    $lines -join "`r`n"
}

Function New-HeaderLine {
    param([string]$Name, [string]$Value)
    if ($Name -in $AddressHeaders) {
        $formatted = @(ConvertFrom-AddressList $Value | ForEach-Object { Format-MailAddress $_.Name $_.Address })
        if ($formatted.Count -gt 0) { return (Format-FoldedHeader $Name ($formatted -join ', ')) }
    }
    if ($Name -eq 'Date') {
        $date = ConvertTo-Rfc2822Date $Value
        if ($date) { return 'Date: ' + $date }
    }
    Format-FoldedHeader $Name (ConvertTo-EncodedWord $Value)
}

# Header as it goes into the output: raw if it is already 7-bit and its date is valid, otherwise re-encoded
Function Format-OutputHeader {
    param($Header)
    if ($Header.Name -eq 'Date') {
        $value = $Header.Value.Trim()
        if ($value -match $Rfc2822DatePattern) { return $Header.Raw }
        $date = ConvertTo-Rfc2822Date $value
        if ($date) { return 'Date: ' + $date }
        return $Header.Raw
    }
    if ($Header.Raw -notmatch '[^\x00-\x7F]') { return $Header.Raw }
    $text = ConvertFrom-RawText $Header.Value.Trim()
    if ($Header.Name -notin $AddressHeaders) { $text = ConvertFrom-EncodedWord $text }
    New-HeaderLine $Header.Name $text
}

# ------------------ MIME parsing ------------------
Function ConvertFrom-HeaderBlock {
    param([string]$Text)
    $list = New-Object System.Collections.Generic.List[object]
    $bad = 0
    if ($Text) {
        $current = $null
        foreach ($line in ($Text -split '\r?\n')) {
            if ($line -match '^[ \t]' -and $current) {
                $current.Raw += "`r`n" + $line
                $current.Value += $line
            } elseif ($line -match '^([!-9;-~]+):[ \t]?(.*)$') {
                $current = [pscustomobject]@{ Name = $Matches[1]; Value = $Matches[2]; Raw = $line }
                $list.Add($current)
            } elseif ($list.Count -eq 0 -and $line -match '^From ') {
                continue   # mbox separator line
            } else { $bad++ }
        }
    }
    [pscustomobject]@{ Headers = $list; Malformed = $bad }
}

Function Split-MimeEntity {
    param([string]$Raw)
    if ($Raw -match '^\r?\n') {
        return [pscustomobject]@{ Headers = (New-Object System.Collections.Generic.List[object]); Malformed = 0; Body = ($Raw -replace '^\r?\n', '') }
    }
    $m = [regex]::Match($Raw, '\r?\n\r?\n')
    if ($m.Success) { $headerText = $Raw.Substring(0, $m.Index); $body = $Raw.Substring($m.Index + $m.Length) }
    else { $headerText = $Raw; $body = '' }
    $parsed = ConvertFrom-HeaderBlock $headerText
    [pscustomobject]@{ Headers = $parsed.Headers; Malformed = $parsed.Malformed; Body = $body }
}

Function Get-HeaderValue {
    param($Headers, [string]$Name)
    foreach ($h in $Headers) { if ($h.Name -ieq $Name) { return $h.Value.Trim() } }
    $null
}

Function Get-HeaderParameter {
    param([string]$Value, [string]$Name)
    if (-not $Value) { return $null }
    # RFC 2231: name*=charset'language'percent-encoded
    $m = [regex]::Match($Value, '(?i);\s*' + [regex]::Escape($Name) + '\*=\s*"?([^;"]*)"?')
    if ($m.Success) {
        $parts = $m.Groups[1].Value.Split([char]39)
        if ($parts.Count -ge 3) {
            $encoded = ($parts[2..($parts.Count - 1)] -join "'")
            $raw = [regex]::Replace($encoded, '%([0-9A-Fa-f]{2})', { param($h) [string][char][Convert]::ToByte($h.Groups[1].Value, 16) })
            return (Get-TextEncoding $parts[0]).GetString($script:Latin1.GetBytes($raw))
        }
        return $m.Groups[1].Value
    }
    $m = [regex]::Match($Value, '(?i)(?:^|;)\s*' + [regex]::Escape($Name) + '\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]+))')
    if (-not $m.Success) { return $null }
    $v = if ($m.Groups[1].Success) { $m.Groups[1].Value -replace '\\(.)', '$1' } else { $m.Groups[2].Value }
    ConvertFrom-EncodedWord (ConvertFrom-RawText $v)
}

Function Get-ContentTypeInfo {
    param($Headers)
    $value = Get-HeaderValue $Headers 'Content-Type'
    if (-not $value) { return [pscustomobject]@{ Type = 'text/plain'; Value = ''; Charset = 'us-ascii'; Boundary = $null; Name = $null } }
    [pscustomobject]@{
        Type     = ($value.Split(';')[0]).Trim().ToLowerInvariant()
        Value    = $value
        Charset  = Get-HeaderParameter $value 'charset'
        Boundary = Get-HeaderParameter $value 'boundary'
        Name     = Get-HeaderParameter $value 'name'
    }
}

Function Split-Multipart {
    param([string]$Body, [string]$Boundary)
    $parts = New-Object System.Collections.Generic.List[string]
    $pattern = '(?m)^--' + [regex]::Escape($Boundary) + '(--)?[ \t]*\r?$\n?'
    $found = [regex]::Matches($Body, $pattern)
    for ($i = 0; $i -lt $found.Count - 1; $i++) {
        if ($found[$i].Groups[1].Success) { break }
        $start = $found[$i].Index + $found[$i].Length
        $part = $Body.Substring($start, $found[$i + 1].Index - $start)
        $parts.Add(($part -replace '\r?\n$', ''))   # the line break before a delimiter belongs to the delimiter
    }
    $parts
}

Function ConvertFrom-TransferEncoding {
    param($Entity)
    $cte = "$(Get-HeaderValue $Entity.Headers 'Content-Transfer-Encoding')".Trim().ToLowerInvariant()
    switch ($cte) {
        'base64' {
            $clean = $Entity.Body -replace '[^A-Za-z0-9+/=]', ''
            $clean = $clean.TrimEnd('=')
            if ($clean.Length % 4 -eq 1) { $clean = $clean.Substring(0, $clean.Length - 1) }
            $clean = $clean.PadRight($clean.Length + ((4 - $clean.Length % 4) % 4), '=')
            return ,[Convert]::FromBase64String($clean)
        }
        'quoted-printable' {
            $s = $Entity.Body -replace '=[ \t]*\r?\n', ''
            $s = [regex]::Replace($s, '=([0-9A-Fa-f]{2})', { param($h) [string][char][Convert]::ToByte($h.Groups[1].Value, 16) })
            return ,$script:Latin1.GetBytes($s)
        }
        default { return ,$script:Latin1.GetBytes($Entity.Body) }
    }
}

Function ConvertFrom-Html {
    param([string]$Html)
    $t = $Html -replace '(?is)<(script|style)\b.*?</\1>', ''
    $t = $t -replace '(?i)<br\s*/?>', "`n" -replace '(?i)</(p|div|tr|li|pre|h\d)>', "`n"
    $t = $t -replace '<[^>]+>', ''
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    $t.Replace([string][char]0xA0, ' ')
}

$PgpMessagePattern = '-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----'

Function Test-PgpData {
    param([byte[]]$Bytes, [string]$Name)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return $false }
    $text = $script:Latin1.GetString($Bytes)
    if ($text.Contains('-----BEGIN PGP MESSAGE-----')) { return $true }
    # Binary OpenPGP: first byte is a packet tag (top bit set); only trusted for .pgp / .gpg names
    ($Name -match '(?i)\.(pgp|gpg)$') -and (($Bytes[0] -band 0x80) -ne 0)
}

Function Get-PartFileName {
    param($Headers, $ContentType)
    $disposition = Get-HeaderValue $Headers 'Content-Disposition'
    $name = Get-HeaderParameter $disposition 'filename'
    if (-not $name) { $name = $ContentType.Name }
    $name
}

# Collects every PGP payload in the entity tree; the caller takes the best one
Function Find-PgpCandidates {
    param($Entity, $Found, [int]$Depth = 0)
    if ($Depth -gt 25) { return }
    $ct = Get-ContentTypeInfo $Entity.Headers
    if ($ct.Type -like 'multipart/*') {
        if (-not $ct.Boundary) { return }
        $parts = @(Split-Multipart $Entity.Body $ct.Boundary | ForEach-Object { Split-MimeEntity $_ })
        if ($ct.Type -eq 'multipart/encrypted') {
            foreach ($p in $parts) {
                $pct = Get-ContentTypeInfo $p.Headers
                if ($pct.Type -eq 'application/pgp-encrypted') { continue }   # the "Version: 1" control part
                $data = ConvertFrom-TransferEncoding $p
                if (Test-PgpData $data (Get-PartFileName $p.Headers $pct)) {
                    $Found.Add([pscustomobject]@{ Kind = 'PGP/MIME'; Priority = 0; Name = (Get-PartFileName $p.Headers $pct); Data = $data; Text = $null; Charset = $null })
                    return
                }
            }
        }
        foreach ($p in $parts) { Find-PgpCandidates $p $Found ($Depth + 1) }
        return
    }
    $name = Get-PartFileName $Entity.Headers $ct
    $disposition = "$(Get-HeaderValue $Entity.Headers 'Content-Disposition')"
    $data = ConvertFrom-TransferEncoding $Entity
    if ($ct.Type -in 'text/plain', 'text/html' -and -not $name -and $disposition -notmatch '^\s*attachment') {
        $text = (Get-TextEncoding $ct.Charset).GetString($data)
        if ($ct.Type -eq 'text/html') { $text = ConvertFrom-Html $text }
        if ($text -match $PgpMessagePattern) {
            $priority = if ($ct.Type -eq 'text/plain') { 2 } else { 3 }
            $Found.Add([pscustomobject]@{ Kind = 'Inline'; Priority = $priority; Name = $null; Data = $null; Text = $text; Charset = $ct.Charset })
        }
        return
    }
    if (Test-PgpData $data $name) {
        $Found.Add([pscustomobject]@{ Kind = 'Attachment'; Priority = 1; Name = $name; Data = $data; Text = $null; Charset = $null })
    }
}

Function Select-PgpPayload {
    param($Candidates)
    @($Candidates | Sort-Object Priority) | Select-Object -First 1
}

# Parses an .eml into the shape every later step uses
Function Read-EmlMessage {
    param([string]$Path)
    $raw = $script:Latin1.GetString([System.IO.File]::ReadAllBytes($Path))
    $entity = Split-MimeEntity $raw
    if ($entity.Headers.Count -eq 0) { throw 'The file has no message headers. It may not be an email, or it is corrupt.' }
    $found = New-Object System.Collections.Generic.List[object]
    Find-PgpCandidates $entity $found
    $addr = { param($name) @(ConvertFrom-AddressList (ConvertFrom-RawText "$(Get-HeaderValue $entity.Headers $name)")) }
    [pscustomobject]@{
        Headers = $entity.Headers
        From    = @(& $addr 'From') | Select-Object -First 1
        To      = @(& $addr 'To')
        Cc      = @(& $addr 'Cc')
        Bcc     = @(& $addr 'Bcc')
        Subject = ConvertFrom-EncodedWord (ConvertFrom-RawText "$(Get-HeaderValue $entity.Headers 'Subject')")
        Date    = [DateTimeOffset](Get-Item -LiteralPath $Path).LastWriteTime   # only used when there is no Date header
        Payload = Select-PgpPayload $found
        PayloadCount = $found.Count
    }
}

# ------------------ Outlook (.msg) ------------------
$script:Outlook = $null
$script:OutlookStartedHere = $false
$PR_TRANSPORT_MESSAGE_HEADERS = 'http://schemas.microsoft.com/mapi/proptag/0x007D001F'
$PR_INTERNET_MESSAGE_ID      = 'http://schemas.microsoft.com/mapi/proptag/0x1035001F'
$PR_SENDER_SMTP_ADDRESS      = 'http://schemas.microsoft.com/mapi/proptag/0x5D01001F'
$PR_SMTP_ADDRESS             = 'http://schemas.microsoft.com/mapi/proptag/0x39FE001F'

Function Test-OutlookRunning { [bool](Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue) }

Function Get-OutlookNamespace {
    if ($script:Outlook) { return $script:OutlookNs }
    $wasRunning = Test-OutlookRunning
    try { $script:Outlook = New-Object -ComObject Outlook.Application }
    catch {
        $hint = if ($wasRunning) { ' Outlook is already running, which commonly blocks COM automation (for example when Outlook and this script run at different elevation levels). Close Outlook and run again.' } else { ' Check that Outlook desktop is installed for this user.' }
        throw ("Could not start Outlook through COM: {0}.{1}" -f $_.Exception.Message, $hint)
    }
    $script:OutlookStartedHere = -not $wasRunning
    $script:OutlookNs = $script:Outlook.GetNamespace('MAPI')
    $script:OutlookNs
}

Function Close-Outlook {
    if (-not $script:Outlook) { return }
    try { if ($script:OutlookStartedHere) { $script:Outlook.Quit() } } catch { }
    try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($script:Outlook) } catch { }
    $script:Outlook = $null; $script:OutlookNs = $null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

Function Get-MapiProperty {
    param($Object, [string]$Tag)
    try { $v = $Object.PropertyAccessor.GetProperty($Tag); if ($v) { return [string]$v } } catch { }
    $null
}

Function Get-OutlookSenderAddress {
    param($Item)
    $smtp = Get-MapiProperty $Item $PR_SENDER_SMTP_ADDRESS
    if ($smtp) { return $smtp }
    try { if ($Item.SenderEmailType -eq 'EX') { $u = $Item.Sender.GetExchangeUser(); if ($u -and $u.PrimarySmtpAddress) { return [string]$u.PrimarySmtpAddress } } } catch { }
    [string]$Item.SenderEmailAddress
}

Function Get-OutlookRecipientAddress {
    param($Recipient)
    $smtp = Get-MapiProperty $Recipient $PR_SMTP_ADDRESS
    if ($smtp) { return $smtp }
    try { $u = $Recipient.AddressEntry.GetExchangeUser(); if ($u -and $u.PrimarySmtpAddress) { return [string]$u.PrimarySmtpAddress } } catch { }
    [string]$Recipient.Address
}

# Reads a .msg through Outlook into the same shape as Read-EmlMessage. The item is closed and
# released before returning so the file can be moved or deleted.
Function Read-MsgMessage {
    param([string]$Path, [string]$WorkFolder)
    $ns = Get-OutlookNamespace
    try { $item = $ns.OpenSharedItem($Path) }
    catch { throw ("Outlook could not open the .msg: {0}. The file may be corrupt or not an Outlook message." -f $_.Exception.Message) }
    try {
        $from = [pscustomobject]@{ Name = [string]$item.SenderName; Address = (Get-OutlookSenderAddress $item) }
        $to = New-Object System.Collections.Generic.List[object]
        $cc = New-Object System.Collections.Generic.List[object]
        $bcc = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $item.Recipients.Count; $i++) {
            $r = $item.Recipients.Item($i)
            $entry = [pscustomobject]@{ Name = [string]$r.Name; Address = (Get-OutlookRecipientAddress $r) }
            switch ([int]$r.Type) { 2 { $cc.Add($entry) } 3 { $bcc.Add($entry) } default { $to.Add($entry) } }
            $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($r)
        }

        # Envelope headers: the original transport headers when Outlook kept them, otherwise built
        # from the item's properties (RFC 2047 encoded, RFC 2822 date)
        $headers = New-Object System.Collections.Generic.List[object]
        $transport = Get-MapiProperty $item $PR_TRANSPORT_MESSAGE_HEADERS
        if ($transport) {
            $headers = (ConvertFrom-HeaderBlock (ConvertFrom-OutlookText $transport)).Headers
        }
        $date = $null
        try { if ($item.SentOn -and $item.SentOn.Year -lt 4000) { $date = [DateTimeOffset]$item.SentOn } } catch { }
        if (-not $date) { try { if ($item.ReceivedTime -and $item.ReceivedTime.Year -lt 4000) { $date = [DateTimeOffset]$item.ReceivedTime } } catch { } }
        if (-not (Get-HeaderValue $headers 'From'))       { Add-SyntheticHeader $headers 'From' (Format-MailAddress $from.Name $from.Address) }
        if (-not (Get-HeaderValue $headers 'To') -and $to.Count)  { Add-SyntheticHeader $headers 'To' (@($to | ForEach-Object { Format-MailAddress $_.Name $_.Address }) -join ', ') }
        if (-not (Get-HeaderValue $headers 'Cc') -and $cc.Count)  { Add-SyntheticHeader $headers 'Cc' (@($cc | ForEach-Object { Format-MailAddress $_.Name $_.Address }) -join ', ') }
        if (-not (Get-HeaderValue $headers 'Subject'))    { Add-SyntheticHeader $headers 'Subject' ([string]$item.Subject) }
        if (-not (Get-HeaderValue $headers 'Date') -and $date) { Add-SyntheticHeader $headers 'Date' (Format-Rfc2822Date $date) }
        if (-not (Get-HeaderValue $headers 'Message-ID')) {
            $id = Get-MapiProperty $item $PR_INTERNET_MESSAGE_ID
            if ($id) { Add-SyntheticHeader $headers 'Message-ID' $id }
        }

        # PGP payload: an encrypted attachment (message.pgp, encrypted.asc...) first, then an inline block
        $found = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $item.Attachments.Count; $i++) {
            $att = $item.Attachments.Item($i)
            try {
                $name = [string]$att.FileName
                $looksPgp = $name -match '(?i)\.(pgp|gpg|asc)$'
                if ($looksPgp -or $att.Size -lt 25MB) {
                    $tmp = Join-Path $WorkFolder ('att_{0}.bin' -f [guid]::NewGuid().ToString('N'))
                    $att.SaveAsFile($tmp)
                    try { $data = [System.IO.File]::ReadAllBytes($tmp) } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                    if (Test-PgpData $data $name) {
                        $kind = if ($name -match '(?i)^encrypted\.asc$') { 'PGP/MIME' } else { 'Attachment' }
                        $found.Add([pscustomobject]@{ Kind = $kind; Priority = $(if ($kind -eq 'PGP/MIME') { 0 } else { 1 }); Name = $name; Data = $data; Text = $null; Charset = $null })
                    }
                }
            } finally { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($att) }
        }
        $body = [string]$item.Body
        if ($body -match $PgpMessagePattern) {
            $found.Add([pscustomobject]@{ Kind = 'Inline'; Priority = 2; Name = $null; Data = $null; Text = $body; Charset = 'utf-8' })
        }

        [pscustomobject]@{
            Headers = $headers
            From    = $from
            To      = @($to); Cc = @($cc); Bcc = @($bcc)
            Subject = [string]$item.Subject
            Date    = $date
            Payload = Select-PgpPayload $found
            PayloadCount = $found.Count
        }
    }
    finally {
        try { $item.Close(1) } catch { }   # 1 = olDiscard
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($item)
        $item = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# Outlook returns .NET strings; header handling works on one-char-per-byte text
Function ConvertFrom-OutlookText {
    param([string]$Text)
    $script:Latin1.GetString($script:Utf8.GetBytes($Text))
}

Function Add-SyntheticHeader {
    param($Headers, [string]$Name, [string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return }
    $raw = if ($Name -in 'From', 'To', 'Cc', 'Date') { Format-FoldedHeader $Name $Value } else { New-HeaderLine $Name $Value }
    $Headers.Add([pscustomobject]@{ Name = $Name; Value = $Value; Raw = $raw })
}

# ------------------ GnuPG ------------------
Function ConvertTo-ProcessArgument {
    param([string]$Arg)
    if ($Arg -notmatch '[\s"]' -and $Arg) { return $Arg }
    '"' + ($Arg -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

# Runs gpg against the run's keyring. The passphrase goes in on stdin, never on the command line.
Function Invoke-Gpg {
    param([string[]]$Arguments, [string]$StdIn)
    $common = @('--homedir', $script:GpgHome, '--batch', '--no-tty', '--yes', '--status-fd', '2', '--pinentry-mode', 'loopback')
    if ($null -ne $StdIn) { $common += @('--passphrase-fd', '0') }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $GpgPath
    $psi.Arguments = (@($common + $Arguments) | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardErrorEncoding = $script:Utf8
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = New-Object System.IO.MemoryStream
    $outTask = $p.StandardOutput.BaseStream.CopyToAsync($out)
    $errTask = $p.StandardError.ReadToEndAsync()
    try {
        if ($null -ne $StdIn) {
            $bytes = $script:Utf8.GetBytes($StdIn + "`n")
            $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        $p.StandardInput.Close()
    } catch { }   # gpg may exit before reading stdin; its stderr says why
    $p.WaitForExit()
    $outTask.Wait(); $errTask.Wait()
    [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $out.ToArray(); StdErr = $errTask.Result }
}

Function Get-GpgVersion {
    if (-not (Test-Path -LiteralPath $GpgPath -PathType Leaf)) { throw "gpg.exe was not found at '$GpgPath'. Install Gpg4win or pass -GpgPath." }
    $text = (& $GpgPath --version 2>&1 | Out-String)
    $m = [regex]::Match($text, 'gpg \(GnuPG[^)]*\)\s+(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { throw "'$GpgPath' did not report a GnuPG version. Output: $($text.Trim())" }
    $version = [version]('{0}.{1}.{2}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
    if ($version -lt [version]'2.1.0') { throw "GnuPG $version is too old. Version 2.1 or later is needed for loopback passphrase entry." }
    $version
}

Function New-TempKeyring {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('EchoworxGpg_' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $dir
    if ($script:OnWindows) {
        # Only the current user can read the keyring
        $acl = Get-Acl -LiteralPath $dir
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRule($rule) }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        Set-Acl -LiteralPath $dir -AclObject $acl
    } else {
        & chmod 700 $dir
    }
    Set-Content -LiteralPath (Join-Path $dir 'gpg-agent.conf') -Value 'allow-loopback-pinentry' -Encoding ASCII
    $dir
}

Function Remove-TempKeyring {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return $true }
    $gpgconf = Join-Path (Split-Path -Parent $GpgPath) $(if ($GpgPath -match '(?i)\.exe$') { 'gpgconf.exe' } else { 'gpgconf' })
    if (Test-Path -LiteralPath $gpgconf) {
        try { $null = & $gpgconf --homedir $Dir --kill all 2>&1 } catch { }
    }
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try { Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction Stop; return $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    -not (Test-Path -LiteralPath $Dir)
}

Function Get-GpgErrorLines {
    param([string]$StdErr)
    @($StdErr -split '\r?\n' | Where-Object { $_ -match '^gpg: ' -and $_ -notmatch '^gpg: (encrypted with|\s+")' } | ForEach-Object { $_.Substring(5).Trim() })
}

# Turns gpg's status output into a reason a person can act on
Function Get-GpgFailureReason {
    param($Run, [string]$KeyOwner)
    $err = $Run.StdErr
    $encTo = @([regex]::Matches($err, '\[GNUPG:\] ENC_TO ([0-9A-F]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $keyIds = if ($encTo.Count) { $encTo -join ', ' } else { 'unknown' }
    $gpgSays = (Get-GpgErrorLines $err) -join ' | '
    $reason = if ($err -match 'BAD_PASSPHRASE|Bad passphrase') {
        "Authentication to the private key failed: the passphrase did not unlock the key bundle exported for $KeyOwner (bad passphrase)."
    } elseif ($err -match '\[GNUPG:\] NODATA') {
        'No valid OpenPGP data in the PGP payload. The item is corrupt, truncated, or not really encrypted.'
    } elseif ($err -match '(?i)invalid (armor|packet|radix64)|CRC error|unexpected end|packet\(\d+\) too short|invalid encrypted data|premature eof|malformed') {
        'The PGP payload is corrupt or truncated, so GnuPG could not read it.'
    } elseif ($err -match '\[GNUPG:\] NO_SECKEY' -or $err -match 'No secret key') {
        "No matching private key: the message is encrypted to key ID(s) $keyIds, and the key exported from Echoworx for $KeyOwner is not one of them."
    } elseif ($err -match 'not integrity protected|MDC') {
        'The message uses legacy encryption with no integrity protection (no MDC), which GnuPG refuses to decrypt.'
    } elseif ($err -match '\[GNUPG:\] DECRYPTION_FAILED') {
        'GnuPG could not decrypt the message.'
    } else {
        "GnuPG failed with exit code $($Run.ExitCode)."
    }
    if ($gpgSays) { $reason += " GnuPG said: $gpgSays" }
    $reason
}

Function Import-KeyBundle {
    param([string]$ArmoredKey, [string]$PlainPassphrase, [string]$Owner)
    $file = Join-Path $script:GpgHome ('import_{0}.asc' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($file, $ArmoredKey, $script:Utf8)
    try { $run = Invoke-Gpg -Arguments @('--import', $file) -StdIn $PlainPassphrase }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    $fingerprints = @([regex]::Matches($run.StdErr, '\[GNUPG:\] IMPORT_OK \d+ ([0-9A-F]{40,64})') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $secretRead = [regex]::Match($run.StdErr, '\[GNUPG:\] IMPORT_RES(?: \d+){9} (\d+)')
    if ($fingerprints.Count -eq 0 -or ($secretRead.Success -and [int]$secretRead.Groups[1].Value -eq 0)) {
        $why = (Get-GpgErrorLines $run.StdErr) -join ' | '
        if ($run.StdErr -match 'BAD_PASSPHRASE|Bad passphrase') { throw "GnuPG could not unlock the key bundle exported for ${Owner}: bad passphrase. GnuPG said: $why" }
        throw "GnuPG did not import a private key from the bundle exported for $Owner. GnuPG said: $why"
    }
    Write-RunLog ("Imported key for {0}: {1}" -f $Owner, ($fingerprints -join ', '))
    $fingerprints
}

Function Invoke-GpgDecrypt {
    param([byte[]]$Data, [string]$PlainPassphrase, [string]$KeyOwner)
    $file = Join-Path $script:GpgHome ('payload_{0}.pgp' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllBytes($file, $Data)
    try { $run = Invoke-Gpg -Arguments @('--decrypt', $file) -StdIn $PlainPassphrase }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    # A signature gpg cannot check (no public key for the signer) makes the exit code non-zero
    # even though the message decrypted, so DECRYPTION_OKAY decides
    $ok = ($run.StdErr -match '\[GNUPG:\] DECRYPTION_OKAY') -and ($run.StdErr -notmatch '\[GNUPG:\] DECRYPTION_FAILED') -and $run.Output.Length -gt 0
    $notes = New-Object System.Collections.Generic.List[string]
    if ($ok) {
        if ($run.StdErr -match '\[GNUPG:\] NO_PUBKEY ([0-9A-F]+)') { $notes.Add("Signature not verified: the signer's public key ($($Matches[1])) is not in the keyring.") }
        elseif ($run.StdErr -match '\[GNUPG:\] GOODSIG [0-9A-F]+ (.+)') { $notes.Add("Good signature from $($Matches[1].Trim()).") }
        elseif ($run.StdErr -match '\[GNUPG:\] BADSIG [0-9A-F]+ (.+)') { $notes.Add("WARNING: BAD signature from $($Matches[1].Trim()).") }
    }
    $decryptionKey = $null
    if ($run.StdErr -match '\[GNUPG:\] DECRYPTION_KEY [0-9A-F]+ ([0-9A-F]+)') { $decryptionKey = $Matches[1] }
    [pscustomobject]@{
        Success       = $ok
        Output        = $run.Output
        Reason        = $(if ($ok) { $null } else { Get-GpgFailureReason $run $KeyOwner })
        Notes         = @($notes)
        DecryptionKey = $decryptionKey
        StdErr        = $run.StdErr
    }
}

# ------------------ Echoworx EMG API ------------------
Function Get-EchoworxApiKey {
    param([string]$SecretName, [string]$Vault, [System.Security.SecureString]$UnlockPassword)
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop }
        catch { throw 'The Microsoft.PowerShell.SecretManagement module is not installed. Run: Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser' }
    }
    if ($UnlockPassword) {
        if (-not (Get-Command Unlock-SecretStore -ErrorAction SilentlyContinue)) {
            try { Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop }
            catch { throw 'The Microsoft.PowerShell.SecretStore module is not installed, so the vault cannot be unlocked. Run: Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser' }
        }
        try { Unlock-SecretStore -Password $UnlockPassword -ErrorAction Stop }
        catch { throw ("Could not unlock the SecretStore vault: {0}. Check the vault password." -f $_.Exception.Message) }
    }
    $params = @{ Name = $SecretName; AsPlainText = $true; ErrorAction = 'Stop' }
    if ($Vault) { $params.Vault = $Vault }
    $where = if ($Vault) { "vault '$Vault'" } else { 'the default vault' }
    try { $value = Get-Secret @params }
    catch { throw ("Could not read the API key secret '{0}' from {1}: {2}. If the vault is locked, supply its password." -f $SecretName, $where, $_.Exception.Message) }
    if ($value -is [System.Security.SecureString]) { $value = ConvertTo-PlainText $value }
    if ([string]::IsNullOrWhiteSpace([string]$value)) { throw "The secret '$SecretName' in $where is empty." }
    [string]$value
}

Function Get-HttpClient {
    if ($script:HttpClient) { return $script:HttpClient }
    Add-Type -AssemblyName System.Net.Http
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }
    $script:HttpClient = New-Object System.Net.Http.HttpClient
    $script:HttpClient.Timeout = [TimeSpan]::FromSeconds(90)
    $script:HttpClient
}

# Finds the armored private key in a response, whatever JSON shape it comes in
Function Find-ArmoredPrivateKey {
    param([string]$Body)
    $pattern = '-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----'
    $json = $null
    try { $json = $Body | ConvertFrom-Json -ErrorAction Stop } catch { }
    if ($null -ne $json) {
        $stack = New-Object System.Collections.Stack
        $stack.Push($json)
        while ($stack.Count -gt 0) {
            $node = $stack.Pop()
            if ($node -is [string]) {
                $m = [regex]::Match($node, $pattern)
                if ($m.Success) { return $m.Value }
                if ($node.Length -gt 100 -and $node -match '^[A-Za-z0-9+/=\s]+$') {
                    try {
                        $decoded = $script:Utf8.GetString([Convert]::FromBase64String($node))
                        $m = [regex]::Match($decoded, $pattern)
                        if ($m.Success) { return $m.Value }
                    } catch { }
                }
            } elseif ($node -is [System.Collections.IEnumerable]) {
                foreach ($child in $node) { if ($null -ne $child) { $stack.Push($child) } }
            } elseif ($node -is [psobject]) {
                foreach ($prop in $node.PSObject.Properties) { if ($null -ne $prop.Value) { $stack.Push($prop.Value) } }
            }
        }
    }
    $m = [regex]::Match(($Body -replace '\\r\\n|\\n', "`n"), $pattern)
    if ($m.Success) { return $m.Value }
    $null
}

Function Get-ApiErrorMessage {
    param([string]$Body)
    if (-not $Body) { return '' }
    try {
        $j = $Body | ConvertFrom-Json -ErrorAction Stop
        foreach ($name in 'message', 'error_description', 'error', 'detail', 'title', 'errorMessage') {
            $v = $j.$name
            if ($v -is [string] -and $v) { return $v }
            if ($v -and $v.message) { return [string]$v.message }
        }
    } catch { }
    $text = ($Body -replace '\s+', ' ').Trim()
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
    $text
}

Function Invoke-KeyExport {
    param([string]$Email, [string]$PlainPassphrase)
    $exportProfile = $ProfileName.Replace('{email}', $Email)
    $url = '{0}/profiles/{1}/pgp-key-pair/export' -f $script:BaseUrl.TrimEnd('/'), [uri]::EscapeDataString($exportProfile)
    $client = Get-HttpClient
    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $url)
    $null = $request.Headers.TryAddWithoutValidation('x-echoworx-api-key', $script:ApiKey)
    $null = $request.Headers.TryAddWithoutValidation('Accept', 'application/json')
    $request.Content = New-Object System.Net.Http.StringContent((New-KeyExportBody -EmailAddress $Email -PlainPassphrase $PlainPassphrase), $script:Utf8, 'application/json')
    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } catch {
        $messages = New-Object System.Collections.Generic.List[string]
        $e = $_.Exception
        while ($e) { if ($e.Message -and -not $messages.Contains($e.Message)) { $messages.Add($e.Message) }; $e = $e.InnerException }
        throw ("Could not reach Echoworx at {0}: {1}" -f $url, ($messages -join ' -> '))
    } finally { $request.Dispose() }
    $status = [int]$response.StatusCode
    Write-RunLog ("POST {0} for {1}: HTTP {2}" -f $url, $Email, $status)
    if ($status -ge 200 -and $status -lt 300) {
        $key = Find-ArmoredPrivateKey $body
        if (-not $key) { throw ("Echoworx returned HTTP {0} for {1} but the response held no PGP private key block ({2} characters, {3})." -f $status, $Email, $body.Length, $response.Content.Headers.ContentType) }
        return $key
    }
    $server = Get-ApiErrorMessage $body
    $suffix = if ($server) { " Echoworx said: $server" } else { '' }
    $message = switch ($status) {
        401 { "Authentication failed (HTTP 401): Echoworx rejected the x-echoworx-api-key from secret '$($script:SecretName)'. Check the secret in the vault is the current $Environment key." }
        403 { "Access denied (HTTP 403): the API key is not allowed to export keys for profile '$exportProfile'." }
        404 { "No key found (HTTP 404): Echoworx has no PGP key pair for $Email under profile '$exportProfile'." }
        { $_ -in 400, 422 } { "Echoworx rejected the export request for $Email (HTTP $status)." }
        429 { "Echoworx is rate limiting requests (HTTP 429). Wait and run again." }
        { $_ -ge 500 } { "Echoworx had a server error (HTTP $status) exporting the key for $Email." }
        default { "Echoworx returned HTTP $status ($($response.ReasonPhrase)) exporting the key for $Email." }
    }
    throw ($message + $suffix)
}

# Exports and imports a user's key once per run; failures are cached too, so the API is not asked again
Function Get-UserKey {
    param([string]$Email, [string]$PlainPassphrase)
    $id = $Email.ToLowerInvariant()
    if ($script:KeyCache.ContainsKey($id)) { return $script:KeyCache[$id] }
    try {
        $armored = Invoke-KeyExport -Email $Email -PlainPassphrase $PlainPassphrase
        $fingerprints = Import-KeyBundle -ArmoredKey $armored -PlainPassphrase $PlainPassphrase -Owner $Email
        $armored = $null
        $entry = [pscustomobject]@{ Email = $Email; Ok = $true; Detail = 'Imported'; Fingerprints = $fingerprints }
    } catch {
        Write-RunLog ("Key for {0} unavailable: {1}" -f $Email, $_.Exception.Message) 'ERROR'
        $entry = [pscustomobject]@{ Email = $Email; Ok = $false; Detail = $_.Exception.Message; Fingerprints = @() }
    }
    $script:KeyCache[$id] = $entry
    $script:ApiCalls++
    $entry
}

# ------------------ Rebuilding the decrypted message ------------------
Function Test-MimeEntityText {
    param([string]$Latin1Text)
    $e = Split-MimeEntity $Latin1Text
    ($e.Headers.Count -gt 0) -and ($e.Malformed -eq 0) -and [bool](Get-HeaderValue $e.Headers 'Content-Type')
}

Function ConvertTo-QuotedPrintable {
    param([string]$Text)
    $out = New-Object System.Text.StringBuilder
    $lines = ($Text -replace '\r\n', "`n" -replace '\r', "`n") -split "`n"
    for ($l = 0; $l -lt $lines.Count; $l++) {
        $bytes = $script:Utf8.GetBytes($lines[$l])
        $lineLen = 0
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $b = $bytes[$i]
            $last = ($i -eq $bytes.Length - 1)
            $token = if (($b -ge 33 -and $b -le 126 -and $b -ne 61) -or (($b -eq 32 -or $b -eq 9) -and -not $last)) { [string][char]$b } else { '={0:X2}' -f $b }
            if ($lineLen + $token.Length -gt 75) { $null = $out.Append("=`r`n"); $lineLen = 0 }
            $null = $out.Append($token); $lineLen += $token.Length
        }
        if ($l -lt $lines.Count - 1) { $null = $out.Append("`r`n") }
    }
    $out.ToString()
}

Function Get-ArmorCharset {
    param([string]$Block)
    $m = [regex]::Match($Block, '(?m)^Charset:\s*(\S+)')
    if ($m.Success) { $m.Groups[1].Value } else { 'utf-8' }
}

# Decrypted bytes as a MIME entity: kept as-is when they already are one, otherwise wrapped
Function ConvertTo-InnerEntity {
    param([byte[]]$Bytes, [string]$Name)
    $text = $script:Latin1.GetString($Bytes)
    if (Test-MimeEntityText $text) { return $text }
    $isText = $true
    try { $unicode = $script:Utf8Strict.GetString($Bytes) } catch { $isText = $false }
    if ($isText -and $unicode.IndexOf([char]0) -ge 0) { $isText = $false }
    if ($isText) {
        return "Content-Type: text/plain; charset=utf-8`r`nContent-Transfer-Encoding: quoted-printable`r`n`r`n" + (ConvertTo-QuotedPrintable $unicode)
    }
    $fileName = if ($Name) { $Name -replace '(?i)\.(pgp|gpg|asc)$', '' } else { 'decrypted.bin' }
    if (-not $fileName) { $fileName = 'decrypted.bin' }
    $b64 = [Convert]::ToBase64String($Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $quoted = $fileName -replace '(["\\])', '\$1'
    "Content-Type: application/octet-stream; name=`"$quoted`"`r`nContent-Disposition: attachment; filename=`"$quoted`"`r`nContent-Transfer-Encoding: base64`r`n`r`n" + $b64
}

# Envelope headers from the encrypted message plus the decrypted content
Function New-DecryptedEml {
    param($Message, [string]$InnerEntity, $FallbackDate)
    $inner = Split-MimeEntity $InnerEntity
    $innerNames = @($inner.Headers | ForEach-Object { $_.Name.ToLowerInvariant() })
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($h in $Message.Headers) {
        $n = $h.Name.ToLowerInvariant()
        # Every original header is kept except the outer Content-* ones, which described the PGP wrapper
        if ($n -like 'content-*' -or $n -eq 'mime-version') { continue }
        $lines.Add((Format-OutputHeader $h))
    }
    $outerNames = @($Message.Headers | ForEach-Object { $_.Name.ToLowerInvariant() })
    $haveDate = (Get-HeaderValue $Message.Headers 'Date') -or ($innerNames -contains 'date')
    if (-not $haveDate -and $FallbackDate) { $lines.Add('Date: ' + (Format-Rfc2822Date $FallbackDate)) }
    $lines.Add('MIME-Version: 1.0')
    # The decrypted body brings its own Content-* headers (content type, boundary); any other header it
    # carries is only added when the original message did not have it
    foreach ($h in $inner.Headers) {
        $n = $h.Name.ToLowerInvariant()
        if ($n -eq 'mime-version') { continue }
        if ($n -notlike 'content-*' -and $outerNames -contains $n) { continue }
        $lines.Add((Format-OutputHeader $h))
    }
    $text = ($lines -join "`r`n") + "`r`n`r`n" + $inner.Body
    $text = $text -replace '(?<!\r)\n', "`r`n"
    if (-not $text.EndsWith("`r`n")) { $text += "`r`n" }
    $script:Latin1.GetBytes($text)
}

# Decrypts the payload and returns the reconstructed .eml bytes
Function Invoke-PayloadDecryption {
    param($Message, [string]$KeyOwner, [string]$PlainPassphrase)
    $p = $Message.Payload
    $notes = New-Object System.Collections.Generic.List[string]
    $decryptionKey = $null
    if ($p.Kind -eq 'Inline') {
        $blocks = [regex]::Matches($p.Text, $PgpMessagePattern)
        $sb = New-Object System.Text.StringBuilder
        $pos = 0
        $singleEntity = $null
        foreach ($block in $blocks) {
            $run = Invoke-GpgDecrypt -Data ($script:Utf8.GetBytes($block.Value)) -PlainPassphrase $PlainPassphrase -KeyOwner $KeyOwner
            if (-not $run.Success) { return [pscustomobject]@{ Success = $false; Reason = $run.Reason; StdErr = $run.StdErr } }
            foreach ($n in $run.Notes) { if (-not $notes.Contains($n)) { $notes.Add($n) } }
            if ($run.DecryptionKey) { $decryptionKey = $run.DecryptionKey }
            $plainLatin1 = $script:Latin1.GetString($run.Output)
            if ($blocks.Count -eq 1 -and -not $p.Text.Replace($block.Value, '').Trim() -and (Test-MimeEntityText $plainLatin1)) { $singleEntity = $plainLatin1 }
            $null = $sb.Append($p.Text.Substring($pos, $block.Index - $pos))
            $null = $sb.Append((Get-TextEncoding (Get-ArmorCharset $block.Value)).GetString($run.Output))
            $pos = $block.Index + $block.Length
        }
        $null = $sb.Append($p.Text.Substring($pos))
        $inner = if ($singleEntity) { $singleEntity } else { "Content-Type: text/plain; charset=utf-8`r`nContent-Transfer-Encoding: quoted-printable`r`n`r`n" + (ConvertTo-QuotedPrintable $sb.ToString()) }
        if ($blocks.Count -gt 1) { $notes.Add("$($blocks.Count) inline PGP blocks decrypted.") }
    } else {
        $run = Invoke-GpgDecrypt -Data $p.Data -PlainPassphrase $PlainPassphrase -KeyOwner $KeyOwner
        if (-not $run.Success) { return [pscustomobject]@{ Success = $false; Reason = $run.Reason; StdErr = $run.StdErr } }
        foreach ($n in $run.Notes) { $notes.Add($n) }
        $decryptionKey = $run.DecryptionKey
        $inner = ConvertTo-InnerEntity -Bytes $run.Output -Name $p.Name
    }
    [pscustomobject]@{
        Success = $true
        Bytes = (New-DecryptedEml -Message $Message -InnerEntity $inner -FallbackDate $Message.Date)
        PlainLength = $inner.Length
        Notes = @($notes)
        DecryptionKey = $decryptionKey
    }
}

# ------------------ Per-file processing ------------------
Function Format-AddressSummary {
    param($List)
    (@($List | Where-Object { $_ } | ForEach-Object { $_.Address }) -join '; ')
}

Function Invoke-FileDecryption {
    param([System.IO.FileInfo]$File, [string[]]$Domains, [string]$PlainPassphrase)
    $row = [ordered]@{
        Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); File = $File.Name; Format = $File.Extension.TrimStart('.').ToLowerInvariant()
        Result = 'Failed'; Sender = ''; Recipients = ''; Subject = ''; InternalUser = ''; PgpFormat = ''; Output = ''; Detail = ''
    }
    $gpgDetail = $null
    try {
        $message = if ($row.Format -eq 'msg') { Read-MsgMessage -Path $File.FullName -WorkFolder $script:GpgHome } else { Read-EmlMessage -Path $File.FullName }
        $row.Sender = Format-AddressSummary @($message.From)
        $row.Recipients = Format-AddressSummary (@($message.To) + @($message.Cc) + @($message.Bcc))
        $row.Subject = [string]$message.Subject

        if (-not $message.Payload) {
            $row.Result = 'Not Encrypted'
            $row.Output = Move-ToFolder $File.FullName $script:NotEncryptedDir
            $row.Detail = 'No PGP/MIME part, message.pgp attachment or inline PGP block was found.'
            return [pscustomobject]$row
        }
        $row.PgpFormat = if ($message.Payload.Kind -eq 'Attachment') { 'Attachment ({0})' -f $message.Payload.Name } else { $message.Payload.Kind }

        # Internal recipients first (inbound mail), then an internal sender (sent items)
        $recipients = @(@($message.To) + @($message.Cc) + @($message.Bcc) | Where-Object { $_ -and $_.Address })
        $candidates = @(@($recipients | Where-Object { Test-InternalAddress $_.Address $Domains }) + @(@($message.From) | Where-Object { $_ -and $_.Address -and (Test-InternalAddress $_.Address $Domains) }) |
            ForEach-Object { $_.Address.Trim() } | Select-Object -Unique)
        if ($candidates.Count -eq 0) {
            throw ("No participant matches a domain in InternalDomains.csv, so there is no Echoworx profile owner to fetch a key for. From: {0}. Recipients: {1}." -f $(if ($row.Sender) { $row.Sender } else { 'none' }), $(if ($row.Recipients) { $row.Recipients } else { 'none' }))
        }

        $errors = New-Object System.Collections.Generic.List[string]
        $result = $null
        foreach ($user in $candidates) {
            $key = Get-UserKey -Email $user -PlainPassphrase $PlainPassphrase
            if (-not $key.Ok) { $errors.Add("${user}: $($key.Detail)"); continue }
            $attempt = Invoke-PayloadDecryption -Message $message -KeyOwner $user -PlainPassphrase $PlainPassphrase
            if ($attempt.Success) {
                $owner = $user
                if ($attempt.DecryptionKey) {
                    foreach ($k in $script:KeyCache.Values) { if ($k.Ok -and $k.Fingerprints -contains $attempt.DecryptionKey) { $owner = $k.Email } }
                }
                $row.InternalUser = $owner
                $result = $attempt
                break
            }
            $errors.Add("${user}: $($attempt.Reason)")
            $gpgDetail = $attempt.StdErr
        }
        if (-not $result) {
            $row.InternalUser = $candidates -join '; '
            throw ($errors -join ' || ')
        }

        if (-not (Test-Path -LiteralPath $script:SuccessDir)) { $null = New-Item -ItemType Directory -Path $script:SuccessDir }
        $outPath = Get-UniquePath $script:SuccessDir ([System.IO.Path]::GetFileNameWithoutExtension($File.Name) + '.eml')
        [System.IO.File]::WriteAllBytes($outPath, $result.Bytes)

        # Only delete the encrypted original once the output is on disk and not empty
        $written = Get-Item -LiteralPath $outPath -ErrorAction SilentlyContinue
        if (-not $written -or $written.Length -eq 0 -or $result.PlainLength -le 0) {
            Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue
            throw 'Decryption produced an empty message, so the encrypted original was kept.'
        }
        Remove-Item -LiteralPath $File.FullName -Force
        $row.Result = 'Decrypted'
        $row.Output = $outPath
        $detail = @('Decrypted with the key for {0}.' -f $row.InternalUser) + @($result.Notes)
        if ($message.PayloadCount -gt 1) { $detail += ('{0} PGP payloads found; the {1} one was used.' -f $message.PayloadCount, $message.Payload.Kind) }
        $row.Detail = $detail -join ' '
    }
    catch {
        $row.Result = 'Failed'
        $row.Detail = $_.Exception.Message
        try { $row.Output = Move-ToFolder $File.FullName $script:FailedDir }
        catch { $row.Detail += (' Moving the original to Failed also failed: {0}' -f $_.Exception.Message) }
        if ($gpgDetail) { Write-RunLog ("GnuPG output for {0}:`r`n{1}" -f $File.Name, $gpgDetail.Trim()) 'ERROR' }
    }
    [pscustomobject]$row
}

# ------------------ Main ------------------
# Dot-sourcing loads the functions only (used by the tests)
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not $SourceFolder) { throw 'Pass -SourceFolder: the folder holding the .eml / .msg files to decrypt.' }
if (-not (Test-Path -LiteralPath $SourceFolder -PathType Container)) { throw "The source folder '$SourceFolder' does not exist." }
$SourceFolder = (Resolve-Path -LiteralPath $SourceFolder).ProviderPath
if (-not $EchoworxEnvironments.Contains($Environment)) { throw ("Unknown environment '{0}'. Known: {1}" -f $Environment, ($EchoworxEnvironments.Keys -join ', ')) }
$envConfig = $EchoworxEnvironments[$Environment]
$script:BaseUrl = if ($ApiBaseUrl) { $ApiBaseUrl } else { $envConfig.BaseUrl }
$script:SecretName = $envConfig.SecretName
if (-not $InternalDomainsPath) { $InternalDomainsPath = Join-Path $PSScriptRoot 'InternalDomains.csv' }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:CsvPath = Join-Path $SourceFolder ("EchoworxDecryption_{0}.csv" -f $stamp)
$script:RunLogPath = Join-Path $SourceFolder ("EchoworxDecryption_{0}.log" -f $stamp)
$script:SuccessDir = Join-Path $SourceFolder 'Successful'
$script:FailedDir = Join-Path $SourceFolder 'Failed'
$script:NotEncryptedDir = Join-Path $SourceFolder 'Not Encrypted'
$script:KeyCache = @{}
$script:ApiCalls = 0
$script:GpgHome = $null

Write-RunLog ("Run started: source '{0}', environment {1} ({2}), profile '{3}', gpg '{4}'" -f $SourceFolder, $Environment, $script:BaseUrl, $ProfileName, $GpgPath)
$domains = Read-InternalDomains $InternalDomainsPath
Write-RunLog ("Internal domains: {0}" -f ($domains -join ', '))
$gpgVersion = Get-GpgVersion
Write-RunLog ("GnuPG {0}" -f $gpgVersion)

$files = @(Get-ChildItem -LiteralPath $SourceFolder -File | Where-Object { $_.Extension -in '.eml', '.msg' } | Sort-Object Name)
$msgCount = @($files | Where-Object { $_.Extension -eq '.msg' }).Count
if ($msgCount -gt 0 -and (Test-OutlookRunning)) {
    $warning = "Outlook is already running. $msgCount .msg file(s) are read through Outlook COM automation, which may fail while Outlook is open (especially if Outlook and this script run at different elevation levels). Close Outlook before continuing for reliable results."
    Write-Warning $warning
    Write-RunLog $warning 'WARN'
    if (-not $Force) {
        $answer = Read-Host 'Continue anyway? [Y/N]'
        if ($answer -notmatch '^(y|yes)$') { Write-RunLog 'Stopped: Outlook was running.' 'WARN'; throw 'Stopped because Outlook is running. Close Outlook and run again, or pass -Force.' }
    }
}

$results = New-Object System.Collections.Generic.List[object]
$generated = $false
$plainPassphrase = $null
$cleanedUp = $true
$stopped = $false
try {
    if ($files.Count -gt 0) {
        $script:ApiKey = Get-EchoworxApiKey -SecretName $script:SecretName -Vault $VaultName -UnlockPassword $VaultPassword
        if (-not $Passphrase) { $Passphrase = New-RandomPassphrase; $generated = $true }
        $plainPassphrase = ConvertTo-PlainText $Passphrase
        $script:GpgHome = New-TempKeyring
        Write-RunLog ("Temporary keyring created. Passphrase: {0}" -f $(if ($generated) { 'random, generated for this run only' } else { 'supplied' }))
    }
    $i = 0
    foreach ($file in $files) {
        if ($Progress) {
            if ($Progress.Cancel) { $stopped = $true; Write-RunLog 'Stopped by the user before all files were processed.' 'WARN'; break }
            $Progress.Progress = [pscustomobject]@{ Done = $i; Total = $files.Count; Unit = 'files' }
        }
        $i++
        if (-not $Quiet) { Write-Progress -Activity 'Decrypting messages' -Status $file.Name -PercentComplete ([int](100 * ($i - 1) / $files.Count)) }
        $row = Invoke-FileDecryption -File $file -Domains $domains -PlainPassphrase $plainPassphrase
        $results.Add($row)
        $row | Export-Csv -LiteralPath $script:CsvPath -NoTypeInformation -Append -Encoding UTF8
        $level = if ($row.Result -eq 'Failed') { 'ERROR' } else { 'INFO' }
        Write-RunLog ("{0} | {1} | {2} | {3} | {4}" -f $row.File, $row.Result, $row.InternalUser, $row.PgpFormat, $row.Detail) $level
        if ($ResultQueue) { $ResultQueue.Enqueue($row) }
    }
    if ($Progress) { $Progress.Progress = [pscustomobject]@{ Done = $i; Total = $files.Count; Unit = 'files' } }
}
finally {
    if (-not $Quiet) { Write-Progress -Activity 'Decrypting messages' -Completed }
    Close-Outlook
    if ($script:GpgHome) {
        $cleanedUp = Remove-TempKeyring $script:GpgHome
        if ($cleanedUp) { Write-RunLog 'Temporary keyring and imported private keys deleted.' }
        else { Write-RunLog ("Could not delete the temporary keyring at {0}. Delete it by hand: it holds private keys." -f $script:GpgHome) 'ERROR' }
    }
    $plainPassphrase = $null
    $script:ApiKey = $null
    if ($script:HttpClient) { $script:HttpClient.Dispose(); $script:HttpClient = $null }
}

if ($results.Count -eq 0) {
    $null = New-Item -ItemType File -Path $script:CsvPath -Force
    Set-Content -LiteralPath $script:CsvPath -Value '"Time","File","Format","Result","Sender","Recipients","Subject","InternalUser","PgpFormat","Output","Detail"' -Encoding UTF8
}

$summary = [pscustomobject]@{
    SourceFolder = $SourceFolder
    Total        = $files.Count
    Processed    = $results.Count
    Decrypted    = @($results | Where-Object { $_.Result -eq 'Decrypted' }).Count
    NotEncrypted = @($results | Where-Object { $_.Result -eq 'Not Encrypted' }).Count
    Failed       = @($results | Where-Object { $_.Result -eq 'Failed' }).Count
    KeysFetched  = @($script:KeyCache.Values | Where-Object { $_.Ok }).Count
    ApiCalls     = $script:ApiCalls
    Stopped      = $stopped
    KeyringDeleted = $cleanedUp
    PassphraseGenerated = $generated
    CsvPath      = $script:CsvPath
    LogPath      = $script:RunLogPath
    Results      = $results.ToArray()
}
Write-RunLog ("Run finished: {0} decrypted, {1} not encrypted, {2} failed, {3} of {4} files processed, {5} Echoworx key request(s)." -f $summary.Decrypted, $summary.NotEncrypted, $summary.Failed, $summary.Processed, $summary.Total, $summary.ApiCalls)

if (-not $Quiet) {
    Write-Host ''
    Write-Host 'Echoworx PGP decryption summary' -ForegroundColor Cyan
    Write-Host ('  Source folder   : {0}' -f $SourceFolder)
    Write-Host ('  Files found     : {0}' -f $summary.Total)
    Write-Host ('  Decrypted       : {0}  (Successful)' -f $summary.Decrypted) -ForegroundColor Green
    Write-Host ('  Not encrypted   : {0}  (Not Encrypted)' -f $summary.NotEncrypted) -ForegroundColor Yellow
    Write-Host ('  Failed          : {0}  (Failed)' -f $summary.Failed) -ForegroundColor $(if ($summary.Failed) { 'Red' } else { 'Gray' })
    Write-Host ('  Keys requested  : {0} user(s), {1} imported' -f $summary.ApiCalls, $summary.KeysFetched)
    Write-Host ('  CSV log         : {0}' -f $summary.CsvPath)
    Write-Host ('  Detailed log    : {0}' -f $summary.LogPath)
    if ($stopped) { Write-Host '  Stopped before every file was processed.' -ForegroundColor Yellow }
    if (-not $cleanedUp) { Write-Host ('  WARNING: the temporary keyring could not be deleted. Delete {0} by hand.' -f $script:GpgHome) -ForegroundColor Red }
    $failures = @($results | Where-Object { $_.Result -eq 'Failed' })
    if ($failures.Count) {
        Write-Host ''
        Write-Host 'Failures' -ForegroundColor Red
        foreach ($f in $failures) { Write-Host ('  {0}: {1}' -f $f.File, $f.Detail) }
    }
    Write-Host ''
}
$summary
