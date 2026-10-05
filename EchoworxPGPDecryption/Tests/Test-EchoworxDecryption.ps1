<#
.SYNOPSIS
    End-to-end tests for Invoke-EchoworxDecryption.ps1 against a local mock of the Echoworx EMG API.

.DESCRIPTION
    Builds throwaway PGP keys and test messages, starts a mock export endpoint on 127.0.0.1, and
    runs the decryption script over the messages. Nothing contacts the real Echoworx service:
    -ApiBaseUrl points every request at the mock, and Get-Secret / Unlock-SecretStore are replaced
    with test functions so no real vault is touched.

.EXAMPLE
    .\Tests\Test-EchoworxDecryption.ps1 -GpgPath 'C:\Program Files\GnuPG\bin\gpg.exe'
#>
[CmdletBinding()]
param(
    [string]$GpgPath = $(if ($IsLinux -or $IsMacOS) { (Get-Command gpg -ErrorAction SilentlyContinue).Source } else { 'C:\Program Files\GnuPG\bin\gpg.exe' }),
    [switch]$KeepWorkFolder
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path (Split-Path -Parent $here) 'Invoke-EchoworxDecryption.ps1'
$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
$utf8 = New-Object System.Text.UTF8Encoding($false)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('EchoworxTests_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work
# Load the script's functions for the helper checks. Dot-sourcing binds its parameters here too, so keep ours.
$keepGpg = $GpgPath; . $script; $GpgPath = $keepGpg
$gpgconf = Join-Path (Split-Path -Parent $GpgPath) $(if ($GpgPath -match '(?i)\.exe$') { 'gpgconf.exe' } else { 'gpgconf' })

$script:Passed = 0; $script:FailedTests = New-Object System.Collections.Generic.List[string]
Function Assert {
    param([bool]$Condition, [string]$Name, [string]$Info = '')
    if ($Condition) { $script:Passed++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:FailedTests.Add($Name); Write-Host "  FAIL  $Name $Info" -ForegroundColor Red }
}

Function New-Home([string]$Name) {
    $dir = Join-Path $work $Name
    $null = New-Item -ItemType Directory -Path $dir -Force
    if (-not $onWindows) { & chmod 700 $dir }
    $dir
}
Function Invoke-TestGpg { param([string]$HomeDir, [string[]]$GpgArgs) & $GpgPath --homedir $HomeDir --batch --yes @GpgArgs 2>&1 | Out-Null; if ($LASTEXITCODE) { throw "gpg $($GpgArgs -join ' ') failed" } }

# ------------------ Keys ------------------
Write-Host 'Generating test keys...' -ForegroundColor Cyan
$keyStore = New-Home 'echoworx-keystore'   # what the mock Echoworx "holds": one unprotected keyring per user
$sender = New-Home 'sender'                # public keys of everyone, plus the external signer's secret key
$orphan = New-Home 'orphan'                # carol's key: messages get encrypted to it, Echoworx never has it
Function New-TestKey([string]$HomeDir, [string]$Uid) {
    Invoke-TestGpg $HomeDir @('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-gen-key', $Uid, 'rsa2048', 'sign', 'never')
    $fpr = ((& $GpgPath --homedir $HomeDir --with-colons --list-keys $Uid) | Where-Object { $_ -like 'fpr:*' } | Select-Object -First 1).Split(':')[9]
    Invoke-TestGpg $HomeDir @('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', $fpr, 'rsa2048', 'encr', 'never')
}
foreach ($user in 'alice@lloydsbanking.com', 'bob@lloydsbanking.com', 'dan@lloydsbanking.com') {
    $h = New-Home (Join-Path 'echoworx-keystore' $user)
    New-TestKey $h "Test User <$user>"
    & $GpgPath --homedir $h --armor --export $user 2>$null | Set-Content -LiteralPath (Join-Path $work "$user.pub.asc")
    Invoke-TestGpg $sender @('--import', (Join-Path $work "$user.pub.asc"))
    $null = & $gpgconf --homedir $h --kill all 2>&1
}
New-TestKey $orphan 'Carol <carol@lloydsbanking.com>'
& $GpgPath --homedir $orphan --armor --export carol@lloydsbanking.com 2>$null | Set-Content -LiteralPath (Join-Path $work 'carol.pub.asc')
Invoke-TestGpg $sender @('--import', (Join-Path $work 'carol.pub.asc'))
New-TestKey $sender 'Exter Nal <ext@example.com>'

Function Protect-TestData {
    param([byte[]]$Data, [string[]]$To, [switch]$Armor, [switch]$Sign)
    $in = Join-Path $work ('in_' + [guid]::NewGuid().ToString('N'))
    $out = "$in.pgp"
    [System.IO.File]::WriteAllBytes($in, $Data)
    $a = @('--trust-model', 'always', '--output', $out)
    if ($Armor) { $a += '--armor' }
    foreach ($r in $To) { $a += @('--recipient', $r) }
    if ($Sign) { $a += @('--local-user', 'ext@example.com', '--sign') }
    $a += @('--encrypt', $in)
    Invoke-TestGpg $sender $a
    $bytes = [System.IO.File]::ReadAllBytes($out)
    Remove-Item -LiteralPath $in, $out
    ,$bytes
}

# ------------------ Messages ------------------
Write-Host 'Building test messages...' -ForegroundColor Cyan
$src = New-Home 'source'
Function Save-Eml([string]$Name, [string]$Text) {
    $Text = $Text -replace '(?<!\r)\n', "`r`n"
    [System.IO.File]::WriteAllBytes((Join-Path $src $Name), $utf8.GetBytes($Text))
}
Function ConvertTo-B64Lines([byte[]]$b) { [Convert]::ToBase64String($b, [System.Base64FormattingOptions]::InsertLineBreaks) }

$innerMixed = @"
Content-Type: multipart/mixed; boundary="inner-b"

--inner-b
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

The Q3 numbers are attached. Ünïcödé body.
--inner-b
Content-Type: text/csv; name="figures.csv"
Content-Disposition: attachment; filename="figures.csv"
Content-Transfer-Encoding: base64

$(ConvertTo-B64Lines $utf8.GetBytes("Quarter,Total`r`nQ3,42`r`n"))
--inner-b--
"@ -replace '(?<!\r)\n', "`r`n"
$pgpMimeArmor = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes($innerMixed) -To 'alice@lloydsbanking.com' -Armor -Sign))

Function New-PgpMimeEml([string]$From, [string]$To, [string]$Subject, [string]$Date, [string]$Armor, [string]$Extra = '') {
@"
Received: from mx.example.com by mx.lloydsbanking.com; Thu, 1 Oct 2026 09:30:05 +0100
From: $From
To: $To
Subject: $Subject
Date: $Date
Message-ID: <$([guid]::NewGuid())@example.com>
$Extra
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";
 boundary="outer-boundary"

This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)
--outer-boundary
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

--outer-boundary
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

$Armor
--outer-boundary--
"@ -replace "(?m)^\r?\n(?=MIME-Version)", ''
}

Save-Eml '01_pgpmime.eml' (New-PgpMimeEml '"Exter Nal" <ext@example.com>' '"Alice Smith" <alice@lloydsbanking.com>' 'Résumé – Q3 figures' '2026-10-01T09:30:00+01:00' $pgpMimeArmor)

$innerFull = @"
From: "Exter Nal" <ext@example.com>
To: bob@lloydsbanking.com
Subject: Inner subject from message.pgp
Content-Type: text/html; charset=utf-8

<html><body><p>Hello Bob, this came out of message.pgp.</p></body></html>
"@ -replace '(?<!\r)\n', "`r`n"
$binaryPgp = Protect-TestData -Data $utf8.GetBytes($innerFull) -To 'bob@lloydsbanking.com'
Save-Eml '02_messagepgp.eml' @"
From: Exter Nal <ext@example.com>
To: Bob <bob@lloydsbanking.com>
Subject: Secure message
Date: Thu, 01 Oct 2026 10:00:00 +0100
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix"

--mix
Content-Type: text/plain; charset=us-ascii

You have received a secure message. Open the attached message.pgp.
--mix
Content-Type: application/octet-stream; name="message.pgp"
Content-Disposition: attachment; filename="message.pgp"
Content-Transfer-Encoding: base64

$(ConvertTo-B64Lines $binaryPgp)
--mix--
"@

$inlineArmor = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes("Meet at the café at 3pm.`nBring the file.") -To 'alice@lloydsbanking.com' -Armor))
$inlineQp = ("Hello Alice,`n`n" + $inlineArmor.Trim() + "`n`nRegards =E2=80=94 Ext") -replace '(?<!\r)\n', "`r`n"
Save-Eml '03_inline.eml' @"
From: ext@example.com
To: alice@lloydsbanking.com
Subject: =?utf-8?Q?Inline_caf=C3=A9?=
Date: Thu, 01 Oct 2026 11:00:00 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

$inlineQp
"@

Save-Eml '04_plain.eml' @"
From: ext@example.com
To: alice@lloydsbanking.com
Subject: Lunch?
Date: Thu, 01 Oct 2026 12:00:00 +0100
Content-Type: text/plain

Nothing secret here.
"@

$carolArmor = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes('for carol') -To 'carol@lloydsbanking.com' -Armor))
Save-Eml '05_nokey.eml' (New-PgpMimeEml 'ext@example.com' 'carol@lloydsbanking.com' 'For Carol' 'Thu, 01 Oct 2026 13:00:00 +0100' $carolArmor)

$corrupt = $inlineArmor -replace '(?m)^([A-Za-z0-9+/]{20})[A-Za-z0-9+/]{20}', '$1AAAAAAAAAAAAAAAAAAAA'
Save-Eml '06_corrupt.eml' @"
From: ext@example.com
To: alice@lloydsbanking.com
Subject: Corrupt
Date: Thu, 01 Oct 2026 14:00:00 +0100
Content-Type: text/plain

$corrupt
"@

$extArmor = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes('external only') -To 'ext@example.com' -Armor))
Save-Eml '07_external.eml' (New-PgpMimeEml 'ext@example.com' 'someone@example.org' 'External only' 'Thu, 01 Oct 2026 15:00:00 +0100' $extArmor)

$alice2 = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes("Content-Type: text/plain; charset=utf-8`r`n`r`nSecond message for Alice.") -To 'alice@lloydsbanking.com' -Armor))
Save-Eml '08_alice_again.eml' (New-PgpMimeEml 'ext@example.com' 'alice@lloydsbanking.com' 'Second for Alice' 'Thu, 01 Oct 2026 16:00:00 +0100' $alice2 'X-Mailer: TestMailer 1.0')

$outbound = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes("Content-Type: text/plain`r`n`r`nOutbound from Alice.") -To 'ext@example.com', 'alice@lloydsbanking.com' -Armor))
Save-Eml '09_outbound.eml' (New-PgpMimeEml '"Smith, Alice" <alice@lloydsbanking.com>' 'ext@example.com' 'Outbound' 'Thu, 01 Oct 2026 17:00:00 +0100' $outbound 'Cc: Dave <dave@external.net>')

$htmlArmor = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes('HTML inline secret') -To 'bob@lloydsbanking.com' -Armor))
$htmlBody = '<html><body><p>Hi Bob</p><p>' + (($htmlArmor.Trim() -split '\r?\n') -join '<br>') + '</p></body></html>'
Save-Eml '10_html_inline.eml' @"
From: ext@example.com
To: bob@lloydsbanking.com
Subject: HTML inline
Date: Thu, 01 Oct 2026 18:00:00 +0100
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

$htmlBody
"@

$danWrong = $utf8.GetString((Protect-TestData -Data $utf8.GetBytes('to carol, addressed to dan') -To 'carol@lloydsbanking.com' -Armor))
Save-Eml '11_wrongkey.eml' (New-PgpMimeEml 'ext@example.com' 'dan@lloydsbanking.com' 'Wrong key' 'Thu, 01 Oct 2026 19:00:00 +0100' $danWrong)

Save-Eml '12_not_an_email.eml' "this is just some text`nwith no headers at all`n"

Copy-Item -LiteralPath (Join-Path $src '08_alice_again.eml') -Destination (Join-Path $src '[13] brackets & spaces.eml')

$domainsCsv = Join-Path $work 'InternalDomains.csv'
Set-Content -LiteralPath $domainsCsv -Value @('Domain', 'lloydsbanking.com', '@lloydsbanking.co.uk') -Encoding UTF8
$pristine = New-Home 'pristine'
Copy-Item -Path (Join-Path $src '*') -Destination $pristine

# ------------------ Mock Echoworx EMG API ------------------
$probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
$state = [hashtable]::Synchronized(@{ ApiKey = 'test-api-key-123'; KeyStore = $keyStore; Gpg = $GpgPath; GpgConf = $gpgconf; Calls = [hashtable]::Synchronized(@{}); Paths = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)); Stop = $false; Ready = $false; Error = $null })
$mock = [powershell]::Create()
$null = $mock.AddScript({
    param($Port, $State)
    $ErrorActionPreference = 'Stop'
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $State.Ready = $true
        while (-not $State.Stop) {
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 30; continue }
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $false, 65536, $true)
                $requestLine = $reader.ReadLine()
                $headers = @{}
                while (($line = $reader.ReadLine())) { $i = $line.IndexOf(':'); $headers[$line.Substring(0, $i).Trim().ToLower()] = $line.Substring($i + 1).Trim() }
                $len = [int]$headers['content-length']
                # Content-Length counts bytes; read characters until that many UTF-8 bytes have arrived
                $sb = New-Object System.Text.StringBuilder; $one = New-Object char[] 1
                while ([System.Text.Encoding]::UTF8.GetByteCount($sb.ToString()) -lt $len -and $reader.Read($one, 0, 1) -gt 0) { $null = $sb.Append($one[0]) }
                $body = $sb.ToString()
                $method, $path = $requestLine.Split(' ')[0, 1]
                $path = [uri]::UnescapeDataString($path)
                $null = $State.Paths.Add("$method $path")
                $status = 200; $reply = $null
                $route = [regex]::Match($path, '^/profiles/([^/]+)/pgp-key-pair/export$')
                if ($method -ne 'POST' -or -not $route.Success) { $status = 404; $reply = '{"message":"Unknown route"}' }
                elseif ($headers['x-echoworx-api-key'] -ne $State.ApiKey) { $status = 401; $reply = '{"error":{"message":"Invalid API key"}}' }
                else {
                    $req = $body | ConvertFrom-Json
                    $email = $route.Groups[1].Value   # the profile name is the user's email address
                    $State.Calls[$email] = 1 + [int]$State.Calls[$email]
                    $userHome = Join-Path $State.KeyStore $email
                    if (-not $req.passphrase) { $status = 400; $reply = '{"message":"passphrase is required"}' }
                    elseif (-not (Test-Path -LiteralPath $userHome)) { $status = 404; $reply = ('{{"message":"No PGP key pair found for profile owner {0}"}}' -f $email) }
                    else {
                        # Re-protect a copy of the user's key with the requested transit passphrase, as Echoworx does
                        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('mockgpg_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                        $null = New-Item -ItemType Directory -Path $tmp
                        Copy-Item -Path (Join-Path $userHome '*') -Destination $tmp -Recurse -Exclude 'S.*'
                        $pass = [string]$req.passphrase
                        $null = $pass | & $State.Gpg --homedir $tmp --batch --pinentry-mode loopback --passphrase-fd 0 --passwd $email 2>&1
                        $armored = ($pass | & $State.Gpg --homedir $tmp --batch --pinentry-mode loopback --passphrase-fd 0 --armor --export-secret-keys $email 2>$null) -join "`n"
                        $null = & $State.GpgConf --homedir $tmp --kill all 2>&1
                        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
                        $reply = @{ profileName = $email; owner = $email; keyPair = @{ privateKey = $armored; format = 'armored' } } | ConvertTo-Json -Depth 5
                    }
                }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($reply)
                $reason = @{ 200 = 'OK'; 400 = 'Bad Request'; 401 = 'Unauthorized'; 404 = 'Not Found' }[$status]
                $head = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $status $reason`r`nContent-Type: application/json`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
                $stream.Write($head, 0, $head.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
            } catch { $State.Error = $_.Exception.Message } finally { $client.Close() }
        }
        $listener.Stop()
    } catch { $State.Error = $_.Exception.Message; $State.Ready = $true }
}).AddArgument($port).AddArgument($state)
$mockHandle = $mock.BeginInvoke()
while (-not $state.Ready) { Start-Sleep -Milliseconds 50 }
if ($state.Error) { throw "Mock server failed: $($state.Error)" }
$mockUrl = "http://127.0.0.1:$port"
Write-Host "Mock Echoworx API on $mockUrl" -ForegroundColor Cyan

# Stand-ins for the SecretManagement cmdlets: the vault is locked until unlocked with 'vault-pass'
$global:TestVault = @{ Unlocked = $false; Secret = 'test-api-key-123'; Reads = 0 }
Function global:Unlock-SecretStore {
    param([System.Security.SecureString]$Password)
    $plain = [System.Net.NetworkCredential]::new('', $Password).Password
    if ($plain -ne 'vault-pass') { throw 'The provided password is incorrect.' }
    $global:TestVault.Unlocked = $true
}
Function global:Get-Secret {
    param([string]$Name, [string]$Vault, [switch]$AsPlainText)
    if (-not $global:TestVault.Unlocked) { throw 'A valid password is required to access the Microsoft.PowerShell.SecretStore vault.' }
    if ($Name -ne 'EchoworxApiKey') { throw "The secret $Name was not found." }
    $global:TestVault.Reads++
    $global:TestVault.Secret
}
$vaultPass = ConvertTo-SecureString 'vault-pass' -AsPlainText -Force

Function Reset-Source {
    Get-ChildItem -LiteralPath $src -Force | Remove-Item -Recurse -Force
    Copy-Item -Path (Join-Path $pristine '*') -Destination $src
    $state.Calls.Clear(); $state.Paths.Clear()
    $global:TestVault.Unlocked = $false
}
Function Get-TempKeyrings { @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'EchoworxGpg_*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
Function Get-Row($summary, [string]$file) { $summary.Results | Where-Object { $_.File -eq $file } }
Function Read-Out([string]$name) { [System.Text.Encoding]::GetEncoding(28591).GetString([System.IO.File]::ReadAllBytes((Join-Path $src "Successful\$name"))) }

try {
    # ------------------ Run 1: everything, random passphrase ------------------
    Write-Host "`nRun 1: full folder, random passphrase" -ForegroundColor Cyan
    $before = Get-TempKeyrings
    $s = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -VaultPassword $vaultPass -Quiet
    $after = Get-TempKeyrings

    Assert ($s.Total -eq 13) 'all 13 files found' "got $($s.Total)"
    Assert ($s.PassphraseGenerated) 'random passphrase generated when none supplied'
    foreach ($ok in '01_pgpmime.eml', '02_messagepgp.eml', '03_inline.eml', '08_alice_again.eml', '09_outbound.eml', '10_html_inline.eml', '[13] brackets & spaces.eml') {
        $r = Get-Row $s $ok
        Assert ($r.Result -eq 'Decrypted') "$ok decrypted" "($($r.Result): $($r.Detail))"
        Assert (-not (Test-Path -LiteralPath (Join-Path $src $ok))) "$ok encrypted original deleted"
    }
    Assert ((Get-Row $s '04_plain.eml').Result -eq 'Not Encrypted') '04 plain moved to Not Encrypted'
    Assert (Test-Path -LiteralPath (Join-Path $src 'Not Encrypted\04_plain.eml')) '04 is in the Not Encrypted folder'
    $r = Get-Row $s '05_nokey.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'No key found \(HTTP 404\)' -and $r.Detail -match 'carol@lloydsbanking.com') '05 fails with a verbose no-key error' $r.Detail
    $r = Get-Row $s '06_corrupt.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'corrupt|No valid OpenPGP') '06 fails as corrupt' $r.Detail
    $r = Get-Row $s '07_external.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'InternalDomains.csv') '07 fails: no internal participant' $r.Detail
    $r = Get-Row $s '11_wrongkey.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'No matching private key' -and $r.Detail -match 'key ID') '11 fails: key does not match' $r.Detail
    $r = Get-Row $s '12_not_an_email.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'no message headers') '12 fails: not an email' $r.Detail
    foreach ($f in '05_nokey.eml', '06_corrupt.eml', '07_external.eml', '11_wrongkey.eml', '12_not_an_email.eml') {
        Assert (Test-Path -LiteralPath (Join-Path $src "Failed\$f")) "$f moved to Failed"
    }
    Assert ($state.Calls['alice@lloydsbanking.com'] -eq 1) 'alice key requested once for 5 messages' "calls: $($state.Calls['alice@lloydsbanking.com'])"
    Assert ($state.Calls['bob@lloydsbanking.com'] -eq 1) 'bob key requested once for 2 messages'
    Assert ($state.Calls['carol@lloydsbanking.com'] -eq 1) 'failed carol lookup cached (one call)'
    Assert ($s.ApiCalls -eq 4) 'four key requests in total' "got $($s.ApiCalls)"
    Assert (@($state.Paths | Where-Object { $_ -notmatch '^POST /profiles/[^/@]+@lloydsbanking\.com/pgp-key-pair/export$' }).Count -eq 0) 'every request was POST /profiles/{user email}/pgp-key-pair/export' ($state.Paths -join '; ')
    Assert ($global:TestVault.Reads -eq 1) 'API key read from the vault once'
    Assert ((Get-Row $s '09_outbound.eml').InternalUser -eq 'alice@lloydsbanking.com') '09 outbound uses the internal sender'
    Assert ((Get-Row $s '01_pgpmime.eml').Detail -match 'Signature not verified') '01 notes the unverifiable signature'
    Assert ((Get-Row $s '02_messagepgp.eml').PgpFormat -eq 'Attachment (message.pgp)') '02 payload found as message.pgp'
    Assert ((Get-Row $s '03_inline.eml').PgpFormat -eq 'Inline') '03 payload found inline'

    $o1 = Read-Out '01_pgpmime.eml'
    Assert ($o1 -match '(?m)^Subject: =\?utf-8\?B\?') '01 raw 8-bit subject is RFC 2047 encoded'
    Assert ($o1 -match '(?m)^Date: Thu, 01 Oct 2026 09:30:00 \+0100\r$') '01 ISO date rewritten as RFC 2822' (([regex]::Match($o1, '(?m)^Date:.*')).Value)
    Assert ($o1 -notmatch 'multipart/encrypted' -and $o1 -match 'figures.csv' -and $o1 -match 'Received: from mx.example.com') '01 rebuilt with inner parts and envelope headers'
    Assert ($o1 -notmatch '(?<!\r)\n') '01 uses CRLF line endings throughout'
    $subj = ConvertFrom-EncodedWord (Get-HeaderValue (Split-MimeEntity $o1).Headers 'Subject')
    Assert ($subj -eq 'Résumé – Q3 figures') '01 encoded subject decodes back to the original' $subj
    $o2 = Read-Out '02_messagepgp.eml'
    Assert ($o2 -match '(?m)^Subject: Secure message' -and $o2 -notmatch '(?m)^Subject: Inner subject' -and $o2 -match 'Hello Bob' -and $o2 -match '(?m)^Content-Type: text/html') '02 keeps the original headers with the message.pgp body and its content type'
    Assert ($o1 -match '(?m)^Content-Type: multipart/mixed; boundary="inner-b"' -and $o1 -notmatch 'Content-Description' -and $o1 -notmatch 'outer-boundary') '01 outer PGP/MIME Content-* headers replaced by the decrypted body''s own'
    Assert ((Read-Out '08_alice_again.eml') -match '(?m)^X-Mailer: TestMailer 1.0') '08 X- headers kept'
    $o3 = Read-Out '03_inline.eml'
    Assert ($o3 -match 'Hello Alice' -and $o3 -match 'caf=C3=A9' -and $o3 -match 'Regards =E2=80=94 Ext' -and $o3 -notmatch 'BEGIN PGP') '03 inline block replaced, surrounding text kept'
    Assert ((Read-Out '10_html_inline.eml') -match 'HTML inline secret') '10 HTML inline decrypted'
    Assert ((Read-Out '09_outbound.eml') -match '(?m)^From: "Smith, Alice" <alice@lloydsbanking.com>') '09 quoted display name kept'

    $csv = @(Import-Csv -LiteralPath $s.CsvPath)
    Assert ($csv.Count -eq 13 -and (Split-Path $s.CsvPath) -eq (Resolve-Path $src).ProviderPath) 'CSV log in the source folder with 13 rows'
    Assert ((Get-Content -LiteralPath $s.LogPath -Raw) -match 'GnuPG output for 06_corrupt.eml') 'detailed log includes GnuPG output for failures'
    Assert ($s.KeyringDeleted -and @($after | Where-Object { $before -notcontains $_ }).Count -eq 0) 'temporary keyring deleted'
    $leak = (Get-ChildItem -LiteralPath $src -Recurse -File | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'PRIVATE KEY BLOCK' })
    Assert (-not $leak) 'no private key material written to the source folder'

    if ($KeepWorkFolder) { Copy-Item -LiteralPath $src -Destination (Join-Path $work 'run1-output') -Recurse }

    # ------------------ Run 2: wrong API key ------------------
    Write-Host "`nRun 2: API key rejected" -ForegroundColor Cyan
    Reset-Source
    $global:TestVault.Secret = 'wrong-key'
    $s = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -VaultPassword $vaultPass -Quiet
    $global:TestVault.Secret = 'test-api-key-123'
    $r = Get-Row $s '01_pgpmime.eml'
    Assert ($r.Result -eq 'Failed' -and $r.Detail -match 'Authentication failed \(HTTP 401\)' -and $r.Detail -match 'Invalid API key') '401 reported as authentication failure with the server message' $r.Detail
    Assert ((Get-Row $s '04_plain.eml').Result -eq 'Not Encrypted') 'plain mail still sorted when the API key is wrong'
    Assert ($s.Decrypted -eq 0) 'nothing decrypted with a rejected key'

    # ------------------ Run 3: supplied passphrase, single file folder ------------------
    Write-Host "`nRun 3: supplied passphrase" -ForegroundColor Cyan
    Reset-Source
    Get-ChildItem -LiteralPath $src -File | Where-Object { $_.Name -ne '02_messagepgp.eml' } | Remove-Item
    $pass = ConvertTo-SecureString 'My Passphrase £ with spaces' -AsPlainText -Force
    $s = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -VaultPassword $vaultPass -Passphrase $pass -Quiet
    Assert ($s.Decrypted -eq 1 -and -not $s.PassphraseGenerated) 'decrypts with a supplied non-ASCII passphrase'

    # ------------------ Run 4: vault locked ------------------
    Write-Host "`nRun 4: locked vault" -ForegroundColor Cyan
    Reset-Source
    $err = $null
    try { $null = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match "Could not read the API key secret 'EchoworxApiKey'" -and $err -match 'password') 'locked vault stops the run with a clear error' $err
    Assert ((Get-ChildItem -LiteralPath $src -File -Filter '*.eml').Count -eq 13) 'no files moved when the vault cannot be read'
    $err = $null
    try { $null = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -VaultPassword (ConvertTo-SecureString 'nope' -AsPlainText -Force) -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match 'Could not unlock the SecretStore vault') 'wrong vault password reported' $err

    # ------------------ Input validation ------------------
    Write-Host "`nInput validation" -ForegroundColor Cyan
    $bad = Join-Path $work 'bad.csv'
    Set-Content -LiteralPath $bad -Value @('Domains', 'lloydsbanking.com')
    $err = $null; try { $null = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $bad -ApiBaseUrl $mockUrl -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match 'no Domain header') 'CSV without a Domain header rejected' $err
    Set-Content -LiteralPath $bad -Value @('Domain')
    $err = $null; try { $null = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $bad -ApiBaseUrl $mockUrl -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match 'lists no domains') 'CSV with no domains rejected' $err
    $err = $null; try { $null = & $script -SourceFolder $src -GpgPath (Join-Path $work 'nope\gpg.exe') -InternalDomainsPath $domainsCsv -ApiBaseUrl $mockUrl -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match 'gpg.exe was not found') 'missing gpg path rejected' $err
    $err = $null; try { $null = & $script -SourceFolder $src -GpgPath $GpgPath -InternalDomainsPath $domainsCsv -Environment Staging -Quiet } catch { $err = $_.Exception.Message }
    Assert ($err -match "Unknown environment 'Staging'") 'unknown environment rejected' $err

    # ------------------ Header helpers (used for .msg conversion) ------------------
    Write-Host "`nHeader helpers" -ForegroundColor Cyan
    $long = 'Ünïcödé subject that is long enough to need more than one encoded word and folding — ✓ 😀'
    $line = New-HeaderLine 'Subject' $long
    Assert (@($line -split "`r`n" | Where-Object { $_.Length -gt 78 }).Count -eq 0) 'encoded subject folded to 78 characters'
    Assert ((ConvertFrom-EncodedWord ($line.Substring(9) -replace "`r`n ", ' ')) -eq $long) 'encoded subject round-trips, emoji included'
    Assert ((Format-Rfc2822Date ([DateTimeOffset]::new(2026, 3, 5, 7, 8, 9, [TimeSpan]::FromHours(-5)))) -eq 'Thu, 05 Mar 2026 07:08:09 -0500') 'RFC 2822 date with negative offset'
    Assert ((Format-MailAddress 'Zoë Dupré' 'zoe@lloydsbanking.com') -match '^=\?utf-8\?B\?[^?]+\?= <zoe@lloydsbanking.com>$') 'non-ASCII display name encoded'
    $msgHeaders = New-Object System.Collections.Generic.List[object]
    Add-SyntheticHeader $msgHeaders 'From' (Format-MailAddress 'Zoë Dupré' 'zoe@lloydsbanking.com')
    Add-SyntheticHeader $msgHeaders 'To' ((Format-MailAddress 'Ext' 'ext@example.com'), (Format-MailAddress 'O''Brien, Pat' 'pat@example.com') -join ', ')
    Add-SyntheticHeader $msgHeaders 'Subject' 'Café meeting'
    Add-SyntheticHeader $msgHeaders 'Date' (Format-Rfc2822Date ([DateTimeOffset]::new(2026, 10, 1, 9, 0, 0, [TimeSpan]::FromHours(1))))
    $fake = [pscustomobject]@{ Headers = $msgHeaders; Date = $null }
    $eml = [System.Text.Encoding]::GetEncoding(28591).GetString((New-DecryptedEml -Message $fake -InnerEntity "Content-Type: text/plain`r`n`r`nbody"))
    Assert ($eml -notmatch '[^\x00-\x7F]') '.msg-style headers are pure ASCII'
    Assert ($eml -match '(?m)^To: Ext <ext@example.com>, "O''Brien, Pat" <pat@example.com>' -and $eml -match '(?m)^Subject: =\?utf-8\?B\?' -and $eml -match '(?m)^Date: Thu, 01 Oct 2026 09:00:00 \+0100') '.msg-style headers built correctly'
    $dec = ConvertFrom-EncodedWord '=?iso-8859-1?Q?Caf=E9?= =?utf-8?B?IOKckw==?='
    Assert ($dec -eq 'Café ✓') 'mixed Q and B encoded words decode' $dec
}
finally {
    $state.Stop = $true
    try { $null = $mock.EndInvoke($mockHandle) } catch { }
    $mock.Dispose()
    foreach ($h in @($sender, $orphan) + @(Get-ChildItem -LiteralPath $keyStore -Directory | ForEach-Object { $_.FullName })) { $null = & $gpgconf --homedir $h --kill all 2>&1 }
    if (-not $KeepWorkFolder) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } else { Write-Host "Work folder kept: $work" }
}

Write-Host ''
if ($script:FailedTests.Count) {
    Write-Host ("{0} passed, {1} failed: {2}" -f $script:Passed, $script:FailedTests.Count, ($script:FailedTests -join '; ')) -ForegroundColor Red
    exit 1
}
Write-Host ("All {0} checks passed." -f $script:Passed) -ForegroundColor Green
