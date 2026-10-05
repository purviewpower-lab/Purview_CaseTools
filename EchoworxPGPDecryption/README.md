**Echoworx PGP Decryption Tool**

A WPF front end (same look as Purview Case Tools) and a PowerShell engine that decrypt PGP-encrypted `.eml` and `.msg` files with private keys exported from the Echoworx EMG REST API, using GnuPG for the decryption itself.

## Files

| File | What it is |
| --- | --- |
| `EchoworxDecryptionTool.ps1` | The GUI. Run this. |
| `Invoke-EchoworxDecryption.ps1` | The engine. The GUI drives it, and it also runs on its own from the command line. |
| `InternalDomains.csv` | Internal domains, under a `Domain` header (at least one). Editable from the GUI's Internal Domains page. |
| `Tests\Test-EchoworxDecryption.ps1` | End-to-end tests against a local mock of the Echoworx API. Never contacts Echoworx. |

Keep the first three in the same folder.

## Requirements

* Windows PowerShell 5.1 or PowerShell 7 (the GUI needs Windows).
* GnuPG 2.1 or later (Gpg4win). Default path `C:\Program Files\GnuPG\bin\gpg.exe`; change it on the Settings page or with `-GpgPath`.
* `Microsoft.PowerShell.SecretManagement` and `Microsoft.PowerShell.SecretStore`, with the Production API key stored as `EchoworxApiKey`:
  ```powershell
  Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser
  Register-SecretVault -Name EchoworxVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
  Set-Secret -Name EchoworxApiKey -Secret '<x-echoworx-api-key>'
  ```
* Outlook desktop, for `.msg` files only (they are read through COM automation).

## Using the GUI

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\EchoworxDecryptionTool.ps1
```

1. **Settings**: check the environment (Production), profile name (`{email}`, meaning each internal user's own address), vault name (empty = default vault), vault password and the gpg.exe path. Click **Check** to confirm GnuPG.
2. **Internal Domains**: one domain per line, then **Save**.
3. **Decrypt**: pick the source folder, optionally enter a key bundle passphrase, then **Decrypt Folder** (Ctrl+Enter). Results stream into the grid; double-click a row for the full detail. **Stop** finishes the current file and still deletes the keyring.

If the folder has `.msg` files and Outlook is already running, the Decrypt page shows a warning and the tool asks before continuing, since COM automation may not work while Outlook is open.

Settings (not passwords) are remembered in `%APPDATA%\EchoworxDecryptionTool\settings.json`. The app's own log is in `C:\EchoworxDecryptionLogs`.

## Command line

```powershell
.\Invoke-EchoworxDecryption.ps1 -SourceFolder 'D:\Evidence\Batch1'

$vault = Read-Host 'Vault password' -AsSecureString
$pass  = Read-Host 'Key bundle passphrase' -AsSecureString
.\Invoke-EchoworxDecryption.ps1 -SourceFolder 'D:\Evidence\Batch1' -VaultPassword $vault -Passphrase $pass -GpgPath 'D:\Tools\GnuPG\bin\gpg.exe'
```

| Parameter | Default | Notes |
| --- | --- | --- |
| `-SourceFolder` | (required) | Top level only; the output folders inside it are never re-processed. |
| `-Environment` | `Production` | Key of `$EchoworxEnvironments` at the top of the engine (URL and secret name). |
| `-ProfileName` | `{email}` | The Echoworx profile is the internal user's email address. A fixed name can be given instead. |
| `-GpgPath` | `C:\Program Files\GnuPG\bin\gpg.exe` | |
| `-Passphrase` | random per run | SecureString. Protects the exported bundle in transit and unlocks it in GnuPG. A generated one is never written anywhere. |
| `-VaultName` | default vault | |
| `-VaultPassword` | prompt | SecureString. Unlocks the SecretStore vault. |
| `-InternalDomainsPath` | `InternalDomains.csv` next to the script | |
| `-Force` | off | Don't ask when Outlook is already running. |
| `-ApiBaseUrl` | environment URL | For testing against a mock only. |

The command line prints a summary and returns an object with the counts, the CSV and log paths and every result row.

## What happens to each file

1. The message is parsed for sender, To/Cc/Bcc and a PGP payload, in this order of preference: a PGP/MIME part (`multipart/encrypted`), an encrypted attachment (`message.pgp`, or any `.pgp`/`.gpg`/`.asc` holding OpenPGP data), an inline `BEGIN PGP MESSAGE` block (plain text or HTML).
2. No payload: moved to `Not Encrypted`.
3. The internal user is the participant whose domain is in `InternalDomains.csv` (recipients first, then the sender for sent items). If several are internal, each is tried until one key works.
4. Their key is exported once per address with `POST /profiles/{profileName}/pgp-key-pair/export` and imported into a temporary keyring created for this run (`%TEMP%\EchoworxGpg_<guid>`, readable only by you). Failed lookups are cached too, so Echoworx is asked once per user per run.
5. gpg decrypts the payload (passphrase on stdin, never the command line). The decrypted content is rebuilt into an `.eml` with the original envelope headers and written to `Successful`.
6. Once the output is confirmed non-empty, the encrypted original is deleted. Anything that fails is moved to `Failed`.
7. When the run ends, gpg-agent is stopped and the keyring, with every private key in it, is deleted. If that ever fails, the summary and the GUI say so loudly.

The rebuilt message keeps every original header (Date, From, To, Cc, Subject, Message-ID, Received, X- headers and so on) except the outer Content-* headers that described the PGP wrapper; the decrypted body supplies its own Content-Type and boundary. Output headers are 7-bit clean: non-ASCII subjects and display names are RFC 2047 encoded, and dates are RFC 2822 (a non-standard `Date` is rewritten; a missing one is filled from the message). `.msg` envelopes come from Outlook's transport headers when present, otherwise from the item's properties.

## Logs

Each run writes two files to the source folder:

* `EchoworxDecryption_<timestamp>.csv`: one row per file with Result, Sender, Recipients, Subject, InternalUser, PgpFormat, Output and Detail.
* `EchoworxDecryption_<timestamp>.log`: every API call (URL and HTTP status, never the key) and GnuPG's own output for failures.

Failure details are written to be acted on, for example:

* `No key found (HTTP 404): Echoworx has no PGP key pair for carol@lloydsbanking.com under profile 'carol@lloydsbanking.com'.`
* `Authentication failed (HTTP 401): Echoworx rejected the x-echoworx-api-key from secret 'EchoworxApiKey'...`
* `No matching private key: the message is encrypted to key ID(s) 1A2B..., and the key exported from Echoworx for dan@lloydsbanking.com is not one of them.`
* `The PGP payload is corrupt or truncated, so GnuPG could not read it. GnuPG said: ...`
* `Authentication to the private key failed: the passphrase did not unlock the key bundle...`
* `No participant matches a domain in InternalDomains.csv...`

## To confirm against the Echoworx API docs

The request body field names are an assumption. The engine sends:

```json
{ "emailAddress": "alice@lloydsbanking.com", "passphrase": "<passphrase>" }
```

If EMG expects different names, change `New-KeyExportBody` near the top of `Invoke-EchoworxDecryption.ps1`. The response can be any shape: the engine finds the `-----BEGIN PGP PRIVATE KEY BLOCK-----` wherever it is (plain text, any JSON property, or base64 inside JSON).

## Tests

```powershell
.\Tests\Test-EchoworxDecryption.ps1 -GpgPath 'C:\Program Files\GnuPG\bin\gpg.exe'
```

Generates throwaway keys and messages, starts a mock export endpoint on 127.0.0.1 and runs the engine over PGP/MIME, `message.pgp`, inline and HTML inline mail, plain mail, missing keys, wrong keys, corrupt payloads, non-internal mail, a rejected API key, a locked vault and bad inputs. The SecretStore cmdlets are replaced with test stand-ins, so no real vault is used. `.msg` handling needs Outlook and is not covered by these tests.
