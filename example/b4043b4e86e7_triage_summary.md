# Executive Summary — b4043b4e86e7

**File:** `evil3.exe` | **Size:** 80,384 bytes | **Date:** 2026-03-25

## Hashes

| Algorithm | Value |
|---|---|
| MD5 | `88a95686ccbdaf9365aaa73b4d46abb9` |
| SHA-1 | `fb56944f8ab9d173344818c31e044050e2983e54` |
| SHA-256 | `b4043b4e86e7591012251410ec5408360c03f479165580c22cf116bd4d0c9eae` |

## VirusTotal Verdict

**0 / ? engines** — Not yet submitted or undetected. No threat label assigned. Low AV coverage does not indicate safety given the strong behavioral indicators below.

## Key Suspicious Imports

No explicit suspicious imports were resolved in the IAT; however, DLL names present in strings indicate dynamic loading of:
- `wininet.dll`, `winhttp.dll` — HTTP/network communications
- `crypt32.dll`, `vaultcli.dll`, `advapi32.dll` — credential decryption (DPAPI)
- `pstorec.dll` — legacy Protected Storage credential access
- `ws2_32.dll`, `dnsapi.dll` — socket/DNS operations
- `mpr.dll` — network provider credential access

## Notable IoCs

| Type | Value |
|---|---|
| IP | `176.126.70.119` |
| Domain | `http://benten02.futbol` |
| C2 path | `%S/gate.php` |
| Self-delete | `/c ping 127.0.0.1 && del "%s"` |
| URL template | `https://%S/a/%S` |

**Credential theft targets identified in strings:** Firefox (`key3.db`, `key4.db`, `logins.json`, `signons.sqlite`, `cookies.sqlite`), Chrome (`Login Data`, `Web Data`), Internet Explorer (`IntelliForms/Storage2`, `TypedURLs`), Outlook profiles, FileZilla, WinSCP, WS_FTP, Pidgin/PSI+, Steam, Discord, NordVPN, EarthVPN, Electrum, Exodus, Ethereum, and Monero wallets (`wallet.dat`, `*.wallet`). System fingerprinting strings (`MachineGuid`, CPU, RAM, screen resolution, `screenshot.png`) and grabber delimiter markers (`__GRABBER__`, `__DELIMM__`) confirm data-exfiltration functionality.

The `.text` section has high entropy (6.57), consistent with packed or obfuscated code explaining the absence of resolved IAT imports.

## Overall Risk Assessment

**CRITICAL**

This sample exhibits all hallmarks of a credential-harvesting infostealer (consistent with families such as Pony/Fareit or a custom stealer): DPAPI-based credential decryption, broad browser/email/FTP/VPN/crypto-wallet targeting, C2 beaconing via `gate.php`, and a self-deletion mechanism. Active C2 infrastructure (hardcoded IP and domain) and comprehensive victim profiling make this a high-confidence malicious sample warranting immediate containment and IOC blocking.
