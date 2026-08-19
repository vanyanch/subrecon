# SubRecon

Asynchronous subdomain finder and enumerator with passive intelligence and active brute-force.

---

## Overview

SubRecon is a high-speed subdomain discovery tool written in Python. It combines passive intelligence from Certificate Transparency logs with active brute-force enumeration using `asyncio` for fast DNS resolution.

---

## Features

- **Passive intelligence** — Fetches subdomains from crt.sh CT logs
- **Active brute-force** — Resolves common subdomain names from wordlists
- **Asynchronous resolution** — Fast DNS queries with configurable concurrency
- **Custom wordlists** — Support for custom subdomain wordlists
- **Colored output** — Clear visual feedback
- **Cross-platform** — Works on Windows and Linux

---

## Quick Start

```bash
git clone https://github.com/vanyanch/subrecon
cd subrecon
python subrecon.py example.com
```

---

## Usage

### Basic Enumeration
Uses default wordlist and passive CT log intelligence:
```bash
python subrecon.py github.com
```

### Custom Wordlist
Load custom subdomain names from a file:
```bash
python subrecon.py example.com --wordlist subdomains.txt
```

### Adjust Concurrency
Control parallel DNS queries (default: 500):
```bash
python subrecon.py example.com --concurrency 1000
```

---

## Command Reference

| Flag | Description |
| :--- | :--- |
| `domain` | Target domain (required) |
| `--wordlist FILE` | Custom wordlist for brute-force |
| `--concurrency N` | Max parallel DNS queries (default: 500) |
| `-h, --help` | Show help message |

---

## Output Example

```text
$ python subrecon.py github.com

🚀 Launching SubRecon for: github.com
------------------------------------------------------------
[*] Using default wordlist (44 entries).
    (Use --wordlist to load custom subdomain names)
[*] Fetching passive intelligence from crt.sh...
[+] Gathered 0 unique subdomains from CT logs.
[*] Total unique targets to verify: 43
------------------------------------------------------------
🔍 Starting asynchronous resolution...

[+] Found: ssh.github.com                 -> [140.82.121.36]
[+] Found: shop.github.com                -> [140.82.121.4]
[+] Found: blog.github.com                -> [185.199.109.153]
[+] Found: admin.github.com               -> [140.82.113.23]
[+] Found: api.github.com                 -> [140.82.121.6]
[+] Found: support.github.com             -> [185.199.110.133]
[+] Found: smtp.github.com                -> [140.82.112.32]
[+] Found: ns1.github.com                 -> [192.0.2.1]
[+] Found: test.github.com                -> [192.0.2.1]
[+] Found: status.github.com              -> [140.82.114.18]
[+] Found: ns2.github.com                 -> [192.0.2.2]
------------------------------------------------------------
🎯 Subdomain enumeration completed successfully.
```

---

## Passive Intelligence

### Certificate Transparency Logs
The tool queries crt.sh (public CT log aggregator) to discover subdomains that have been issued SSL/TLS certificates. This is a passive method that:
- Does not touch the target directly
- Discovers subdomains that may not be in public DNS
- Works best for domains with HTTPS-enabled subdomains

---

## Active Brute-Force

### Wordlist
SubRecon attempts to resolve subdomain names from a wordlist. Default wordlist includes common naming patterns:

- **Infrastructure:** admin, dev, staging, prod, api
- **Services:** mail, vpn, git, jenkins, monitor
- **DNS:** ns1, ns2, dns
- **Protocols:** ftp, smtp, pop3, imap, ssh
- **Management:** cpanel, webmail, portal, support

### Resolution
Each subdomain is resolved using system DNS. Only A records (IPv4) are checked.

---

## Performance

The scanner uses `asyncio.Semaphore` to control concurrent DNS queries. Default concurrency is 500, which balances speed and resolver load.

### Recommended Settings

| Environment | Recommended Concurrency |
| :--- | :--- |
| Linux | 500 - 1000 |
| Windows | 300 - 500 |
| Low-spec machine | 100 - 300 |

---

## Technical Details

- **Passive Gathering:** Uses `urllib.request` for synchronous HTTPS request to crt.sh API
- **Active Resolution:** Uses `loop.getaddrinfo()` for asynchronous DNS resolution
- **Concurrency Control:** Semaphore limits simultaneous DNS queries
- **Windows Compatibility:** Uses `WindowsSelectorEventLoopPolicy` for stable asyncio behavior
- **Color Output:** ANSI escape codes provide colored output on compatible terminals

---

## Dependencies

- Python 3.8+
- **No external dependencies** (Pure standard library)

---

## License

This project is licensed under the [GNU GPL v3 License](LICENSE).

---

## Author

Created by **vanyanch**