# SubRecon

Asynchronous subdomain finder and enumerator.

---

## Overview

SubRecon is a high-speed subdomain discovery tool that combines passive intelligence from Certificate Transparency logs with active brute-force enumeration. Built with Python's `asyncio` for fast DNS resolution.

---

## Features

- **Passive Intelligence** — Fetches subdomains from crt.sh CT logs
- **Active Brute-Force** — Attempts to resolve common subdomain names
- **Asynchronous Resolution** — Fast DNS queries with concurrency control
- **Custom Wordlists** — Support for custom subdomain wordlists
- **No External Dependencies** — Uses only Python standard library

---

## Quick Start

```bash
git clone https://github.com/vanyanch/subrecon
cd subrecon
python subrecon.py example.com