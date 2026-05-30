# 🔥 firewall_blocker

Windows Firewall blocklist manager written in Rust — automatically downloads known malicious IP lists and blocks them via PowerShell.

## Features

- 🚀 **Single PowerShell execution** — generates one `.ps1` script and runs it in a single process (minimal CPU/RAM usage)
- 🔄 **Auto-purge** — removes old rules before recreating them, no duplicates
- ⏰ **Scheduled task** — installs a daily Windows Task Scheduler job via `--install-task`
- 📋 **84 000+ IPs blocked** across 9 threat intelligence sources
- 📦 **2.2 MB standalone executable** — no runtime, no dependencies, runs on any Windows machine

## Blocklists

| Source | Description |
|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | Networks allocated to criminal organizations |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Active botnet C2 IPs (Emotet, TrickBot...) |
| [ThreatFox](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs) | Recent malware IPs — abuse.ch mirror |
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised IPs (used by pfSense/OPNsense) |
| [Binary Defense](https://www.binarydefense.com/) | Active attackers — Artillery project |
| [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker) | Microsoft telemetry IPs |
| [Blocklist.de](https://www.blocklist.de/) | SSH/FTP/mail attackers reported by honeypots |
| [GreenSnow](https://blocklist.greensnow.co/) | Active malicious IPs |
| [CINSArmy](https://cinsscore.com/) | IP reputation score blocklist |

## Usage

```powershell
# Apply all lists (purges old rules first)
.\firewall_blocker.exe

# Dry run — display without applying
.\firewall_blocker.exe --dry-run

# Install daily scheduled task (requires admin)
.\firewall_blocker.exe --install-task

# Custom hour for scheduled task (default: 3 = 03:00)
.\firewall_blocker.exe --install-task --hour 6

# Apply a single list only
.\firewall_blocker.exe --only Feodo-Tracker

# List all created firewall rules
.\firewall_blocker.exe --list

# Remove all created rules
.\firewall_blocker.exe --remove
```

> ⚠️ Must be run as **Administrator**

## How it works

1. Downloads all blocklists concurrently
2. Parses and deduplicates IPs/CIDRs
3. Generates a single `.ps1` script with all `New-NetFirewallRule` calls (500 IPs per rule chunk)
4. Executes the script in **one PowerShell process**
5. Deletes the temporary `.ps1` file

Rules are prefixed `BLOCKLIST - <source> - chunk<N> [Inbound/Outbound]` for easy identification in `wf.msc`.

## Build

**Prerequisites:**
- [Rust](https://rustup.rs/)
- Visual Studio with **"Desktop development with C++"** workload

```powershell
cargo build --release
```

Output: `target\release\firewall_blocker.exe`

## Stack

- **Rust 2021**
- [`ureq`](https://github.com/algesten/ureq) — minimal sync HTTP client (only external dependency)
- Pure `std` for CLI parsing, IP validation, timestamps and logging

## Scheduled task

The `--install-task` flag registers a Windows Task Scheduler job that:
- Runs daily at 03:00 (configurable with `--hour`)
- Runs as `SYSTEM` with elevated privileges
- Uses `StartWhenAvailable` — if the PC was off at 03:00, the task runs on next boot

## License

MIT
