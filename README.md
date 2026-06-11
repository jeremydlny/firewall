# 🔥 firewall_blocker

Windows firewall IP blocklist manager, written in Rust. Automatically downloads known malicious IP lists and blocks them via PowerShell.

## Features

- 🚀 **Single PowerShell process** — generates a single `.ps1` script and runs it once (minimal CPU/RAM usage)
- 🔄 **Automatic purge** — removes old rules before recreating new ones, never duplicates
- ⏰ **Scheduled task** — installs a daily Windows task via `--install-task`
- 📋 **84,000+ IPs blocked** from 9 threat intelligence sources
- 📦 **2.2 MB standalone executable** — no runtime, no dependencies, works on any Windows machine

## Blocklists

| Source | Description |
|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | Networks allocated to criminal organizations |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Active botnet IPs (Emotet, TrickBot...) |
| [ThreatFox](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs) | Recent malware — abuse.ch GitHub mirror |
| [Emerging Threats](https://rules.emergingthreats.net/) | Active compromised IPs (used by pfSense/OPNsense) |
| [Binary Defense](https://www.binarydefense.com/) | Active attackers — Artillery project |
| [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker) | Microsoft telemetry IPs |
| [Blocklist.de](https://www.blocklist.de/) | SSH/FTP/mail attackers reported by honeypots |
| [GreenSnow](https://blocklist.greensnow.co/) | Active malicious IPs |
| [CINSArmy](https://cinsscore.com/) | IP reputation blocklist |

## Usage

```powershell
# Apply all lists (purges old rules first)
.\firewall_blocker.exe

# Dry run — show without applying
.\firewall_blocker.exe --dry-run

# Install the daily scheduled task (requires admin rights)
.\firewall_blocker.exe --install-task

# Custom time for the task (default: 3 = 3 AM)
.\firewall_blocker.exe --install-task --hour 6

# Apply a single list
.\firewall_blocker.exe --only Feodo-Tracker

# List all created rules
.\firewall_blocker.exe --list

# Remove all created rules
.\firewall_blocker.exe --remove
```

> ⚠️ Must be run as **Administrator**

## How it works

1. Downloads all blocklists
2. Parses and deduplicates IPs/CIDRs
3. Generates a single `.ps1` script with all `New-NetFirewallRule` calls (max 500 IPs per rule)
4. Executes the script in **a single PowerShell process**
5. Deletes the temporary `.ps1` file

Rules are prefixed `BLOCKLIST - <source> - chunk<N> [Inbound/Outbound]` for easy identification in `wf.msc`.

## Build

**Requirements:**
- [Rust](https://rustup.rs/)
- Visual Studio with the **"Desktop development with C++"** workload

```powershell
cargo build --release
```

Output: `target\release\firewall_blocker.exe`

## Tech stack

- **Rust 2021**
- [`ureq`](https://github.com/algesten/ureq) — minimalist sync HTTP client (only external dependency)
- pure `std` for CLI parsing, IP validation, timestamps and logging

## Scheduled task

The `--install-task` option registers a task in the Windows Task Scheduler that:
- Runs daily at 3:00 AM (configurable with `--hour`)
- Runs as `SYSTEM` with elevated rights
- Uses `StartWhenAvailable` — if the PC was off at 3:00 AM, the task runs at the next startup

## License

MIT
