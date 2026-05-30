# 🔥 firewall_blocker

Gestionnaire de blocklists IP pour le pare-feu Windows, écrit en Rust. Télécharge automatiquement des listes d'IPs malveillantes connues et les bloque via PowerShell.

## Fonctionnalités

- 🚀 **Un seul process PowerShell** — génère un unique script `.ps1` et l'exécute en une fois (consommation CPU/RAM minimale)
- 🔄 **Purge automatique** — supprime les anciennes règles avant de recréer les nouvelles, jamais de doublons
- ⏰ **Tâche planifiée** — installe une tâche Windows quotidienne via `--install-task`
- 📋 **84 000+ IPs bloquées** issues de 9 sources de threat intelligence
- 📦 **Exécutable autonome de 2.2 MB** — aucun runtime, aucune dépendance, fonctionne sur n'importe quelle machine Windows

## Blocklists

| Source | Description |
|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | Réseaux alloués à des organisations criminelles |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | IPs de botnets actifs (Emotet, TrickBot...) |
| [ThreatFox](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs) | Malware récents — mirror GitHub abuse.ch |
| [Emerging Threats](https://rules.emergingthreats.net/) | IPs compromises actives (utilisé par pfSense/OPNsense) |
| [Binary Defense](https://www.binarydefense.com/) | Attaquants actifs — projet Artillery |
| [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker) | IPs de télémétrie Microsoft |
| [Blocklist.de](https://www.blocklist.de/) | Attaquants SSH/FTP/mail remontés par des honeypots |
| [GreenSnow](https://blocklist.greensnow.co/) | IPs malveillantes actives |
| [CINSArmy](https://cinsscore.com/) | Blocklist de réputation IP |

## Utilisation

```powershell
# Applique toutes les listes (purge les anciennes règles avant)
.\firewall_blocker.exe

# Simulation — affiche sans appliquer
.\firewall_blocker.exe --dry-run

# Installe la tâche planifiée quotidienne (nécessite les droits admin)
.\firewall_blocker.exe --install-task

# Heure personnalisée pour la tâche (défaut : 3 = 03h00)
.\firewall_blocker.exe --install-task --hour 6

# Applique une seule liste
.\firewall_blocker.exe --only Feodo-Tracker

# Liste toutes les règles créées
.\firewall_blocker.exe --list

# Supprime toutes les règles créées
.\firewall_blocker.exe --remove
```

> ⚠️ Doit être lancé en tant qu'**Administrateur**

## Fonctionnement

1. Télécharge toutes les blocklists
2. Parse et dédoublonne les IPs/CIDRs
3. Génère un unique script `.ps1` avec tous les appels `New-NetFirewallRule` (500 IPs par règle max)
4. Exécute le script en **un seul process PowerShell**
5. Supprime le fichier `.ps1` temporaire

Les règles sont préfixées `BLOCKLIST - <source> - chunk<N> [Inbound/Outbound]` pour les retrouver facilement dans `wf.msc`.

## Compilation

**Prérequis :**
- [Rust](https://rustup.rs/)
- Visual Studio avec le workload **"Développement Desktop en C++"**

```powershell
cargo build --release
```

Résultat : `target\release\firewall_blocker.exe`

## Stack technique

- **Rust 2021**
- [`ureq`](https://github.com/algesten/ureq) — client HTTP sync minimaliste (seule dépendance externe)
- `std` pure pour le parsing CLI, la validation IP, les timestamps et le logging

## Tâche planifiée

L'option `--install-task` enregistre une tâche dans le Planificateur de tâches Windows qui :
- Se lance chaque jour à 03h00 (modifiable avec `--hour`)
- S'exécute en tant que `SYSTEM` avec droits élevés
- Utilise `StartWhenAvailable` — si le PC était éteint à 03h00, la tâche se lance au prochain démarrage

## Licence

MIT
