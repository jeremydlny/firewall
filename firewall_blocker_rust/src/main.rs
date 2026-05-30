/*
firewall_blocker – Windows Firewall Blocklist Manager
======================================================
Optimisé CPU/RAM :
  - Un seul process PowerShell pour toutes les règles (pas de spawn répété)
  - Validation IP sans regex (pas d'allocations inutiles)
  - Parsing ligne par ligne sans buffer intermédiaire
  - Seule dépendance : ureq (HTTP sync minimaliste)
*/

use std::collections::HashSet;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;

const RULE_PREFIX: &str = "BLOCKLIST";
const CHUNK_SIZE:  usize = 500;
const LOG_FILE:    &str  = "firewall_blocker.log";
const PS1_TMP:     &str  = "firewall_tmp.ps1";

struct Blocklist {
    name:         &'static str,
    url:          &'static str,
    comment_char: char,
    description:  &'static str,
}

const BLOCKLISTS: &[Blocklist] = &[
    Blocklist { name: "Spamhaus-DROP",    url: "https://www.spamhaus.org/drop/drop.txt",                                                                               comment_char: ';', description: "Reseaux alloues a des criminels (Spamhaus DROP)" },
    Blocklist { name: "Feodo-Tracker",    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",                                                              comment_char: '#', description: "IPs de botnets actifs - Feodo Tracker" },
    Blocklist { name: "ThreatFox",        url: "https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt",                        comment_char: '#', description: "IPs de malware recents - ThreatFox" },
    Blocklist { name: "Emerging-Threats", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",                                                     comment_char: '#', description: "IPs compromises - Emerging Threats" },
    Blocklist { name: "Binary-Defense",   url: "https://www.binarydefense.com/banlist.txt",                                                                            comment_char: '#', description: "Attaquants actifs - Binary Defense" },
    Blocklist { name: "WindowsSpyBlocker", url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt",                          comment_char: '#', description: "Telemetrie Microsoft - WindowsSpyBlocker" },
    Blocklist { name: "Blocklist-DE",      url: "https://lists.blocklist.de/lists/all.txt",                                                                            comment_char: '#', description: "Attaquants SSH/FTP/mail - Blocklist.de" },
    Blocklist { name: "GreenSnow",         url: "https://blocklist.greensnow.co/greensnow.txt",                                                                        comment_char: '#', description: "IPs malveillantes actives - GreenSnow" },
    Blocklist { name: "CINSArmy",          url: "https://cinsscore.com/list/ci-badguys.txt",                                                                           comment_char: '#', description: "Score reputation IP - CINSArmy" },
];

// ── Logging ───────────────────────────────────────────────────────────────────

fn ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (s % 86400) / 3600, (s % 3600) / 60, s % 60)
}

fn log(level: &str, msg: &str) {
    let line = format!("{}  {:<8}  {}", ts(), level, msg);
    println!("{line}");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        let _ = writeln!(f, "{line}");
    }
}

macro_rules! info  { ($($t:tt)*) => { log("INFO",    &format!($($t)*)) }; }
macro_rules! warn  { ($($t:tt)*) => { log("WARNING", &format!($($t)*)) }; }
macro_rules! error { ($($t:tt)*) => { log("ERROR",   &format!($($t)*)) }; }

// ── IP validation sans regex ──────────────────────────────────────────────────

fn is_valid_ip_or_cidr(s: &str) -> bool {
    let (ip, prefix) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None         => (s, None),
    };
    if let Some(p) = prefix {
        match p.parse::<u8>() { Ok(n) if n <= 32 => {} _ => return false }
    }
    let parts: Vec<&str> = ip.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── CLI sans clap ─────────────────────────────────────────────────────────────

struct Cli { dry_run: bool, remove: bool, list: bool, install_task: bool, hour: u8, only: Option<String> }

fn parse_args() -> Cli {
    let args: Vec<String> = env::args().collect();
    let mut c = Cli { dry_run: false, remove: false, list: false, install_task: false, hour: 3, only: None };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run"      => c.dry_run = true,
            "--remove"       => c.remove = true,
            "--list"         => c.list = true,
            "--install-task" => c.install_task = true,
            "--hour" => { i += 1; c.hour = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(3); }
            "--only" => { i += 1; c.only = args.get(i).cloned(); }
            "--help" | "-h" => {
                println!("Usage: firewall_blocker.exe [OPTIONS]");
                println!("  --dry-run        Affiche sans appliquer");
                println!("  --remove         Supprime les regles creees");
                println!("  --list           Liste les regles en place");
                println!("  --install-task   Installe la tache planifiee");
                println!("  --hour N         Heure de la tache (defaut: 3)");
                println!("  --only NOM       Une seule liste");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    c
}

// ── PowerShell ────────────────────────────────────────────────────────────────

fn is_admin() -> bool {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
        .output();
    matches!(out, Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "True")
}

/// Exécute un fichier .ps1 — UN SEUL process PowerShell pour tout le script.
fn run_ps1(path: &str, dry_run: bool) -> bool {
    if dry_run { println!("  [DRY-RUN] powershell -File {path}"); return true; }
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path])
        .output()
    {
        Ok(o) if o.status.success() => true,
        Ok(o) => { warn!("PS: {}", String::from_utf8_lossy(&o.stderr).trim().chars().take(150).collect::<String>()); false }
        Err(e) => { warn!("Exec: {e}"); false }
    }
}

/// Exécute une commande PS inline courte (remove, list, install-task).
fn run_ps_inline(cmd: &str, dry_run: bool) -> bool {
    if dry_run { println!("  [DRY-RUN] {}", &cmd[..cmd.len().min(120)]); return true; }
    match Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", cmd]).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => { warn!("PS: {}", String::from_utf8_lossy(&o.stderr).trim().chars().take(150).collect::<String>()); false }
        Err(e) => { warn!("{e}"); false }
    }
}

// ── Fetch ─────────────────────────────────────────────────────────────────────

fn fetch_ips(bl: &Blocklist) -> Vec<String> {
    info!("[{}] Telechargement...", bl.name);
    let body = match ureq::get(bl.url).set("User-Agent", "Mozilla/5.0").call() {
        Ok(r)  => match r.into_string() { Ok(s) => s, Err(e) => { error!("[{}] {e}", bl.name); return vec![]; } }
        Err(e) => { error!("[{}] {e}", bl.name); return vec![]; }
    };
    let mut seen = HashSet::new();
    let mut out  = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(bl.comment_char) { continue; }
        let token = line.split_whitespace().next().unwrap_or("")
            .split(bl.comment_char).next().unwrap_or("").trim();
        if is_valid_ip_or_cidr(token) && seen.insert(token.to_string()) {
            out.push(token.to_string());
        }
    }
    info!("[{}] {} entrees valides", bl.name, out.len());
    out
}

// ── Génération du script PS1 (un seul fichier, une seule exécution) ───────────

fn build_ps1(all_rules: &[(&Blocklist, Vec<String>)]) -> String {
    let mut ps = String::with_capacity(1024 * 512);

    // Purge des anciennes règles
    ps.push_str(&format!(
        "Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '{RULE_PREFIX}*'}} | Remove-NetFirewallRule\n"
    ));

    for (bl, ips) in all_rules {
        let n_chunks = ips.len().div_ceil(CHUNK_SIZE);
        for (idx, batch) in ips.chunks(CHUNK_SIZE).enumerate() {
            let n    = idx + 1;
            let addr = batch.join(",");
            let rule = format!("{RULE_PREFIX} - {} - chunk{n:03}", bl.name);
            for dir in ["Inbound", "Outbound"] {
                ps.push_str(&format!(
                    "New-NetFirewallRule -DisplayName '{rule} [{dir}]' -Direction {dir} \
                     -Action Block -RemoteAddress {addr} -Description '{}' \
                     -Enabled True -Profile Any | Out-Null\n",
                    bl.description
                ));
            }
            // Progress inline dans le script PS
            ps.push_str(&format!(
                "Write-Host '  -> {} chunk {n}/{n_chunks} OK'\n", bl.name
            ));
        }
    }
    ps
}

// ── Actions ───────────────────────────────────────────────────────────────────

fn remove_rules(dry_run: bool) {
    info!("Suppression des regles '{RULE_PREFIX}*'...");
    run_ps_inline(
        &format!("Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '{RULE_PREFIX}*'}} | Remove-NetFirewallRule"),
        dry_run,
    );
    info!("Suppression terminee.");
}

fn list_rules() {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            &format!("Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '{RULE_PREFIX}*'}} | Select-Object DisplayName, Enabled | Format-Table -AutoSize")])
        .output().expect("PowerShell introuvable");
    let s = String::from_utf8_lossy(&out.stdout);
    println!("{}", if s.trim().is_empty() { "(aucune regle)" } else { s.trim() });
}

fn install_task(hour: u8, dry_run: bool) {
    let exe  = env::current_exe().unwrap_or_default();
    let path = exe.to_string_lossy();
    let name = "FirewallBlocklistUpdate";
    info!("Installation tache '{name}' a {hour:02}h00...");
    let ps = format!(
        "$a=New-ScheduledTaskAction -Execute '{path}'; \
         $t=New-ScheduledTaskTrigger -Daily -At '{hour:02}:00'; \
         $s=New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable; \
         $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest; \
         Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue; \
         Register-ScheduledTask -TaskName '{name}' -Action $a -Trigger $t -Settings $s -Principal $p \
           -Description 'Blocklist IP quotidienne'"
    );
    if run_ps_inline(&ps, dry_run) { info!("Tache installee. Verifier dans taskschd.msc"); }
    else { error!("Echec installation tache."); }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let cli = parse_args();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!(  "║          Windows Firewall Blocklist Manager          ║");
    println!(  "╚══════════════════════════════════════════════════════╝\n");

    if !cli.dry_run && !is_admin() {
        error!("Lancer en tant qu'Administrateur.");
        std::process::exit(1);
    }

    if cli.list         { list_rules();                         return; }
    if cli.remove       { remove_rules(cli.dry_run);           return; }
    if cli.install_task { install_task(cli.hour, cli.dry_run); return; }

    if cli.dry_run { info!("DRY-RUN - aucune modification"); }

    // Sélection des listes
    let selected: Vec<&Blocklist> = match &cli.only {
        Some(name) => {
            let v: Vec<&Blocklist> = BLOCKLISTS.iter().filter(|b| b.name == name.as_str()).collect();
            if v.is_empty() {
                error!("Liste inconnue : '{name}'. Choix : {}", BLOCKLISTS.iter().map(|b| b.name).collect::<Vec<_>>().join(", "));
                std::process::exit(1);
            }
            v
        }
        None => BLOCKLISTS.iter().collect(),
    };

    // 1. Téléchargement de toutes les listes
    info!("Telechargement des listes...");
    let mut all_rules: Vec<(&Blocklist, Vec<String>)> = Vec::new();
    let mut total = 0usize;

    for bl in &selected {
        let ips = fetch_ips(bl);
        if ips.is_empty() { warn!("[{}] Aucune IP, ignoree.", bl.name); continue; }
        total += ips.len();
        all_rules.push((bl, ips));
    }

    info!("{total} IPs au total — generation du script PowerShell...");

    // 2. Génération du script PS1
    let ps1_content = build_ps1(&all_rules);

    if cli.dry_run {
        println!("{}", &ps1_content[..ps1_content.len().min(500)]);
        println!("... (script tronque en dry-run)");
        return;
    }

    // 3. Écriture dans un fichier temporaire
    match std::fs::write(PS1_TMP, &ps1_content) {
        Ok(_)  => info!("Script PS1 genere ({} octets)", ps1_content.len()),
        Err(e) => { error!("Impossible d'ecrire le script : {e}"); std::process::exit(1); }
    }

    // 4. Exécution — UN SEUL process PowerShell pour tout
    info!("Execution du script (un seul process PowerShell)...");
    if run_ps1(PS1_TMP, cli.dry_run) {
        info!("Termine. {total} IPs appliquees.");
    } else {
        error!("Le script PowerShell a echoue.");
    }

    // 5. Nettoyage du fichier temporaire
    let _ = std::fs::remove_file(PS1_TMP);
    info!("Log : {LOG_FILE}");
}
