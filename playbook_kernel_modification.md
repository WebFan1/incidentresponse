# Playbook: Kernel Modification

## 🧠 Detection
- **Quelle:** Auditd, Sysmon for Linux, Elastic Agent
- **Rule-ID / Query:**
  ```elasticsearch
  tags: "kernel_mod_load" OR process.args : *insmod*
  ```

- **MITRE ATT&CK Mapping:**  
  - T1547.006 – Boot or Logon Autostart Execution: Kernel Modules and Extensions

## 📌 Priorität
- **Einschätzung:** Hoch bis kritisch – Kernel-Modifikationen stellen ein Risiko für vollständige Kompromittierung und Unsichtbarkeit (Rootkits) dar
- **Eskalationsstufe:** SOC-Level 3 – sofortige forensische Analyse notwendig

## 🚨 Initial Response
1. Sofortige Prüfung des ausführenden Prozesses und Benutzers
2. Kontext analysieren: Wurde `insmod`, `modprobe` oder ein verdächtiges Modul geladen?
3. Prüfen, ob Modul dauerhaft eingebunden oder nur temporär verwendet wurde

## 🔍 Forensik
- Kernelmodul-Namen und Pfade analysieren
- Vergleich mit bekannten legitimen Kernelmodulen (Whitelist)
- `dmesg`, `lsmod`, `modinfo` zur Laufzeit verwenden
- Prüfen, ob zusätzliche Backdoors oder versteckte Prozesse aktiv sind

## 🛡️ Maßnahmen
- Modul entladen (falls sicher möglich)
- betroffenen Host isolieren
- vollständige Speicheranalyse (Volatility, LiME)
- eventuell Neuinstallation/Neuaufsetzen bei Rootkit-Verdacht

## 📋 Kommunikation
- Incident Response und Forensik sofort einbinden
- Systemadministration informieren (bei legitimen Modulen mit falschem Alarm aufklären)
- Dokumentation mit Modul, Hash, Benutzer, Zeitpunkt

## 📁 Artefakte
- Pfad und Name des Kernelmoduls
- Kommandozeile (`insmod`, `modprobe`)
- Log-Quellen: `audit.log`, `syslog`, `dmesg`
- Benutzer, Hostname, Timestamp
- Speicherabbild bei Rootkit-Verdacht

## ✅ Lessons Learned
- Whitelist erlaubter Kernelmodule definieren
- Monitoring auf Kernelmodule, insmod/modprobe aktivieren
- Kernel Lockdown Mode prüfen (falls verfügbar)
- Integritätsprüfung mit IMA, SELinux, AppArmor stärken