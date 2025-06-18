# Playbook: System Information Discovery

## 🧠 Detection
- **Quelle:** Verschiedene Logquellen (PowerShell, Sysmon, Auditd etc.)
- **Rule-ID / Query:**
  ```elasticsearch
  tags: "sysinfo_discovery"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1082 – System Information Discovery

## 📌 Priorität
- **Einschätzung:** Mittel – Hinweis auf Reconnaissance oder Vorbereitungsphase eines Angreifers
- **Eskalationsstufe:** SOC-Level 2 – Analyse erforderlich, ob legitime oder bösartige Nutzung

## 🚨 Initial Response
1. Prozess, Befehl und Benutzer identifizieren
2. Parent-Prozess analysieren (z. B. durch Malware oder interaktive Sitzung?)
3. Kontext prüfen – Initialzugriff, Remoteverbindung, Skript?

## 🔍 Forensik
- Kommandozeile und verwendetes Tool analysieren (z. B. `systeminfo`, `Get-WmiObject`)
- Hostname, Benutzer, Zeit prüfen
- Korrelation mit weiteren Aktivitäten (Netzwerkerkennung, Benutzerlistenabfragen etc.)

## 🛡️ Maßnahmen
- Prozess ggf. blockieren oder User sperren
- Host aktiv überwachen (z. B. weitere Recon oder C2-Aktivität)
- IOC sichern (CommandLine, Pfade, ggf. Tools)

## 📋 Kommunikation
- SOC-Team und ggf. IT-Support informieren
- Dokumentation mit Host, User, Zeit, Kontext
- bei Eskalation: Weitergabe an IR-Team

## 📁 Artefakte
- Kommandozeile (`systeminfo`, `Get-ComputerInfo`, `hostname`, `uname`, `wmic`)
- Benutzerkontext, Hostname, Uhrzeit
- Prozessbaum (Parent, Child-Prozesse)

## ✅ Lessons Learned
- SOC-Regel zur Systeminfo-Erkennung regelmäßig verfeinern
- Whitelisting bekannter Tools oder Admin-Kontexte definieren
- Angriffssimulationen (z. B. Red Team, Atomic Red Team) nutzen zur Testabdeckung