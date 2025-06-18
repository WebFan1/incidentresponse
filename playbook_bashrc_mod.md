# Playbook: Event Triggered Execution – .bash_profile and .bashrc

## 🧠 Detection
- **Quelle:** Auditd / File Integrity Monitoring (FIM) / Elastic Agent
- **Rule-ID / Query:**
  ```elasticsearch
  tags : "bashrc_mod"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1546.004 – Event Triggered Execution: Unix Shell Configuration Modification

## 📌 Priorität
- **Einschätzung:** Hoch – Angreifer können durch Modifikation von `.bashrc` oder `.bash_profile` persistente Backdoors etablieren
- **Eskalationsstufe:** SOC-Level 3 – sofortige Überprüfung bei nicht autorisierten Änderungen

## 🚨 Initial Response
1. Dateiänderung analysieren: Wer hat wann welche Datei verändert?
2. Änderungsinhalt auslesen – wurden Befehle, Aliase oder Funktionen ergänzt?
3. Kontext analysieren: war dies ein interaktiver Nutzer, ein Skript oder Remote-Zugriff?

## 🔍 Forensik
- Diff der Datei (vorher/nachher) prüfen
- Benutzeraktivität zum Zeitpunkt der Änderung rekonstruieren
- Nachgelagerte Aktionen der veränderten Shellprofile beobachten
- Prozesse, Netzwerkverbindungen und gespeicherte Payloads auswerten

## 🛡️ Maßnahmen
- Datei zurücksetzen oder säubern
- Benutzerkonto sperren, wenn kompromittiert
- vollständige Analyse des Hosts und seiner Prozesse durchführen
- Monitoring auf ähnliche Aktivitäten auf anderen Hosts ausweiten

## 📋 Kommunikation
- Security-Team und zuständige Linux-Admins informieren
- Dokumentation mit Benutzer, Host, Dateiinhalt, Zeit
- Kommunikation an IR- und ggf. Forensik-Team eskalieren

## 📁 Artefakte
- Dateien: `~/.bashrc`, `~/.bash_profile`, `/etc/profile`
- Benutzer, Host, Zeitstempel
- Inhalt der Datei (besonders verdächtige Shellkommandos)
- Prozessverläufe (z. B. durch `.bash_history`, `audit.log`)

## ✅ Lessons Learned
- Integritätsüberwachung für Benutzer-Login-Skripte implementieren
- Interaktive Shells und Remote-Logins genauer protokollieren
- Awareness für Persistence-Mechanismen in Login-Shells stärken
- Default-Härtung der Shellprofile für nicht-admin User