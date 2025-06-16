# Playbook: Sniffing Detection – Promiscuous Mode Activation

## 🧠 Detection
- **Quelle:** Elastic SIEM – Auditd (Linux) / Auditbeat
- **Rule-ID / Query:**
  ```elasticsearch
  (auditd.log.record_type : "ANOM_PROMISCUOUS" OR auditd.log.record_type : "EXECVE")
  AND process.args : *promisc* AND process.args : *on*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1040 – Network Sniffing  
  - T1562 – Impair Defenses (bei verdecktem Einsatz)

## 📌 Priorität
- **Einschätzung:** Hoch (Hinweis auf Sniffing-Versuch oder Netzwerkanalyse durch Angreifer)
- **Eskalationsstufe:** SOC-Level 3

## 🚨 Initial Response
1. Quell-Host und Benutzer ermitteln – Admin oder verdächtiger User?
2. Prozess analysieren, der Promiscuous Mode aktivierte (z. B. `ip`, `ifconfig`, `tcpdump`)
3. Wenn Aktivierung nicht durch legitimes Monitoring → Incident einleiten

## 🔍 Forensik
- Prozesskette und -argumente analysieren (Command Line)
- Prüfen, ob Tools wie `tcpdump`, `wireshark`, `ettercap`, `dsniff` ausgeführt wurden
- Logs des Systems sichern (Bash History, Auditd, Netzwerkauslastung)
- Überprüfen, ob sensible Daten (z. B. Authentifizierungsdaten) abgefangen wurden

## 🛡️ Maßnahmen
- Prozess stoppen, Host ggf. isolieren
- Benutzerkonto sperren oder unter Monitoring stellen
- Applocker / sudoers anpassen, um Zugriff auf Sniffing-Tools zu kontrollieren
- Sniffing Detection dauerhaft aktivieren

## 📋 Kommunikation
- IT-Security-Team sofort benachrichtigen
- Incident-Response-Team involvieren
- Management informieren, wenn Hinweis auf Spionage oder internen Missbrauch vorliegt

## 📁 Artefakte
- Auditd Events mit `ANOM_PROMISCUOUS` oder `EXECVE`
- Prozessdetails: Name, Pfad, Argumente
- Benutzerinformationen, Terminal, Zeitpunkt
- Liste der Netzwerkgeräte im promisc-Modus

## ✅ Lessons Learned
- Legitimes Monitoring sauber dokumentieren und whitelisten
- Sniffing Detection als feste Auditregel definieren
- Regel auf bestimmte Tools oder Kombinationen erweitern (z. B. Interface + Capture)
- Awareness bei Admins schärfen – Interface-Modusänderung sollte nie unbeobachtet bleiben