# Playbook: Linux Sniffing V 1.2 – Promiscuous Mode Detection

## 🧠 Detection
- **Quelle:** Elastic SIEM – Auditd über Elastic Agent
- **Rule-ID / Query:**
  ```elasticsearch
  data_stream.dataset : "auditd_manager.auditd" AND 
  tags : "promisc-mode-change" AND 
  process.executable : (
    "/usr/bin/dumpcap" OR 
    "/usr/bin/tshark" OR 
    *wireshark*
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1040 – Network Sniffing

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch (kann auf legitime oder bösartige Sniffing-Aktivitäten hinweisen)
- **Eskalationsstufe:** SOC-Level 2

## 🚨 Initial Response
1. Prüfen, ob das betroffene System autorisiert ist, Netzwerktraffic zu sniffen
2. Prozessdetails erfassen (Benutzer, Pfad, Parent, CmdLine)
3. Prüfen, ob es sich um geplante/legitime Netzwerkanalyse handelt

## 🔍 Forensik
- Audit-Logdetails sichern (Zeitpunkt, User, Kontext)
- Interface-Status abfragen (`ip link show`, `ethtool`)
- Aktive Prozesse prüfen (`ps`, `lsof`, `netstat`)
- Prüfen, ob Interface im Promiscuous Mode ist (`cat /sys/class/net/<iface>/flags`)

## 🛡️ Maßnahmen
- Prozess beenden, falls unautorisiert
- Netzwerkschnittstelle zurücksetzen
- Benutzerkontext untersuchen und ggf. sperren
- Whitelist-Management aktualisieren (Tool/Benutzer/System)

## 📋 Kommunikation
- IT-Security informieren
- Ggf. betroffene Systemverantwortliche oder Netzwerkteam einbeziehen
- Falls Verdacht auf Spionage/Abhören besteht: Incident Handling gemäß interner Policy

## 📁 Artefakte
- Prozessinformationen (Name, Pfad, UID, Parent)
- Interface-Status vor/nach Wechsel
- Auditd-Event-Details (mit `promisc-mode-change`)
- Hostname, IP-Adresse, Zeitstempel

## ✅ Lessons Learned
- Sniffing-Aktivitäten müssen klar dokumentiert und legitimiert sein
- Monitoring auf Promiscuous-Mode-Änderungen ausweiten
- Einsatz von IDS/IPS in kritischen Netzbereichen sinnvoll
- Awareness bei Admins für legitime vs. illegitime Netzwerktools stärken