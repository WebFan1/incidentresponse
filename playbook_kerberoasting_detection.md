# Playbook: Kerberoasting Detection

## 🧠 Detection
- **Quelle:** Windows Security Eventlog – Kerberos Service Ticket Request
- **Rule-ID / Query:**
  ```elasticsearch
  event.code: ("4770" OR "4769") AND 
  winlog.event_data.Status : "0x0" AND 
  winlog.event_data.TicketEncryptionType : ("0x12" OR "0x17" OR "0x1")
  ```
- **MITRE ATT&CK Mapping:**  
  - T1558.003 – Kerberoasting

## 📌 Priorität
- **Einschätzung:** Hoch – Hinweis auf Versuch, Service Tickets mit schwacher Verschlüsselung zu extrahieren
- **Eskalationsstufe:** SOC-Level 3 – potentieller Credential Dump oder Angriffsvorbereitung

## 🚨 Initial Response
1. Prüfen, welcher Benutzer und welche SPN betroffen sind
2. Abgleich: Tritt SPN normal auf? Wird er häufig genutzt?
3. Kontext prüfen: kommt die Abfrage von legitimen Applikationen oder Skripten?

## 🔍 Forensik
- Korrelation mit Logons desselben Users (4624, 4768)
- Hashing-Tools wie Rubeus/Mimikatz erkennen: Timing, Batch-Abfragen
- Ticket-Nutzung auf Zielsystem analysieren (Event ID 5140, 5156)

## 🛡️ Maßnahmen
- Account mit schwacher SPN-Absicherung identifizieren
- AES-Only & Strong Passwords für Service-Accounts durchsetzen
- SPNs mit restriktiven Delegierungen konfigurieren
- Tools wie `Set-ADUser` zur TicketEncryptionType-Absicherung einsetzen

## 📋 Kommunikation
- IT-Security Team & ggf. AD-Administrator informieren
- Risiko einschätzen und ggf. IR-Prozess einleiten
- Kontext und Maßnahmen dokumentieren (Ticketnummer, User, Zeit)

## 📁 Artefakte
- Eventlogs: 4769/4770 mit SPN, EncryptionType, User
- Hostname, IP, Domänenrolle
- Benutzerkontext & Prozessdetails (falls EDR vorhanden)

## ✅ Lessons Learned
- Schwache Verschlüsselung (RC4) erlaubt Offline-Crackversuche
- Monitoring auf SPN-Aktivität & Service-Ticket-Ausgabe verbessern
- Regelmäßige Passwort-Rotation & Audits für Service-Accounts