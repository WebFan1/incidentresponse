# Playbook: Kerberos Ticket Dump Detection

## 🧠 Detection
- **Quelle:** Elastic SIEM – PowerShell ScriptBlock Logging
- **Rule-ID / Query:**
  ```elasticsearch
  event.category:process AND 
  host.os.type:windows AND 
  powershell.file.script_block_text : (
    "LsaCallAuthenticationPackage" AND (
      "KerbRetrieveEncodedTicketMessage" OR 
      "KerbQueryTicketCacheMessage" OR 
      "KerbQueryTicketCacheExMessage" OR 
      "KerbQueryTicketCacheEx2Message" OR 
      "KerbRetrieveTicketMessage" OR 
      "KerbDecryptDataMessage"
    )
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1558 – Steal or Forge Kerberos Tickets  
  - T1558.003 – Kerberoasting  
  - T1558.004 – AS-REP Roasting

## 📌 Priorität
- **Einschätzung:** Kritisch – Zugriff auf Kerberos-Tickets möglich
- **Eskalationsstufe:** SOC-Level 3 – C2-Kommunikation oder Lateral Movement vorbereitend

## 🚨 Initial Response
1. Vollständigen Scriptblock analysieren
2. Benutzer- und Hostkontext bestimmen
3. Prüfen, ob Tools wie Rubeus, Mimikatz oder Custom Scripts aktiv sind

## 🔍 Forensik
- PowerShell Logging (ScriptBlock) und EDR-Daten korrelieren
- Prüfen, ob Kerberos-Tickets exportiert, gespeichert oder übertragen wurden
- Lsass.exe-Zugriffe untersuchen (ggf. parallele Credential Dumping Versuche)
- Authentifizierungsversuche in Domäne untersuchen (KDC Logs, 4769/4770 Events)

## 🛡️ Maßnahmen
- Host isolieren
- Benutzerkonto sperren oder zurücksetzen
- Alle Kerberos-Tickets des Systems ungültig machen (z. B. Ticket Purge via `klist`)
- PowerShell ExecutionPolicy verschärfen
- Scriptblock-Logging dauerhaft aktivieren

## 📋 Kommunikation
- Incident Response Team alarmieren
- CISO und ggf. Datenschutzbeauftragter bei exfiltrierten Credentials informieren
- Dokumentation im SOC-Ticket mit IOC-Zusammenfassung

## 📁 Artefakte
- PowerShell ScriptBlock Text
- User- und Hostdaten
- Prozessinformationen
- Zeitstempel, Netzwerkinformationen
- Eventlogs aus dem Security Channel (Kerberos Events)

## ✅ Lessons Learned
- Kerberos-Ticket-Manipulation ist hochkritisch – vollständiges SIEM-Mapping notwendig
- Kombination mit Regeln zu Lsass, Dump-Tools, Prozessinjektion und AD-Enum empfehlenswert
- Awareness und Monitoring für bekannte Tools wie Rubeus, Kekeo, Mimikatz erweitern