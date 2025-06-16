# Playbook: WPAD Activity – Verdächtige Netzwerkverbindungen zu WPAD

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon Network Connections (Event ID 3)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "3"
  AND message : *wpad*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1557 – Adversary-in-the-Middle  
  - T1557.001 – LLMNR/NBT-NS Poisoning and WPAD Relay

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch (abhängig von Netzwerkdesign)
- **Eskalationsstufe:** SOC-Level 2

## 🚨 Initial Response
1. Prüfen, welches System eine Verbindung zu "wpad" aufbaut (Hostname, Benutzer)
2. DNS- oder Proxy-Logs sichten → Wird ein echter WPAD-Server erreicht?
3. Kontext bewerten: legitime Proxy-Nutzung oder interne/externe Manipulation?

## 🔍 Forensik
- Ziel-IP und Port analysieren (HTTP, HTTPS, andere?)
- DNS-Log: Welche IP wurde zu "wpad" aufgelöst?
- Quellprozess identifizieren: Wer hat die Verbindung ausgelöst?
- DHCP, ARP, Hostname prüfen – gibt es Rogue Devices im Netz?
- Tools wie Responder, Inveigh oder MITM6 auf verdächtigen Hosts prüfen

## 🛡️ Maßnahmen
- Falls keine legitime WPAD-Nutzung:
  - DNS-Antwort für "wpad" per Blackhole/Sinkhole konfigurieren
  - WPAD im Browser und via GPO deaktivieren
- Host mit Verbindung zu WPAD unter Beobachtung stellen
- Monitoring für verwandte Aktivitäten aktivieren: `LLMNR`, `NBNS`, `mDNS`

## 📋 Kommunikation
- Netzwerkteam involvieren (Analyse DNS/Proxy/Netzwerkverkehr)
- Security-Team über potenziellen MITM-Vektor informieren
- Kein Benutzerkontakt nötig, außer Kompromittierung ist bestätigt

## 📁 Artefakte
- Sysmon Event ID 3 (Netzwerkverbindung)
- Quellhost, Ziel-IP, Port, Prozessinformationen
- DNS-Anfrage und -Antwort
- ggf. zugehörige Registry- oder Browser-Einstellungen

## ✅ Lessons Learned
- WPAD sollte deaktiviert werden, wenn nicht explizit benötigt
- Regel ergänzen durch Kombination mit DNS-Events (Event ID 22)
- Awareness für stille MITM-Vektoren erhöhen
- Angreifer nutzen häufig WPAD, um Datenverkehr umzuleiten oder Credentials abzufangen