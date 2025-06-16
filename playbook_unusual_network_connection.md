# Playbook: Unusual Network Connection

## 🧠 Detection
- **Quelle:** Windows Sysmon (Event ID 3 – Network Connection)
- **Rule-ID / Query (EQL):**
  ```eql
  sequence by host.name with maxspan=1m 
    [any where event.code == 3 and process.name == "svchost.exe" and network.transport == "tcp"] 
    [any where event.code == 3 and rule.name == "Usermode"]
  ```

- **MITRE ATT&CK Mapping:**  
  - T1071 – Application Layer Protocol  
  - T1043 – Commonly Used Port  
  - T1027 – Obfuscated Files or Information (bei untypischer rule.name)

## 📌 Priorität
- **Einschätzung:** Hoch – Kombination aus svchost.exe TCP-Verbindungen und nicht-standardmäßiger Filterregel (Usermode)
- **Eskalationsstufe:** SOC-Level 3 – sofort untersuchen, potenzielle Command & Control oder Datenexfiltration

## 🚨 Initial Response
1. Verbindungshost und Ziel-IP identifizieren
2. Prozessdetails und Elternprozess analysieren
3. Prüfen, ob svchost.exe legitim oder injected ist (z. B. DLL Injection)
4. Verbindungsport, Protokoll und Ziel-Domain analysieren

## 🔍 Forensik
- Prozess-Metadaten und Netzwerkverhalten korrelieren
- Traffic-Dump analysieren (sofern möglich)
- Verhalten anderer Prozesse im Zeitraum prüfen
- Ziel-IP reputationsbasiert bewerten

## 🛡️ Maßnahmen
- Verbindung blockieren oder Host isolieren
- Prozess beenden (nach forensischer Sicherung)
- IOC-Blockierung über Firewall/SIEM/SOAR konfigurieren
- Endpoint weiter überwachen

## 📋 Kommunikation
- IT-Security-Team und ggf. Network Engineering involvieren
- Analysebericht für Incident-Dokumentation erstellen
- Bei externem Ziel ggf. Threat Intel informieren

## 📁 Artefakte
- Sysmon Event ID 3
- Prozessname: svchost.exe
- TCP-Ziel, Port, rule.name = "Usermode"
- Zeitstempel, Hostname, Benutzer

## ✅ Lessons Learned
- Network Connection baselines regelmäßig aktualisieren
- svchost.exe-Nutzung im Netzwerkzugriff einschränken
- Logging und Alerting auf verdächtige rule.name-Kombinationen verbessern