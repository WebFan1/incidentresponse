# Playbook: Registry Value "ProxyEnable" Set – Verdächtige Proxy-Aktivierung

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Registry Event Monitoring)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "13"
  AND winlog.event_data.EventType: "SetValue"
  AND winlog.task : "Registry value set (rule: RegistryEvent)"
  AND registry.value : "ProxyEnable"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1112 – Modify Registry  
  - T1557 – Adversary-in-the-Middle (bei Verwendung für Traffic Redirection)

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch (je nach Kontext und Zielsystem)
- **Eskalationsstufe:** SOC-Level 2

## 🚨 Initial Response
1. Ermitteln, welcher Prozess die Änderung durchgeführt hat (Parent/Child, Path)
2. Kontext prüfen:
   - Legitimer IT-Prozess?
   - Unbekannter Pfad oder auffälliger Parent-Prozess?
3. Falls verdächtig:
   - Host analysieren
   - User und Prozesse isolieren oder unter Beobachtung stellen

## 🔍 Forensik
- Registry-Änderungen im Kontext betrachten: Wann? Was wurde zusätzlich verändert?
- Sysmon-Ereignisse zum Prozess identifizieren (Event ID 1, 13)
- Netzwerkanalyse: Wird ein Proxy tatsächlich verwendet? Wohin zeigt er?
- Useraktivitäten und Login-Zeiten untersuchen
- Persistenz prüfen: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

## 🛡️ Maßnahmen
- Registry-Wert auf Standard zurücksetzen (sofern nicht gewünscht)
- Host isolieren, wenn zusätzliche Anzeichen für MITM-Aktivitäten bestehen
- Erkennungsschwelle ergänzen: Kombination mit `ProxyServer`-Wert
- GPO prüfen: Wird dort Proxy eingestellt?

## 📋 Kommunikation
- Security- und Netzwerkteam informieren (Proxy-Verkehr prüfen)
- IT-Team involvieren, wenn zentral gesteuerte Änderung vermutet wird
- Dokumentation im SIEM-Ticket / Vorfallbericht

## 📁 Artefakte
- Sysmon Event ID 13
- Registry Key/Value Name, alter/neuer Wert
- Prozessname, Kommandozeile, Parent-Prozess
- Hostname, Benutzername, Zeitstempel

## ✅ Lessons Learned
- Regel ggf. erweitern um `ProxyServer` zur Bewertung des Ziels
- Verdächtige Prozesse wie `mshta.exe`, `powershell.exe` mit Registryzugriff korrelieren
- Proxy-Einstellungen zentral per GPO absichern
- Regel in MITM-Erkennungsstrategie einbetten