# Playbook: Registry Value “ProxyEnable” Set

## 🧠 Detection
- **Quelle:** Windows Security / Sysmon über Winlogbeat oder Elastic Agent
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "13" AND
  winlog.event_data.EventType: "SetValue" AND
  winlog.task : "Registry value set (rule: RegistryEvent)" AND
  registry.value : "ProxyEnable"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1112 – Modify Registry  
  - T1090 – Proxy

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch – das Setzen von `ProxyEnable` kann für Traffic Redirection, Tunneling oder Umgehung interner Sicherheitsrichtlinien missbraucht werden
- **Eskalationsstufe:** SOC-Level 2 (bei legitimer Admin-Aktion) bis Level 3 (bei unbekanntem Kontext)

## 🚨 Initial Response
1. Benutzer identifizieren, der die Änderung vorgenommen hat
2. Kontext analysieren: Parent-Prozess, Zeitpunkt, Zielwert
3. Prüfen, ob zeitgleich neue Proxyeinstellungen konfiguriert wurden

## 🔍 Forensik
- Registry-Schlüssel-Inhalt vor/nach Änderung vergleichen
- Prozessanalyse: Wer hat den Schlüssel verändert?
- Prüfen, ob Proxy über GPOs oder manuell gesetzt wurde
- Netzwerkanalyse: Gibt es Verbindungen über neue Proxyrouten?

## 🛡️ Maßnahmen
- Registry-Wert zurücksetzen, wenn nicht autorisiert
- Benutzeraktivität weiter untersuchen
- Monitoring- und Proxyregeln verschärfen
- System ggf. temporär isolieren

## 📋 Kommunikation
- IT-Security-Team informieren
- Registry-Wertänderung dokumentieren
- Kommunikation mit IT/Netzwerkteam über Proxy-Auswirkungen

## 📁 Artefakte
- Registry Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable`
- Benutzer, Hostname, Prozess
- Zeitpunkt der Änderung
- ggf. URL-/IP-Ziele nach Änderung

## ✅ Lessons Learned
- Registry Monitoring erweitern für kritische Schlüssel wie Proxy, Autorun etc.
- Proxy-Einstellungen über GPO verwalten und absichern
- Alert auf `ProxyEnable`-Änderung in Change-Auditing-Prozess aufnehmen