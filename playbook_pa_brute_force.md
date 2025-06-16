# Playbook: PA Brute Force – Admin-Loginversuche in kurzer Abfolge

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Logon Events mit sequentieller Korrelation
- **Rule-ID / Query:**
  ```elasticsearch
  sequence by winlog.computer_name, source.ip with maxspan=10s 
  [authentication where event.action == "logon-failed" 
  and winlog.logon.type : "Network" 
  and source.ip != null 
  and source.ip != "127.0.0.1" 
  and user.name : "*admin*" 
  and not winlog.event_data.Status : (
    "0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")
  ] with runs=5
  ```
- **MITRE ATT&CK Mapping:**  
  - T1110 – Brute Force  
  - T1110.001 – Password Guessing

## 📌 Priorität
- **Einschätzung:** Hoch (gezielte Angriffe auf administrative Konten)
- **Eskalationsstufe:** SOC-Level 3 – unmittelbare Prüfung

## 🚨 Initial Response
1. Identifiziere die Ziel-Hosts und betroffenen Admin-Konten
2. Quell-IP analysieren – interner Angreifer, VPN, Botnet?
3. Prüfen, ob die Login-Versuche geblockt wurden oder Erfolg hatten

## 🔍 Forensik
- Quell-IP und zugehörige Geräte über DHCP/DNS zuordnen
- Benutzerhistorie analysieren (letzte erfolgreiche Anmeldungen)
- Eventkorrelation mit Event ID 4625, 4624, 4768 (Kerberos), 4771 (Pre-auth failure)
- Kontextprüfung: Zeit, Zielhost, Tools, Häufung

## 🛡️ Maßnahmen
- Benutzerkonto temporär sperren oder Passwort zurücksetzen
- Quell-IP blockieren oder auf Quarantäneliste setzen
- GPO prüfen: Lockout-Policy, MFA-Aktivierung für Admins
- Weiterleitung an Threat Hunt oder Incident Response

## 📋 Kommunikation
- IT-Sicherheitsleitung informieren
- Ggf. betroffene Admins benachrichtigen
- Bei Zugriff auf kritische Systeme: CISO- und Management-Eskalation

## 📁 Artefakte
- Event-Kette mit Zeitstempeln (Fehlversuche)
- IP-Adresse, Zielhost, Benutzername
- Log-Details zu verwendeten Protokollen und Statuscodes

## ✅ Lessons Learned
- Brute Force gegen Admins ist kritisch – sofortige Eskalation notwendig
- Ergänzende Regeln für Servicekonten und Domänenadmins sinnvoll
- Zeitfenster und Schwellenwert regelmäßig prüfen und optimieren
- Automatisierte Reaktion (z. B. Quarantäne, Lockout) prüfen