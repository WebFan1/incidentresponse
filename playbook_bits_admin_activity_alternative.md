# Playbook: Bits Admin Activity Alternative

## 🧠 Detection
- **Quelle:** Windows Eventlog – BITS Client
- **Rule-ID / Query:**
  ```elasticsearch
  event.provider : "Microsoft-Windows-Bits-Client" AND 
  (winlog.event_data.jobTitle : * OR winlog.event_data.LocalName: *) AND 
  NOT winlog.event_data.jobTitle: (
    "NucleusUpdateRingConfigJSON", 
    "PreSignInSettingsConfigJSON", 
    "UpdateDescriptionXml", 
    "Edge Component Updater", 
    "Font Download", 
    "UpdateBinary"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1197 – BITS Jobs  
  - T1105 – Ingress Tool Transfer

## 🧾 Erklärung der Regel
Diese Regel erkennt **verdächtige oder nicht standardmäßige Nutzung von BITS (Background Intelligent Transfer Service)**. BITS wird normalerweise für Systemupdates verwendet, kann jedoch auch von Angreifern missbraucht werden, um Dateien im Hintergrund herunterzuladen oder zu übertragen, ohne Alarm auszulösen.

Die Regel beobachtet:
- Ereignisse vom **Microsoft-Windows-Bits-Client**
- Es müssen Einträge in `jobTitle` oder `LocalName` vorhanden sein
- Es werden **bekannte legitime Jobtitel ausgeschlossen**, z. B. Edge-Komponenten oder Windows-Updates

Ziel: **Ungewöhnliche oder benutzerdefinierte BITS-Jobs** erkennen, z. B. solche, die ein Angreifer erstellt hat.

## 📌 Priorität
- **Einschätzung:** Hoch – kann auf Datei-Transfer durch Malware hinweisen
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. `jobTitle` und `LocalName` analysieren
2. Prüfen, ob Auftrag durch legitime Software erstellt wurde
3. Prüfen, ob Dateien heruntergeladen wurden und wohin

## 🔍 Forensik
- Prozess analysieren, der den BITS-Job erzeugt hat
- Ziel-URL, Zeitstempel und Zielverzeichnis prüfen
- Netzwerkverbindungen korrelieren
- Prüfen, ob `bitsadmin.exe` oder API genutzt wurde

## 🛡️ Maßnahmen
- Auftrag stoppen oder löschen
- URL blockieren
- Datei isolieren und analysieren (z. B. Hash prüfen)
- BITS-Logik im EDR oder durch Group Policy restriktiver konfigurieren

## 📋 Kommunikation
- IR-Team benachrichtigen
- Falls externe Kommunikation entdeckt: Management/DSB informieren
- Nutzerkommunikation bei verdächtigen Userkontexten

## 📁 Artefakte
- Eventdaten aus `Microsoft-Windows-Bits-Client`
- jobTitle, LocalName
- Netzwerk- und Datei-IO-Daten
- Hostname, Benutzername, Zeitstempel

## ✅ Lessons Learned
- BITS wird selten legitim außerhalb von Updates verwendet
- Whitelist regelmäßig pflegen
- Verdächtige Nutzungen mit Prozess-Korrelation kombinieren
- Regel regelmäßig anpassen, da neue legitime Jobs auftauchen können