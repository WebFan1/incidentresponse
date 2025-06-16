# Playbook: Archive via Utility (7-Zip)

## 🧠 Detection
- **Quelle:** Windows Sysmon Log
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "1" AND 
  process.executable : "C:\Program Files\7-Zip\7z.exe" AND 
  (process.args : *a* OR process.args : *-*)
  ```
- **MITRE ATT&CK Mapping:**  
  - T1560.001 – Archive Collected Data: Archive via Utility

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch – abhängig vom Kontext (z. B. Massendatenkompression außerhalb von Geschäftszeiten)
- **Eskalationsstufe:** SOC-Level 2–3 – bei gleichzeitiger externer Kommunikation kritisch

## 🚨 Initial Response
1. Prüfen, **welcher Benutzer** den Archivierungsvorgang gestartet hat
2. Kontext erfassen: Welcher Ordner, welche Dateien, wohin gespeichert?
3. Vorhergehende Aktivitäten analysieren (z. B. Massenzugriff auf Dateien)

## 🔍 Forensik
- Dateinamen und Speicherorte untersuchen
- Prüfen, ob Archiv verschlüsselt wurde
- Korrelieren mit Netzwerkaktivitäten (z. B. Upload, Transfer)
- Nutzung von Wechseldatenträgern untersuchen (USB, Netzlaufwerk)

## 🛡️ Maßnahmen
- Host ggf. isolieren
- Archivdateien sichern und analysieren (Inhalt, Größe, Typ)
- Benutzerrechte prüfen
- Monitoring auf weitere Archivierungs- oder Exfiltrationsversuche aktivieren

## 📋 Kommunikation
- IR-Team und Datenschutzbeauftragte informieren
- Abstimmung mit IT-Operations, ob legitimer Vorgang vorliegt
- Management benachrichtigen bei sensiblen Daten

## 📁 Artefakte
- Event ID 1 mit `7z.exe`-Nutzung
- Argumente des Prozesses (`a`, `-p`, `-t`)
- Dateipfade, Benutzername, Hostname
- ggf. Netzwerkverbindungen während oder nach der Archivierung

## ✅ Lessons Learned
- Archivierungsprogramme unter Sicherheitsüberwachung stellen
- Nutzung von Tools wie 7-Zip im Unternehmenskontext klar regeln
- Verschlüsselungsfunktionen in Archivtools separat prüfen (z. B. Passwortschutz bei ZIP-Dateien)