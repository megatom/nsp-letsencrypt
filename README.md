# NoSpamProxy – Let's Encrypt

Holt ein Let's-Encrypt-Zertifikat per **acme-dns** (DNS-01), spielt es in die gewählten
NoSpamProxy-Konnektoren ein (Empfang und/oder Versand-Dispatcher) und richtet die tägliche
Erneuerung als geplante Aufgabe ein. Bei Fehlern kommt eine Mail.

Ersetzt den bisherigen Ablauf mit win-acme + Skript nur für den Empfangskonnektor.

## Voraussetzungen

- Windows Server 2019, 2022 oder 2025 **mit Desktopdarstellung** (kein Server Core, WPF fehlt dort)
- Windows PowerShell 5.1 (bei allen drei Versionen vorhanden), `$PSVersionTable.PSVersion`
- NoSpamProxy-PowerShell-Modul (auf dem NSP-Server vorhanden)
- Posh-ACME (das Fenster bietet die Installation aus der PowerShell Gallery an)
- Ausgehend: HTTPS zu `acme-v02.api.letsencrypt.org` und zum acme-dns-Server, DNS zu 1.1.1.1/8.8.8.8 (optional)

## Einrichtung auf einem Kundenserver

Beim Öffnen lädt das Fenster die Konnektoren und prüft den DNS-Eintrag selbst (sofern schon
API-Schlüssel bzw. Registrierung da sind). Grüne Meldungen neben den Knöpfen zeigen, was erledigt ist.

Ordner auf den NSP-Server kopieren, `Starten.cmd` doppelklicken (fragt nach Adminrechten).
Bei einer ZIP aus GitHub vorher: `Get-ChildItem <Ordner> | Unblock-File`.
Steht im Status „Posh-ACME fehlt“: *Posh-ACME installieren*. Dann die Schritte im Fenster
von oben nach unten – 1 und 2 ändern noch nichts:

1. **NSP-Zugang** (ab NoSpamProxy 16): Benutzer und Passwort eines NSP-Administrators eintragen
   (meist `Administrator`, bei Domänen `DOMÄNE\Administrator`), *API-Schlüssel anlegen*.
   Ab NSP 16 klappt `Connect-Nsp` nicht mehr automatisch mit dem Windows-Konto
   („Cannot connect without valid credentials“). Das Werkzeug legt deshalb einen API-Schlüssel
   `NspLetsEncrypt <Servername>` an und speichert nur diesen, nicht das Passwort.
   Rechte, die das Konto selbst nicht hat, lässt es weg.
2. **Konnektoren laden**, anhaken, was das Zertifikat bekommt.
   Vorausgewählt: Empfang auf Port 25 und der Default-Sendekonnektor.
3. **Host:** Auf neuen Servern liest das Fenster den Hostnamen aus der SMTP-Begrüßung des
   eigenen NoSpamProxy (`127.0.0.1:25`) und trägt ihn ein; sonst von Hand, z. B. `mail.firma.de`. Das Fenster prüft dann
   (auch beim Öffnen und mit *Prüfen*): Gibt es den Namen im öffentlichen DNS? Ist er Mailserver (MX)
   der Domain? Antwortet dort ein Mailserver auf Port 25? Nur Hinweise, nichts davon blockiert – Port 25
   ist von innen oft nicht erreichbar, obwohl es von außen geht.
4. **acme-dns:** *Registrieren*, dann beim DNS-Hoster der Domain (z. B. IONOS) einen CNAME anlegen (bzw. einen vorhandenen
   von win-acme auf das neue Ziel ändern):
   - Hostname: der Wert aus *DNS-Eintrag beim Hoster* (z. B. `_acme-challenge.mail`)
   - zeigt auf: der Wert aus *zeigt auf*

   *DNS prüfen*, bis es grün ist (der Hoster braucht oft ein paar Minuten; ein geänderter Eintrag ist wegen der TTL bis zu einer Stunde lang noch alt zu sehen).
5. **Mail bei Fehlern:** *Testmail senden*. Vorgabe ist Versand über NSP selbst an die lokale IP
   des Servers (von `localhost` lehnt NSP meist mit 5.4.4 ab), Absender `info@<Domain>`.
6. **Zertifikat holen, einspielen und Erneuerung einrichten**.
7. Optional **Erneuerung testen** – führt die nächtliche Prüfung sofort als SYSTEM aus und zeigt,
   dass die Aufgabe an Posh-ACME, den API-Schlüssel und NSP herankommt. Nötig ist es nicht.
8. Falls vorhanden: die alte **win-acme-Aufgabe deaktivieren** (Knopf erscheint im Status).
   Sonst setzt win-acme bei seiner nächsten Erneuerung den Empfangskonnektor zurück.

## Was wo liegt

| Pfad | Inhalt |
|---|---|
| `C:\ProgramData\NspLetsEncrypt\config.json` | Host, Umgebung, acme-dns-Registrierung, Konnektor-Auswahl, Mail, aktueller Thumbprint |
| `C:\ProgramData\NspLetsEncrypt\nsp-zugang.json` | NSP-API-Schlüssel (DPAPI, Rechner-Ebene), Id, Ablaufdatum |
| `C:\ProgramData\NspLetsEncrypt\posh-acme\` | Posh-ACME-Daten (Konto, Auftrag, Zertifikate) |
| `C:\ProgramData\NspLetsEncrypt\scripts\` | Kopie der Skripte, die die Aufgabe ausführt |
| `C:\ProgramData\NspLetsEncrypt\logs\JJJJ-MM.log` | Log aller Läufe |
| Aufgabenplanung: `NspLetsEncrypt Erneuerung` | täglich 03:17 (+ bis zu 2 h Zufall), als SYSTEM |
| Ereignisanzeige: Anwendung, Quelle `NspLetsEncrypt` | 1000 eingerichtet, 1001 erneuert, 1002 Fehler, 1003 Zertifikat läuft bald ab, 1004 API-Schlüssel läuft bald ab |

Der Ordner ist auf SYSTEM und Administratoren beschränkt (`config.json` enthält die acme-dns-Zugangsdaten,
`nsp-zugang.json` den API-Schlüssel).

## Erneuerung

`NspCert-Erneuern.ps1` läuft täglich:

1. `Submit-Renewal` – Posh-ACME erneuert nur, wenn es fällig ist.
2. Weicht das aktuelle Zertifikat vom gespeicherten Thumbprint ab **oder** steht in einem
   gewählten Konnektor ein anderer Thumbprint, wird neu eingespielt und danach gegengeprüft.
3. Das vorherige Zertifikat wird aus dem Speicher entfernt, aber nur wenn es von Let's Encrypt
   stammt und NSP es nirgends mehr verwendet.
4. Bei einem Fehler oder weniger als 10 Tagen Restlaufzeit: Log, Ereignis, Mail.
5. Der NSP-API-Schlüssel läuft nach etwa einem Jahr ab. Ab 60 Tagen Restlaufzeit verlängert
   die Aufgabe ihn selbst (`Reset-NspApiKeyLifetime`). Klappt das nicht, kommt ab 30 Tagen
   täglich eine Mail: im Fenster einen neuen Schlüssel anlegen.

Die Rechte des Schlüssels stehen oben in `NspLetsEncrypt.Common.ps1` (`$NleApiRechte`).

## Von Hand

Posh-ACME auf dieselben Daten zeigen lassen:

```powershell
$env:POSHACME_HOME = 'C:\ProgramData\NspLetsEncrypt\posh-acme'
Import-Module Posh-ACME
Get-PACertificate
```

Zertifikat erneut in die gespeicherten Konnektoren setzen:

```powershell
C:\ProgramData\NspLetsEncrypt\scripts\NspCert-Anwenden.ps1
C:\ProgramData\NspLetsEncrypt\scripts\NspCert-Anwenden.ps1 -Thumbprint <Thumbprint>
```

Staging (Testumgebung von Let's Encrypt, nicht vertrauenswürdige Zertifikate) gibt es im Fenster
nicht mehr. Nur falls man den Abruf oft hintereinander probieren muss (Grenzen von Let's Encrypt):
in `config.json` `"Server": "LE_STAGE"` setzen und dabei **keine** Konnektoren anhaken.

## Updates

Beim Öffnen fragt das Fenster `version.json` in diesem Repo ab. Ist dort eine neuere Version
eingetragen, erscheint im Status „Neue Version … verfügbar“ mit den Änderungen und dem Knopf
*Aktualisieren*. Der lädt das ZIP genau dieses Git-Tags, prüft es (alle Dateien da, Versionsnummer
passt, Skripte fehlerfrei) und ersetzt die Dateien im Programmordner und in
`C:\ProgramData\NspLetsEncrypt\scripts`. Danach startet das Fenster neu. Die nächtliche Aufgabe
aktualisiert sich nie selbst.

Neue Version veröffentlichen:

1. `$NleVersion` oben in `NspLetsEncrypt.Common.ps1` hochsetzen (Format `JJJJ.MM.TT`, bei mehreren
   am selben Tag `JJJJ.MM.TT.2`).
2. `version.json`: `Version`, `Tag` (`v` + Version) und `Aenderungen` eintragen.
3. Committen, Tag setzen und beides zusammen pushen:

   ```bash
   git tag v2026.10.05
   git push origin main --tags
   ```

## Offline-Installation von Posh-ACME

Ohne Internetzugang zur PowerShell Gallery auf einem anderen Rechner:

```powershell
Save-Module Posh-ACME -Path C:\temp
```

und den Ordner `Posh-ACME` nach `C:\Program Files\WindowsPowerShell\Modules\` auf dem Server kopieren.
