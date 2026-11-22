# Server-Migration

## Starten ohne Herunterladen

Die folgende Zeile in **Windows PowerShell** einfügen:

```powershell
irm https://raw.githubusercontent.com/dominguez-posh/DNS-Parser/main/get.ps1 | iex
```

Aus `cmd`, über Win+R oder als Verknüpfung (startet die Windows PowerShell selbst, ohne Profil, Scriptfreigabe nur für diesen Prozess):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dominguez-posh/DNS-Parser/main/get.ps1 | iex"
```

Die Zeile lädt das neueste Release nach `%LOCALAPPDATA%\ServerMigration\<Version>` und startet das Tool. Gibt es noch kein Release, nimmt sie den Stand von `main`. Die Scriptfreigabe (`-ExecutionPolicy Bypass`) gilt nur für diesen einen Prozess, am System wird nichts umgestellt.

Für eine bestimmte Version vorher `$env:TOOL_REF = 'v1.0.0'` setzen.

## Was das Tool ist

Werkzeug für die Migration von Windows-Servern: DNS, DHCP, Printserver und Active Directory. Es besteht aus zwei Fenstern, die zusammenarbeiten:

- **Berater-Tool** auf dem Rechner des Beraters: Projektliste, Tauschordner, Auswertungen und Vergleiche.
- **Server-Fenster** auf dem Kundenserver (zum Beispiel über eine Bastion): sammelt, exportiert, importiert und führt die AD-Aktionen aus. Es wird mit einem Einzeiler aus dem Tauschordner gestartet, nichts muss vorab installiert werden.

> Stand: Das Tool ist bisher nur gegen nachgebaute Cmdlets und einen nachgebauten SharePoint-Server getestet. Was noch nicht an echten Systemen erprobt ist, steht in der [Anleitung](docs/ANLEITUNG.md#stand-und-noch-nicht-live-erprobt). Bitte erst in einer Testumgebung ausprobieren.

## Was es kann

| Bereich | Berater-Tool | Server-Fenster |
|---|---|---|
| **Projektliste** | Alle Projekte in einer verschlüsselten Datei (AES-256), über einen Freigabelink geteilt, mit Zusammenführen bei gleichzeitiger Änderung. Einzelne Projekte als Datei exportieren und importieren. | – |
| **Tauschordner** | Verbinden, Server-Paket ablegen, Einzeiler mit Prüfsumme erzeugen. | Ordner prüfen, Dateien in Teilen hochladen. |
| **DNS** | Debug-Logs auswerten: welche Clients fragen noch an, andere DNS-Server, Fehlerantworten, Namen, Zonen, Typen, Updates, Rohdaten. Export als CSV oder Excel. | DNS-Logging prüfen, ein- und ausschalten (alter Zustand wird wiederhergestellt), Logs mit Metadaten hochladen. |
| **DHCP** | Export vom alten Server mit dem Stand des neuen Servers vergleichen (Bereiche, Optionen, Reservierungen, Leases, Failover). | Export am alten Server, Import am neuen, Autorisierung in AD, Bereiche am alten Server deaktivieren, Stand hochladen. |
| **Print** | Inventuren alt und neu vergleichen, Druckzugriffe auswerten (je Benutzer, Rechner, Drucker), ungenutzte Drucker finden, Namen pseudonymisieren. | Export und Import mit PrintBrm, Inventur, Druckprotokoll (Ereignis 307) ein- und ausschalten und sammeln. |
| **Active Directory** | Berichte des Server-Fensters anzeigen (Ebenen, Schema, DCs, FSMO, Replikation, dcdiag). | Übersicht, FSMO übertragen oder übernehmen, DSRM-Kennwort, Funktionsebenen anheben, Schema-Update (adprep). |

Jede Änderung am Server hat eine Vorprüfung, eine Bestätigung im Fenster und eine Protokollzeile ohne Geheimnisse.

## Ablauf

```
 Berater-Rechner                  Tauschordner                    Kundenserver
 (Berater-Tool)               (SharePoint/OneDrive-Ordner)       (Server-Fenster)
 ───────────────              ────────────────────────────       ─────────────────
 Projektliste öffnen
 Projekt wählen
 "Paket ablegen"  ────────▶   SM-Server-Paket.zip
 Einzeiler kopieren                                    Einzeiler einfügen (Administrator)
                                                       ──▶ lädt Paket, prüft SHA256,
                                                           startet das Server-Fenster
                              ◀────────────────────────  Logs, Exporte, Inventuren,
                                                           Berichte (ZIP/JSON)
 Dateien holen,   ◀────────   SM-DNS-*.zip, DHCP-*,
 auswerten, vergleichen       Print-*, AD-Bericht-*
 Export vom alten Server ─▶   Export + Prüfsumme  ───────▶ Import am neuen Server
                                                           (nur mit passender Prüfsumme)
```

Der Tauschordner ist ein SharePoint- oder OneDrive-Ordner, der mit „Jeder mit dem Link kann bearbeiten“ geteilt ist. Der Link ist der Schlüssel zum Ordner (siehe [Sicherheit](docs/SICHERHEIT.md)).

<!-- Bild: Übersicht der beiden Fenster nebeneinander (Berater-Tool und Server-Fenster), mit Beispieldaten -->

## Kurzstart

1. Berater-Tool mit der Zeile oben starten.
2. Auf **Projekte** die Projektliste anlegen oder verbinden, ein Projekt anlegen, den Tauschordner-Link eintragen und das Projekt als aktiv wählen (dabei den Host des Links bestätigen).
3. Auf **Tauschordner** verbinden und **Paket ablegen**. Den Einzeiler kopieren.
4. Auf dem Kundenserver eine **Windows PowerShell als Administrator** öffnen und den Einzeiler einfügen.
5. Im Server-Fenster den Bereich wählen (DNS, DHCP, Print, Active Directory), im Berater-Tool auswerten und vergleichen.

Alle Schritte mit Meldungen und Hinweisen stehen in der [Anleitung](docs/ANLEITUNG.md).

## Anleitungen

| Dokument | Inhalt |
|---|---|
| [docs/ANLEITUNG.md](docs/ANLEITUNG.md) | Schritt für Schritt von der Projektliste bis zum Aufräumen, je Bereich. Mit Abschnitt „Stand und noch nicht live erprobt“. |
| [docs/SICHERHEIT.md](docs/SICHERHEIT.md) | Was die Prüfsummen schützen, akzeptiertes Risiko, personenbezogene Daten, nötige Rechte. |
| [docs/FEHLERBEHEBUNG.md](docs/FEHLERBEHEBUNG.md) | Fehlerbilder mit Ursache und Lösung. |
| [docs/security-checklist.md](docs/security-checklist.md) | Prüfpunkte für Änderungen am Einzeiler, Paket und Tauschordner (für Entwickler). |

## Sicherheit in Kürze

- Der Einzeiler prüft das Paket per SHA256, **bevor** etwas entpackt oder ausgeführt wird. Die Scriptfreigabe gilt nur für diesen einen Prozess.
- Es werden nur `https`-Ziele auf `*.sharepoint.com` akzeptiert, auch nach Weiterleitungen.
- DHCP- und Print-Importe laufen nur, wenn die vollständige Prüfsumme vom alten Server eingegeben wurde.
- Dateien aus dem Tauschordner gelten als nicht vertrauenswürdig: Größenlimits, XML ohne DTD, nie `Import-Clixml`.
- Der Tauschordner-Link kann im Verlauf und in den Protokollen des Kundenservers landen. Link mit kurzem Ablaufdatum anlegen und nach dem Projekt löschen.
- Gesammelte Daten (DNS-Logs, Leases, Druckprotokoll) sind personenbezogen. Nach dem Projekt im Tauschordner und lokal löschen.

Mehr dazu in [docs/SICHERHEIT.md](docs/SICHERHEIT.md).

## Aufbau des Repos

```
Start-ServerMigration.ps1   Berater-Tool (WPF, Windows PowerShell 5.1)
get.ps1                     Starter für den Einzeiler oben
DNSParser.ps1               Parser für DNS-Debug-Logs auf der Kommandozeile
server/                     Server-Fenster: Start-SmServer.ps1 und je Bereich ein Skript
Modules/                    Gemeinsame Funktionen (Tauschordner, Projekte, DNS, DHCP, Print, Export, Oberfläche)
UI/                         XAML der Oberflächen und das Farbschema (hell/dunkel)
tests/                      Tests je Bereich
docs/                       Anleitungen
```

Das Server-Paket (`SM-Server-Paket.zip`) enthält nur die Dateien, die das Server-Fenster braucht. Die Liste steht in `Modules/SmPaket.ps1`.

## Tests ausführen

Die Tests laufen mit **Windows PowerShell 5.1** (nicht PowerShell 7) und brauchen weder echte Server noch echte Tenants. Sie nutzen nachgebaute Cmdlets, einen nachgebauten SharePoint-Server auf `localhost` und Beispieldaten mit `contoso.local`.

```powershell
powershell.exe -NoProfile -STA -File tests\Test-ServerMigration.ps1   # Gerüst: Syntax, Fenster, Paket, Einzeiler, Tauschordner
powershell.exe -NoProfile -STA -File tests\Test-Projekte.ps1          # Projektliste
powershell.exe -NoProfile -STA -File tests\Test-Dns.ps1               # DNS (mit -LargeMB 500 für die volle Geschwindigkeitsmessung)
powershell.exe -NoProfile -STA -File tests\Test-Dhcp.ps1              # DHCP
powershell.exe -NoProfile -STA -File tests\Test-Print.ps1             # Print
```

Jede Zeile meldet `OK` oder `FAIL`. Die Tests zeigen, dass der Code gegen die nachgebauten Gegenstellen funktioniert, nicht dass er auf echten Servern funktioniert.
