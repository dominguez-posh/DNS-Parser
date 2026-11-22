# Anleitung: Server-Migration Schritt für Schritt

Diese Anleitung führt durch eine Migration von DNS, DHCP, Printserver und Active Directory. Alle Beispiele nutzen `contoso.local`, Adressen aus `10.0.0.0/8` und `contoso-my.sharepoint.com`. Das sind Beispielwerte, keine echten Daten.

Verwandte Dokumente: [Sicherheit](SICHERHEIT.md) · [Fehlerbehebung](FEHLERBEHEBUNG.md) · [README](../README.md)

## Inhalt

1. [Voraussetzungen](#voraussetzungen)
2. [Projektliste anlegen und teilen](#1-projektliste-anlegen-und-teilen)
3. [Projekt anlegen](#2-projekt-anlegen)
4. [Tauschordner anlegen und Link eintragen](#3-tauschordner-anlegen-und-link-eintragen)
5. [Paket ablegen und Einzeiler auf dem Kundenserver](#4-paket-ablegen-und-einzeiler-auf-dem-kundenserver)
6. [DNS](#5-dns)
7. [DHCP](#6-dhcp)
8. [Print](#7-print)
9. [Active Directory](#8-active-directory)
10. [Aufräumen](#9-aufräumen)
11. [Stand und noch nicht live erprobt](#stand-und-noch-nicht-live-erprobt)

## Voraussetzungen

| Wo | Was |
|---|---|
| Berater-Rechner | Windows mit Windows PowerShell 5.1 (WPF-Oberfläche). Zugriff auf GitHub für den Start und auf `*.sharepoint.com`. |
| Tauschordner | Ein SharePoint- oder OneDrive-Ordner, den du teilen kannst („Jeder mit dem Link kann bearbeiten“). |
| Kundenserver | Windows PowerShell 5.1 **als Administrator**. Zugriff auf `*.sharepoint.com` (auf GitHub nicht). |
| DNS | DNS-Rolle mit den DNS-Cmdlets (`Get-DnsServerDiagnostics`, `Set-DnsServerDiagnostics`). |
| DHCP | DHCP-Rolle mit Modul `DhcpServer`, Dienst `DHCPServer` läuft. |
| Print | Rolle Druckserver, `PrintBrm.exe` unter `%windir%\System32\spool\tools`, Dienst Druckspooler läuft. |
| AD | Modul `ActiveDirectory` (auf DCs vorhanden, sonst `Install-WindowsFeature RSAT-AD-PowerShell`) auf dem **neuen** Domänencontroller. |

Das Server-Fenster arbeitet immer an dem Server, auf dem es läuft. Hat ein Server keinen Zugang zu `*.sharepoint.com`, funktioniert der Einzeiler dort nicht. Eine Fernverwaltung über einen Admin-Server mit RSAT ist nicht umgesetzt (siehe [Stand](#stand-und-noch-nicht-live-erprobt)).

Welche Rechte genau nötig sind, steht in [SICHERHEIT.md](SICHERHEIT.md#rechte-die-nötig-sind).

## Berater-Tool starten

Die Zeile aus der [README](../README.md) in Windows PowerShell einfügen. Das Berater-Tool öffnet sich mit der Navigation links: **Tauschordner**, **Projekte**, **DNS**, **DHCP**, **Print**, **Active Directory**. In der Titelleiste wechselst du zwischen hellem und dunklem Design.

<!-- Bild: Berater-Tool, Startseite „Tauschordner und Server-Paket“, hell -->

## 1. Projektliste anlegen und teilen

Alle Projekte stehen in **einer** verschlüsselten Datei (`ServerMigration-Projekte.smproj`) in einem Ordner. Wer den Ordnerlink und das Kennwort hat, sieht dieselben Projekte.

1. Lege in OneDrive oder SharePoint einen **eigenen Ordner** für die Projektliste an, zum Beispiel `ServerMigration-Projekte`. Nimm dafür nicht den Tauschordner eines Kunden: In der Liste stehen die Links aller Projekte.
2. Teile den **Ordner** (nicht eine Datei) mit der Einstellung **„Jeder mit dem Link kann bearbeiten“**. Kopiere den Link. Er sieht so aus: `https://contoso-my.sharepoint.com/:f:/g/personal/...`
3. Öffne im Berater-Tool die Seite **Projekte**.
4. Füge den Link in **Freigabelink des Ordners** ein.
5. Klicke auf **Neue Liste anlegen**. Im Dialog vergibst du das Kennwort der Liste zweimal.
   - Mindestens **12 Zeichen**. Besser ist eine Passphrase aus mehreren Wörtern.
   - Das Kennwort wird nirgends gespeichert. Ohne Kennwort sind die Projekte nicht lesbar. Bewahre es gut auf.
6. Der Status zeigt **Neue Liste angelegt und verbunden**.

Die Datei ist mit AES-256 verschlüsselt, der Schlüssel entsteht aus dem Kennwort (PBKDF2). Einen SharePoint-Kennwortschutz brauchst du nicht.

Weitere Personen verbinden sich mit demselben Link und demselben Kennwort über **Verbinden**.

| Knopf | Bedeutung |
|---|---|
| Verbinden | Liste lesen und entschlüsseln. |
| Neu laden | Aktuellen Stand aus dem Ordner holen. |
| Kennwort auf diesem Rechner merken | Speichert Link und Kennwort verschlüsselt (Windows-Schutz, nur dieser Benutzer auf diesem Rechner). |
| Gemerkte Verbindung löschen | Entfernt die gemerkten Werte wieder. |

**Gleichzeitige Änderungen.** Speichern zwei Personen gleichzeitig, bekommt die zweite eine Meldung „Konflikt, nichts gespeichert“. Deine Änderung geht dabei nicht verloren, sie wird nur nicht gespeichert. Mit **Zusammenführen** wird neu geladen und deine Änderung je Projekt auf den neuen Stand gelegt. Ändern beide dasselbe Projekt unterschiedlich, fragt das Tool nach. **Neu laden (Änderung verwerfen)** verwirft deine Änderung.

> Wer den Ordnerlink hat, kann eine ältere Fassung der Datei wieder einspielen. Sie bleibt verschlüsselt, ist dann aber veraltet.

<!-- Bild: Seite „Projekte“ mit verbundener Liste (Beispielprojekte), hell -->

## 2. Projekt anlegen

1. Auf **Projekte** auf **Neues Projekt** klicken.
2. Ausfüllen:

   | Feld | Inhalt |
   |---|---|
   | Name | Zum Beispiel `Contoso Migration 2026` |
   | Kunde | Freitext |
   | Status | Geplant, Laufend, Abgeschlossen oder Archiviert |
   | Tauschordner-Link dieses Projekts | Kommt nach Schritt 3, kann zunächst leer bleiben |
   | Notizen | Freitext |
   | Server | Name (Buchstaben, Ziffern, Punkt, Bindestrich), Rolle (DNS, DHCP, Print, DC) und alt oder neu, jeweils mit **Hinzufügen** |

3. **Speichern**. Die Liste wird sofort verschlüsselt in den Ordner geschrieben.

Weitere Funktionen: **Bearbeiten**, **Löschen** (gilt für alle, die die Liste nutzen), die Suche über Name, Kunde, Notizen, Status und Servernamen.

**Projekt weitergeben.** **Exportieren** schreibt ein einzelnes Projekt in eine `.smproj`-Datei mit einem eigenen Kennwort (dem Empfänger getrennt mitteilen). **Importieren** liest sie wieder ein. Gibt es das Projekt schon, fragt das Tool, ob es ersetzt oder als Kopie angelegt wird. Einen Tauschordner-Link aus einer fremden Datei übernimmt das Tool nie ungefragt (siehe nächster Abschnitt).

## 3. Tauschordner anlegen und Link eintragen

Der Tauschordner ist der Austauschort zwischen Berater-Rechner und Kundenserver. Je Projekt ein eigener Ordner.

1. Lege in OneDrive oder SharePoint einen Ordner an, zum Beispiel `Tausch-Contoso`.
2. Teile ihn mit **„Jeder mit dem Link kann bearbeiten“** und setze ein **kurzes Ablaufdatum**. Kopiere den Ordnerlink.
3. Bearbeite das Projekt und trage den Link bei **Tauschordner-Link dieses Projekts** ein. Speichern.
4. Wähle das Projekt in der Liste und klicke **Als aktives Projekt wählen**.
5. Beim ersten Mal erscheint **Tauschordner bestätigen** mit dem Host des Links, zum Beispiel `contoso-my.sharepoint.com`. Bestätige nur, wenn das der SharePoint des Kunden oder deiner Firma ist. Ein fremder Tenant könnte Dateien mitlesen oder unterschieben. Die Bestätigung wird im Projekt gespeichert.
6. Der Link steht jetzt auf der Seite **Tauschordner**. Klicke dort auf **Verbinden**. Bei Erfolg steht dort **Verbunden: <Ordnername>** und die Liste der vorhandenen Dateien.

Importierst du ein Projekt aus einer Datei und der Host des Links ist neu, fragt das Tool: Ja übernimmt den Link, Nein importiert das Projekt ohne Link, Abbrechen importiert nichts.

Du kannst den Link auch ohne Projekt direkt auf der Seite **Tauschordner** einfügen.

<!-- Bild: Seite „Tauschordner“ nach „Verbinden“ mit Dateiliste, Link unkenntlich -->

## 4. Paket ablegen und Einzeiler auf dem Kundenserver

### Paket ablegen

1. Auf der Seite **Tauschordner** verbunden sein.
2. **Paket ablegen** klicken. Das Tool baut `SM-Server-Paket.zip`, legt es im Tauschordner ab (große Dateien in Teilen) und zeigt den **Einzeiler** mit der SHA256-Prüfsumme des Pakets.
3. **Einzeiler kopieren**.

Der Einzeiler enthält den Tauschordner-Link. Er wird nie in eine Datei geschrieben. Gib ihn nur an die Person weiter, die ihn auf dem Server braucht.

Legst du das Paket erneut ab, ändert sich die Prüfsumme. Ein älterer Einzeiler funktioniert dann nicht mehr („Pruefsumme falsch“, siehe [Fehlerbehebung](FEHLERBEHEBUNG.md)).

<!-- Bild: Einzeiler-Karte mit Prüfsumme, Link unkenntlich -->

### Einzeiler auf dem Kundenserver

1. Auf dem Kundenserver **Windows PowerShell** (nicht PowerShell 7) **als Administrator** öffnen.
2. Den Einzeiler einfügen und Enter drücken.
3. Der Einzeiler
   - lädt das Paket aus dem Tauschordner und prüft die SHA256 im Speicher,
   - bricht bei falscher Prüfsumme ab, ohne etwas zu entpacken oder auszuführen,
   - entpackt sonst in einen neuen Ordner `%TEMP%\ServerMigration-<Zufall>`,
   - setzt die Scriptfreigabe nur für diesen Prozess (`-Scope Process`) und startet das Server-Fenster.
4. Das Server-Fenster öffnet sich mit der Seite **Dieser Server**. Es verbindet sich automatisch mit dem Tauschordner. Der Status zeigt **Verbunden: <Ordnername>**. Mit **Ordner prüfen** liest du neu, mit **Datei hochladen …** legst du beliebige Dateien ab (Dateinamen nur mit Buchstaben, Ziffern, Punkt, Bindestrich, Unterstrich).
5. Läuft das Fenster nicht als Administrator, zeigt es einen Hinweis. Dann sind alle ändernden Aktionen nicht möglich. Öffne die PowerShell als Administrator und füge den Einzeiler erneut ein.

Das **Protokoll** unten im Fenster zeigt jede Aktion mit Uhrzeit.

<!-- Bild: Server-Fenster, Seite „Dieser Server“ mit verbundenem Tauschordner -->

## 5. DNS

Ziel: herausfinden, welche Clients und Server noch den alten DNS-Server anfragen.

### Logging einschalten (Server-Fenster, Seite DNS)

1. **Status lesen**. Das Fenster zeigt, ob das Logging ein oder aus ist, die Logdatei und die Größe.
2. Ist das Logging aus, erscheint **Logs sammeln** mit zwei Feldern:
   - **Pfad der Logdatei**: Vorgabe `%windir%\System32\dns\dns.log`. Erlaubt ist nur der Ordner `%windir%\System32\dns` (Endung `.log` oder `.txt`). Andere Pfade lehnt das Tool ab, weil der DNS-Server sie ignoriert (Ereignis 506).
   - **Maximale Größe in MB**: Vorgabe 500, erlaubt 10 bis 2048. Auf dem Laufwerk müssen etwa 110 % davon frei sein.
3. **Logging einschalten …**. Das Tool prüft vorab und fragt nach. Es schaltet die Pakete Queries, Answers, Send, Receive, UDP, TCP sowie Notify und Update ein.
4. Der vorherige Zustand der DNS-Diagnose wird gesichert (`%ProgramData%\ServerMigration\dns-diagnostics-before.json`), damit er später wiederhergestellt werden kann.

Lass das Logging so lange laufen, wie das Bild der Anfragen aussagekräftig sein soll. Die Datei ist auf die gewählte Größe begrenzt.

### Sammeln und hochladen

1. Ist eine Logdatei vorhanden, zeigt die Seite **Logs in den Tauschordner**.
2. **Logs hochladen** packt die Logdatei (auch wenn der DNS-Dienst sie offen hält) zusammen mit einer Metadatei und lädt das ZIP `SM-DNS-<Server>-<Datum>.zip` in Teilen hoch. Die Metadatei enthält Servername, Zeitzone, Datumsformat, eigene IPs, Forwarder, bedingte Forwarder, Sekundärserver, Domänencontroller und Zonen.

Das Logging läuft dabei weiter. Du kannst später erneut hochladen.

### Auswerten (Berater-Tool, Seite DNS)

1. **ZIPs im Tauschordner suchen**, ein oder mehrere ZIPs wählen, **Auswählen und auswerten**. Alternativ **Datei öffnen …** für ein lokales ZIP oder eine `.log`-/`.txt`-Datei.
2. **Datumsformat**: Standard ist „automatisch“ (aus der Metadatei, sonst erkannt). Stimmt die Erkennung nicht, wähle `dd.MM.yyyy`, `M/d/yyyy` oder `yyyy-MM-dd`.
3. Optional **Namen der Clients auflösen**: Das Tool fragt die internen IPs beim DNS des Berater-Rechners ab.
4. Ansichten:

   | Ansicht | Zeigt |
   |---|---|
   | Clients (wer fragt noch an) | IP, Anzahl, erste und letzte Anfrage, Namen. Der Schwerpunkt der Auswertung. |
   | Andere DNS-Server | Anfragen anderer DNS-Server sind markiert. |
   | Fehlerhafte Antworten | NXDOMAIN, SERVFAIL, REFUSED und ähnliche. |
   | Namen, Zonen, Record-Typen | Häufigkeiten. |
   | Updates und Notify | Dynamische Updates und Notify-Pakete. |
   | Rohdaten | Alle Pakete mit Filter. |

5. **Filter**: Begriffe mit Leerzeichen, alle müssen vorkommen (IP, Name, Typ, NXDOMAIN, Notify …). **Filtern** wendet sie an.
6. **Als CSV exportieren** schreibt die angezeigte Ansicht samt Filter (CSV oder Excel). Bei sehr vielen Treffern zeigt die Tabelle nur einen Teil an, der Export enthält alle.

Für die Kommandozeile gibt es `DNSParser.ps1`: Es liest Logdateien mit demselben Parser und speichert das Ergebnis als `<Datei>Parsed.XML`.

<!-- Bild: Berater-Tool, DNS-Auswertung, Ansicht „Clients“, Beispieldaten -->

### Logging ausschalten

1. Server-Fenster, Seite DNS: **Logging ausschalten …** und bestätigen.
2. Das Tool stellt den gesicherten Zustand wieder her und prüft nach, dass das Logging aus ist. Die Logdatei bleibt erhalten.
3. Gibt es keinen gesicherten Zustand (zum Beispiel weil das Logging nicht mit diesem Tool eingeschaltet wurde), schaltet das Tool nur das Logging ab.

## 6. DHCP

Ziel: Bereiche, Optionen, Reservierungen und Leases vom alten auf den neuen Server bringen und das Ergebnis prüfen.

Wichtig: Den **Failover** überträgt weder `Export-DhcpServer` noch `Import-DhcpServer`. Du legst ihn am neuen Server von Hand an (siehe unten).

### Vorprüfung

Auf beiden Servern in der Seite DHCP **Vorprüfung** klicken. Sie prüft Cmdlets des Moduls `DhcpServer`, den Dienst `DHCPServer`, Administratorrechte und ob der Server in AD autorisiert ist. Sie ändert nichts.

### Export am alten Server

1. Server-Fenster am **alten** Server, Seite DHCP, Abschnitt **Alter Server: Export**.
2. Entscheide über **Ohne Leases exportieren**. Leases enthalten MAC-Adressen und Hostnamen der Geräte, also personenbezogene Daten. Standard ist **mit** Leases. Ohne Leases vergleicht das Berater-Tool später nur die Anzahl.
3. **Exportieren und hochladen** und die Rückfrage bestätigen. Das Tool schreibt `DHCP-Export-<Server>-<Datum>.zip` mit genau zwei Dateien: `dhcp-export.xml` (von `Export-DhcpServer`) und `dhcp-summary.json` (Zusammenfassung). Das ZIP geht in den Tauschordner.
4. **SHA256 kopieren**. Das ist die Prüfsumme des ZIPs. Bewahre sie auf (Zwischenablage, Notiz), du brauchst sie am neuen Server. Du bekommst sie bewusst **nicht** über den Tauschordner.

### Import am neuen Server

1. Server-Fenster am **neuen** Server, Abschnitt **Neuer Server: Export holen und importieren**.
2. **Exporte im Tauschordner suchen**, den Export wählen, **Herunterladen**. Die Datei landet in einem gesicherten Arbeitsordner unter `%ProgramData%\ServerMigration\Dhcp`.
3. Füge die **vollständige SHA256 vom alten Server** ein. Das Tool zeigt die berechnete Prüfsumme absichtlich nicht an. Stimmt die Eingabe nicht vollständig, wird die Datei nicht geöffnet.
4. **Export prüfen und Bereiche laden**. Das Tool prüft, dass das ZIP genau die zwei erwarteten Dateien enthält, liest die XML ohne DTD und vergleicht sie mit der Zusammenfassung.
5. Wähle **Alles importieren** oder **Nur ausgewählte Bereiche** (Liste anhaken). **Leases mit importieren** ist vorbelegt.
6. **Importieren …**. Das Bestätigungsfenster zeigt, was die Export-XML wirklich enthält (Bereiche, Serveroptionen, Reservierungen, Ausschlüsse), und weist darauf hin, dass der Import vorher die DHCP-Datenbank sichert.
7. Gibt es Bereiche schon am neuen Server, fragt das Tool dreifach: **Ja** löscht die vorhandenen und legt sie aus dem Export neu an (mit zweiter Sicherheitsabfrage), **Nein** behält sie und überspringt sie, **Abbrechen** importiert nichts.

Weicht die Zusammenfassung bei Bereichen oder den Optionen 3, 6, 15, 44 und 252 von der XML ab, **importiert das Tool nichts** und nennt die Abweichung. Importiert wird immer, was in der XML steht.

Die Datenbanksicherung liegt unter `%ProgramData%\ServerMigration\dhcp-sicherung-<Datum>`. Das Protokoll steht in `%ProgramData%\ServerMigration\dhcp-protokoll.log`.

### Autorisierung

Der neue Server darf erst nach dem Import in AD autorisiert werden.

1. Abschnitt **Neuer Server: autorisieren und Stand hochladen**, **In AD autorisieren …**. Die Vorprüfung meldet, wenn der Server schon autorisiert ist oder die Liste in AD nicht lesbar ist (Domäne erreichbar? Rechte als Enterprise Admin oder delegiert?).
2. Nach der Bestätigung führt das Tool `Add-DhcpServerInDC` aus und prüft die Liste nach. Steht der Server noch nicht darin, ist wahrscheinlich die Replikation abzuwarten.

### Vergleich vorher und nachher

1. Am neuen Server **Stand des neuen Servers hochladen** (optional **Ohne Lease-Liste hochladen**). Das erzeugt `DHCP-Nachher-<Server>-<Datum>.json` im Tauschordner.
2. Im Berater-Tool, Seite **DHCP**: **Dateien im Tauschordner suchen**, bei **Vorher** den Export, bei **Nachher** den Stand wählen, **Vergleichen**.
3. Das Ergebnis je Bereich, Option, Reservierung, Ausschluss, Lease-Anzahl und Failover heißt **gleich**, **anders**, **fehlt nachher** oder **neu nachher**. Gleiche Einträge blendest du mit **Auch gleiche Einträge zeigen** ein. Leases werden je Adresse verglichen; sie laufen ab und ändern sich laufend, einzelne Abweichungen sind deshalb normal.
4. **Unterschiede exportieren** schreibt CSV oder Excel.

<!-- Bild: Berater-Tool, DHCP-Vergleich mit Beispielbereichen 10.10.0.0 -->

### Failover von Hand anlegen

Der Vergleich zeigt eine Failover-Beziehung des alten Servers als **fehlt nachher**. Lege sie am neuen Server von Hand an (`Add-DhcpServerv4Failover`) und prüfe sie danach. Das Tool legt keine Beziehung an.

### Bereiche am alten Server deaktivieren

Erst wenn der neue Server die Bereiche übernommen hat und autorisiert ist:

1. Server-Fenster am **alten** Server, Abschnitt **Alter Server: Bereiche deaktivieren**.
2. **Bereiche dieses Servers lesen**, Bereiche anhaken, **Gewählte Bereiche deaktivieren …**.
3. Die Bestätigung nennt den Servernamen. Hat das Fenster in dieser Sitzung selbst importiert, warnt es zusätzlich, dass das vermutlich der neue Server ist. Bereiche in einer Failover-Beziehung werden gemeldet, weil die Änderung zum Partner repliziert würde.
4. Die Bereiche stehen danach auf `InActive`. Rückgängig: Bereich wieder aktivieren.

## 7. Print

Ziel: Drucker, Treiber, Ports und Freigaben vom alten auf den neuen Druckserver übertragen, Zugriffe auswerten und ungenutzte Drucker finden.

Server-Fenster, Seite **Print**. Oben wählst du: **der alte Server (Quelle)** oder **der neue Server (Ziel)**. Alle Dateien liegen im gesicherten Ordner `%ProgramData%\ServerMigration\Print`.

### Export am alten Server

1. Rolle **alter Server**, **Vorprüfung**. Sie prüft Administrator, Rolle Druckserver und `PrintBrm.exe`.
2. **Export und Inventur erstellen** und bestätigen. Das Tool
   - sichert mit `PrintBrm -B` alle Drucker, Treiber, Ports, Warteschlangen und Freigaben in `Print-Export-<Server>-<Datum>.printerExport` (kann einige Minuten dauern; enthält Treiberdateien),
   - erstellt dazu eine Inventur `Print-Inventur-<Server>-<Datum>.json` (Treiberversion, Architektur, Standort, Kommentar, Veröffentlichung im AD).
3. Das Feld **SHA256 des Exports** zeigt zwei Zeilen: `Export: …` und `Inventur: …`. **Beide SHA256 kopieren** und aufbewahren.
4. Im Abschnitt **Dateien hochladen** die Dateien in der Liste wählen und **Hochladen** (große Dateien gehen in Teilen). Die Export- und die Inventurdatei einzeln hochladen.

### Import am neuen Server

1. Rolle **neuer Server**. **Dateien im Tauschordner anzeigen**.
2. Bei **Exportdatei** die Export-Datei, bei **Inventur des alten Servers (optional)** die Inventur wählen. Mit Inventur prüft das Tool Namenskonflikte. **Herunterladen**.
3. Füge beide **vollständigen Prüfsummen** ein (Export und, bei gewählter Inventur, Inventur). Du kannst den kopierten Zweizeiler mit `Export: …` und `Inventur: …` in beide Felder einfügen, das Tool nimmt jeweils den passenden Teil. **Der Import-Knopf bleibt gesperrt, bis alle Prüfsummen vollständig stimmen.** Eine Exportdatei mit Treibern gilt wie ein Skript: ohne Treffer kein Import.
4. Optionen:

   | Option | Bedeutung |
   |---|---|
   | Freigaben übernehmen (Standard an) | Aus: Nach dem Import werden nur die **neu angelegten** Drucker nicht mehr freigegeben. Bestehende Drucker bleiben unverändert. |
   | Im Active Directory veröffentlichen | `PrintBrm -P ORIG`: veröffentlicht, was ursprünglich veröffentlicht war. |
   | Vorhandene Drucker gleichen Namens überschreiben | `PrintBrm -O FORCE`. Ohne Haken werden vorhandene Drucker nicht ersetzt. |

5. **Vorprüfung** zeigt Administrator, Rolle, `PrintBrm.exe`, freien Platz (Datei mal zwei plus 500 MB auf dem Systemlaufwerk), den Druckspooler und die Namenskonflikte gegen die Inventur.
6. **Importieren …**. Das Bestätigungsfenster zeigt die ersten 25 Zeilen des Inhalts der Exportdatei (`PrintBrm -Q`), die Optionen und den Abgleich der Druckernamen mit der Inventur. Treiber, Ports und Einstellungen werden dabei nicht verglichen.
7. Danach: **Inventur erstellen** (Rolle neuer Server), hochladen.

### Vergleich im Berater-Tool

Seite **Print**:

1. **Print-Dateien im Tauschordner anzeigen**, die alte Inventur wählen, **Als alte Inventur laden**, die neue wählen, **Als neue Inventur laden**. (Ohne Auswahl öffnet sich ein Dateidialog für eine lokale Datei.)
2. **Vergleichen** zeigt Drucker, Treiber, Ports und Freigaben als **gleich**, **abweichend**, **nur alt** oder **nur neu**. **Exportieren …** schreibt CSV oder Excel.

<!-- Bild: Berater-Tool, Print-Vergleich der Inventuren, Beispieldrucker -->

### Druckprotokoll und Zugriffe

Ohne Druckprotokoll entsteht kein Ereignis 307 (Druckauftrag). Schalte es am **alten** Server rechtzeitig ein.

1. Abschnitt **Zugriffe (Druckprotokoll)**, **Größe (MB)** (Vorgabe 100, erlaubt 1 bis 4096), **Druckprotokoll einschalten** und bestätigen. Der alte Zustand des Protokolls `Microsoft-Windows-PrintService/Operational` wird vorher gesichert.
2. Nach einer Weile **Zugriffe sammeln**. **Letzte Tage** (Vorgabe 90, erlaubt 1 bis 3650). Das Tool schreibt `Print-Zugriffe-<Server>-<Datum>.json` mit den Ereignissen 307 und einem **Sofortbild** (SMB-Sitzungen, offene Druckdateien, Verbindungen des Spoolers). Ist ein Teil nicht ermittelbar, steht ein Hinweis in der Datei.
3. Datei im Abschnitt **Dateien hochladen** hochladen.
4. Nach der Sammlung **Ausschalten (alter Zustand)** und bestätigen. Das stellt den gesicherten Zustand wieder her. Gibt es keinen gesicherten Zustand, weigert sich das Tool.

**Pseudonyme.** Benutzer- und Rechnernamen sind personenbezogene Daten. Mit **Benutzernamen pseudonymisieren** ersetzt das Tool sie beim Sammeln durch `Benutzer-<12 Hexzeichen>` (HMAC-SHA256 mit einem zufälligen Schlüssel). Mit **Rechnernamen auch pseudonymisieren** werden auch Rechner (`Rechner-<…>`) und Verbindungsadressen ersetzt. Den **Schlüssel** erzeugt das Fenster zufällig (**Neuer Schlüssel**, **Schlüssel kopieren**). Er steht in keiner Datei und nicht im Tauschordner. Benutze für alle Sammlungen und Server des Projekts denselben Schlüssel und bewahre ihn sicher auf, sonst entstehen für dieselbe Person verschiedene Kürzel.

**Auswerten.** Berater-Tool, Seite **Print**:

1. Abschnitt **1 Daten laden**: Zugriffsdateien mit **Zugriffe hinzufügen** laden (mehrfach möglich, Doppelte werden entfernt).
2. Abschnitt **3 Zugriffe auswerten**: Ansicht wählen (je Benutzer, je Rechner, je Drucker, Ungenutzte Drucker, Sofortbild) und **Anzeigen**. **Exportieren …** schreibt CSV oder Excel.
3. **Benutzernamen kürzen** blendet Namen in Anzeige und Export durch Kürzel aus. Das Berater-Tool erzeugt dafür einen eigenen zufälligen Schlüssel je Sitzung. Die Kürzel stimmen deshalb nicht mit denen aus dem Server-Fenster überein.

### Ungenutzte Drucker

**Ungenutzte Drucker** sind Drucker der Inventur ohne Druckauftrag (Ereignis 307) im Zeitraum der geladenen Daten. Der Zeitraum steht über der Tabelle. Je kürzer er ist, desto unsicherer ist die Aussage. Ein Drucker „ohne Ereignis“ ist kein Beweis, dass ihn niemand braucht.

## 8. Active Directory

Alle Aktionen laufen im Server-Fenster auf dem **neuen Domänencontroller** und ändern die Gesamtstruktur des Kunden. Das Fenster zeigt Hinweise, wenn es nicht als Administrator läuft oder das Modul `ActiveDirectory` fehlt. Dann sind die ändernden Knöpfe gesperrt.

Jede Aktion hat: Vorprüfung, Bestätigungsfenster (mit Servername und Ziel), Protokollzeile in `%ProgramData%\ServerMigration\AD\Protokoll.log`. Wird das Protokoll nicht geschrieben, meldet das Tool es als Fehler.

### Übersicht

1. Seite **Active Directory**, Abschnitt **1 Übersicht (nur lesend)**. Optional **DNS-Registrierung der DCs mitprüfen** (dauert länger).
2. **Übersicht erstellen**. Das Tool liest Funktionsebenen, Schema-Version, alle DCs (Betriebssystem, Standort, GC, RODC), FSMO-Inhaber, die Replikation (`repadmin /replsummary`, `/showrepl * /csv`) und `dcdiag` (Tests KnowsOfRoleHolders, Advertising, Replications, Services, RidManager, MachineAccount, FsmoCheck, NCSecDesc).
3. Der Bericht `AD-Bericht-<Server>-<Datum>.json` enthält keine Geheimnisse. **Bericht hochladen** legt ihn in den Tauschordner.
4. Im Berater-Tool, Seite **Active Directory**: **Berichte suchen**, wählen, **Anzeigen**. **DC-Tabelle exportieren (CSV/Excel) …** schreibt die DCs. Die Berichte werden nur als Daten gelesen.

<!-- Bild: Berater-Tool, AD-Bericht mit Beispiel-DCs -->

### FSMO-Rollen übertragen

Abschnitt **2 FSMO-Rollen auf diesen Server übertragen**. Die Rollen wandern vom heutigen Inhaber auf den Server, auf dem das Fenster läuft.

1. Rollen anhaken (PDC-Emulator, RID-Master, Infrastrukturmaster, Schemamaster, Domänennamenmaster) oder **Alle wählen**.
2. **Vorprüfung**: Administrator, beschreibbarer DC (kein RODC), nötige Gruppenmitgliedschaften, Inhaber erreichbar, etwas zu übertragen, Replikation ohne Fehler, `dcdiag` ohne Fehler. Hinweis bei Infrastrukturmaster auf einem GC in einer Gesamtstruktur mit mehreren Domänen. Fehlt eine Voraussetzung, wird nichts übertragen.
3. **Übertragen …** und bestätigen. Das Tool prüft erneut, überträgt mit `Move-ADDirectoryServerOperationMasterRole` (ohne `-Force`) und prüft nach, dass die Rollen jetzt hier liegen. Rollen und Inhaber stehen vorher und nachher im Fenster.

### Seize (Rolle übernehmen)

Nur wenn der alte Inhaber **nie wieder** ans Netz kommt, etwa nach einem Ausfall. Der alte DC darf danach nie wieder gestartet werden, sonst gibt es zwei Rolleninhaber mit Datenverlust.

1. Rolle wählen und **Inhaber prüfen**. Das Tool prüft den Inhaber dreimal im Abstand von 10 Sekunden mit Ping, LDAP (Port 389) und RPC (Port 135). Antwortet auch nur eines davon einmal, gilt er als erreichbar und Seize ist nicht erlaubt: Übertrage die Rolle dann normal. Zusätzlich zeigt das Tool die letzte erfolgreiche Replikation des Inhabers.
2. Setze den Haken **Der alte Inhaber ist dauerhaft entfernt und kommt nie wieder ans Netz**.
3. Tippe zur Bestätigung den Rollennamen genau so (zum Beispiel `RIDMaster`).
4. **Rolle übernehmen (Seize) …**, bestätigen. Das Tool wiederholt die Prüfung, prüft Rechte, führt `Move-ADDirectoryServerOperationMasterRole -Force` aus und prüft nach.

Der Knopf bleibt gesperrt, bis Haken und getippter Name passen.

### DSRM-Kennwort

Abschnitt **3 DSRM-Kennwort**. Zwei Wege:

**A. Mit Domänenkonto synchronisieren (empfohlen).** Das Tool berührt kein Kennwort.

1. Domänenkonto eintragen (`Konto` oder `CONTOSO\Konto`). Am besten ein **eigenes, deaktiviertes Konto**, das in keiner privilegierten Gruppe ist.
2. **DSRM-Kennwort ändern …**. Das Tool liest das Konto und warnt, wenn es aktiviert oder in privilegierten Gruppen ist (dann wäre sein Kennwort zugleich das DSRM-Kennwort). Nach der Bestätigung läuft `ntdsutil` („set dsrm password“, „sync from domain account“). Es wirkt nur auf diesen Server.
3. Erfolg meldet das Tool nur, wenn `ntdsutil` die Erfolgsmeldung ausgibt. Der Exitcode allein genügt nicht.

**B. Neues Kennwort setzen.** Das Kennwort wird zweimal eingegeben, mindestens 12 Zeichen, drei von vier Zeichenarten, ohne Anführungszeichen. Es geht nur über die Standardeingabe an `ntdsutil` und wird nirgends gespeichert, protokolliert oder hochgeladen. Bei **Domänencontroller** leer lassen heißt: dieser Server. Nimmt `ntdsutil` das Kennwort nicht an (keine Erfolgsmeldung oder keine Antwort nach 60 Sekunden), nutze Weg A. Variante B ist noch nicht an einem echten System erprobt.

### Funktionsebenen anheben

Abschnitt **4 Funktionsebene anheben**. **Nicht umkehrbar.** Lege vorher eine aktuelle Systemstatus-Sicherung an.

1. **Ebenen lesen / Vorprüfung** (erster Klick liest die aktuellen Ebenen).
2. Bereich (**Domäne** oder **Gesamtstruktur**) und Zielebene wählen. Zur Wahl stehen die Ebenen über der aktuellen bis Windows Server 2025.
3. Erneut **Ebenen lesen / Vorprüfung**. Geprüft werden: Ziel höher als jetzt, DCs gefunden, **alle DCs** tragen die Zielebene (nach Betriebssystem), Betriebssysteme erkennbar, bei der Gesamtstruktur alle Domänen auf Zielebene, Replikation in Ordnung.
4. Tippe den **Namen der Domäne bzw. Gesamtstruktur** (zum Beispiel `contoso.local`), dann **Ebene anheben (nicht umkehrbar) …** und bestätige. Danach prüft das Tool nach.

### Schema-Update (adprep)

Abschnitt **5 Schema-Update (adprep)**. Nur nötig, wenn das Schema vorab erweitert werden soll. Ab Windows Server 2012 macht das Heraufstufen eines DCs das automatisch.

1. **Binde das originale Microsoft-ISO des neuen Windows Servers ein** (Rechtsklick „Bereitstellen“). Andere Quellen (Ordner, Netzwerkpfade) lehnt das Tool ab.
2. **Laufwerk suchen** trägt ein Laufwerk mit `support\adprep\adprep.exe` ein.
3. **/forestprep prüfen** (auf dem Schemamaster) bzw. **/domainprep prüfen** (auf dem Infrastrukturmaster). Die Prüfung testet Administrator, Medium, Rolle des Servers, Gruppenmitgliedschaften und Replikation. Zusätzlich macht sie eine Probekopie: Das Tool kopiert `support\adprep` in einen gesicherten Ordner, hält die Kopie offen und prüft dort Signaturen (adprep.exe: Microsoft Windows, Microsoft Corporation, Kette in einer Microsoft-Wurzel) und die SHA256 der Kopie gegen die Quelle. Nicht signierbare Dateien (`.ldf`) kann es nicht prüfen, ihre SHA256 werden angezeigt.
4. Lege vorher eine Systemstatus-Sicherung an. Nach der Schemaerweiterung hilft nur eine Gesamtstruktur-Wiederherstellung.
5. **/forestprep ausführen …** bzw. **/domainprep ausführen …**, bestätigen. adprep läuft **nur aus der geprüften Kopie** und bekommt die Rückfrage mit `C` beantwortet. Das Tool zeigt die Schema-Version vorher und nachher. Die Ausgabe steht in einer Datei unter `%ProgramData%\ServerMigration\AD`. Die Kopie wird danach gelöscht.

<!-- Bild: Server-Fenster, AD-Seite mit Vorprüfung FSMO (Beispielserver dc01.contoso.local) -->

## 9. Aufräumen

Nach dem Projekt:

| Wo | Was |
|---|---|
| Server-Fenster | **DNS-Logging ausschalten** und **Druckprotokoll ausschalten**, falls noch an. |
| Kundenserver | Ordner `%ProgramData%\ServerMigration` mit Exporten (`Dhcp`, `Print`), Datenbanksicherungen (`dhcp-sicherung-*`), `AD`, Protokollen und gesicherten Zuständen löschen, sobald du sie nicht mehr brauchst. Dazu `%TEMP%\ServerMigration-*` (das entpackte Paket). Die DNS-Logdatei selbst liegt in `%windir%\System32\dns`. |
| Kundenserver | Den Verlauf der PowerShell-Sitzung ansehen: Der Einzeiler enthält den Tauschordner-Link (siehe [Sicherheit](SICHERHEIT.md#akzeptiertes-risiko-link-im-verlauf-und-in-den-protokollen)). |
| Tauschordner | **Alle Dateien löschen und die Freigabe des Ordners entfernen** (Link ungültig machen). |
| Berater-Rechner | Heruntergeladene und exportierte Dateien (CSV, Excel, ZIPs) löschen. **Gemerkte Verbindung löschen**, falls du das Kennwort der Liste gemerkt hast. |
| Projektliste | Projekt auf **Abgeschlossen** oder **Archiviert** setzen oder löschen. |
| Pseudonym-Schlüssel | Aufbewahren, solange Berichte vergleichbar bleiben sollen, danach vernichten. |

## Stand und noch nicht live erprobt

Das Tool ist **bisher nur gegen nachgebaute Cmdlets und einen nachgebauten SharePoint-Server getestet** (siehe [README](../README.md#tests-ausführen)). Die Tests prüfen Logik, Eingaben und Fehlerfälle, nicht das Verhalten echter Server. Bevor du es produktiv einsetzt, probiere es in einer Testumgebung aus. Offen ist insbesondere:

| Bereich | Noch nicht an echten Systemen geprüft |
|---|---|
| Tauschordner | Upload in Teilen mit einer Datei über 10 MB gegen einen echten Tenant (Antwortformat, Maximalgröße, ob ein anonymer Gast hochladen darf). Der Einzeiler auf einem echten Server über eine Bastion. Zugang der Server zu `*.sharepoint.com`: Das hängt vom Umfeld ab. Ohne Zugang funktioniert der Einzeiler nicht; ein Admin-Server mit RSAT ist nicht umgesetzt. |
| Projektliste | Konflikterkennung bei gleichzeitigem Speichern in einem echten Tenant (wertet SharePoint `If-Match` aus?). Anlegen, Öffnen, Export und Import über einen echten Ordnerlink und auf einem zweiten Rechner. |
| DNS | Logging ein und aus auf einem echten DNS-Server; echte Logzeilen (Datum im Gebietsschema des Servers, auch englische Server); Metadaten (Forwarder, Zonen, DCs) von einem echten Server. |
| DHCP | Export mit vielen Leases (Dauer, Größe); Import am neuen Server mit allen Rückfragen von `Import-DhcpServer`; Autorisierung in AD; Failover (wird nicht übertragen, nur als Hinweis). |
| Print | Echtes `PrintBrm` (Export, `-Q`-Ausgabe, Import mit `-O FORCE` und `-P ORIG`, Exitcodes); Druckprotokoll und Ereignis 307 auf einem echten Druckserver; Sofortbild; Veröffentlichung im AD. |
| Active Directory | Alles nur in einer Testdomäne erproben. Format der `repadmin`-Ausgaben und der `ntdsutil`-Meldungen (insbesondere deutschsprachige); FSMO-Übertragung und Seize; DSRM-Variante B (ob `ntdsutil` das Kennwort über die Standardeingabe annimmt); Anheben der Ebenen (auch 2025); adprep vom Medium mit Signaturprüfung. |
| Start per Einzeiler | Der Start aus `cmd` und per Win+R auf echten Systemen. Für das erste Release ist noch offen, wie die Integrität des Starters abgesichert wird (veröffentlichte Prüfsumme oder Signatur). |

Alle Bedienschritte in dieser Anleitung beschreiben, was der Code tut. Screenshots folgen, sobald ein Durchlauf an einer Testumgebung vorliegt.
