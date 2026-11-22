# Fehlerbehebung

Die Meldungen stehen so im Tool, wie sie hier zitiert sind (ohne Umlaute, weil die Skripte ASCII-Text ausgeben). Suche nach einem Stichwort der Meldung. Bedienung: [Anleitung](ANLEITUNG.md). Hintergrund: [Sicherheit](SICHERHEIT.md).

## Inhalt

1. [Einzeiler und Start](#einzeiler-und-start)
2. [Tauschordner](#tauschordner)
3. [Projektliste](#projektliste)
4. [DNS](#dns)
5. [DHCP](#dhcp)
6. [Print](#print)
7. [Active Directory](#active-directory)
8. [Allgemein](#allgemein)

## Einzeiler und Start

| Meldung oder Bild | Ursache | Lösung |
|---|---|---|
| `Pruefsumme falsch: Das Paket im Tauschordner ist nicht das erwartete. Nichts ausgefuehrt.` | Die SHA256 des heruntergeladenen Pakets passt nicht zu der im Einzeiler. Meist wurde das Paket seit dem Erzeugen des Einzeilers **neu abgelegt** (neue Prüfsumme) oder durch eine andere Version ersetzt. Es kann auch ein Austausch im Tauschordner sein. | Im Berater-Tool auf **Paket ablegen** klicken und den **neuen** Einzeiler verwenden. Tritt es mit einem frischen Einzeiler wieder auf, prüfe, wer Schreibzugriff auf den Ordner hat. Nichts wurde ausgeführt. |
| `Weiterleitung auf unerlaubtes Ziel: <Host>` | Der Link leitet auf einen Host um, der nicht `https://*.sharepoint.com` ist. | Den Link neu aus SharePoint oder OneDrive kopieren. Ein Link auf andere Dienste wird nie akzeptiert. |
| `Kein Ordnerlink: <Adresse>` | Aus dem Link ließ sich kein Ordner ermitteln. Meist ist es ein Dateilink oder ein ungültiger Link. | Den **Ordner** teilen (Jeder mit dem Link, Bearbeiten) und dessen Link nehmen. |
| Der Einzeiler tut nichts oder der Server meldet einen Netzwerkfehler | Der Server erreicht `*.sharepoint.com` nicht (Proxy, Firewall) oder der Link ist abgelaufen. | Zugriff auf `*.sharepoint.com` klären, Link prüfen oder neu anlegen. Ein Admin-Server mit RSAT ist nicht umgesetzt. |
| Das Fenster öffnet sich, aber mit Hinweis „Dieses Fenster läuft nicht als Administrator“ | Die PowerShell lief ohne erhöhte Rechte. | PowerShell **Als Administrator ausführen** öffnen und den Einzeiler erneut einfügen. Ändernde Aktionen sind bis dahin gesperrt. |
| `get.ps1`: `github.com cannot be reached` oder `Cannot find the latest release` | Der Berater-Rechner erreicht GitHub nicht oder es gibt keine Version. | Netzzugang prüfen. Eine bestimmte Version mit `$env:TOOL_REF = '<Tag>'` vorgeben. Es gibt keinen stillen Wechsel auf `main`, wenn GitHub nicht erreichbar ist. |

## Tauschordner

| Meldung | Ursache | Lösung |
|---|---|---|
| `Das ist kein SharePoint-/OneDrive-Freigabelink (https://<firma>.sharepoint.com/... bzw. https://<firma>-my.sharepoint.com/...), oder er enthaelt Leerzeichen bzw. Anfuehrungszeichen.` | Falscher Linktyp, anderer Host, oder beim Kopieren sind Leerzeichen oder typografische Anführungszeichen mitgekommen. | Link neu kopieren. Er muss mit `https://` beginnen und auf `*.sharepoint.com` zeigen. |
| `Das ist ein Link auf eine Datei. Bitte den ORDNER teilen ...` | Link auf eine einzelne Datei statt auf den Ordner. | Den Ordner teilen und dessen Link nehmen. |
| `Der Tauschordner ist nicht erreichbar: <Fehler>. Hat der Server Internetzugang zu *.sharepoint.com? Ist der Link noch gueltig?` | Kein Netzzugang zu SharePoint, Proxy, abgelaufener oder gelöschter Link. | Zugriff und Gültigkeit prüfen. Im Server-Fenster **Ordner prüfen**, im Berater-Tool **Verbinden**. Der Status zeigt **Nicht erreichbar**. |
| `Der Freigabelink leitet auf ein unerlaubtes Ziel weiter (erlaubt: https auf *.sharepoint.com). Abgebrochen.` | Der Link wird auf einen anderen Host weitergeleitet. | Neuen Link aus dem richtigen Tenant erzeugen. |
| `Der Link fuehrt nicht zu einem Ordner (<Adresse>). Bitte einen Ordner mit 'Jeder mit dem Link' und 'Bearbeiten' teilen ...` | Link ist kein Ordnerlink oder die Freigabe verlangt eine Anmeldung. | Freigabe auf „Jeder mit dem Link kann bearbeiten“ stellen. |
| `Keine Schreibberechtigung im Tauschordner (kein Formular-Digest). Ist der Link auf "Bearbeiten" gestellt?` | Der Link erlaubt nur Ansehen oder eine Anmeldung. | Auf **Bearbeiten** stellen, ohne Anmeldung. |
| `Hochladen fehlgeschlagen: <Fehler>. Ist der Link auf 'Bearbeiten' gestellt?` | Fehlende Schreibrechte, abgelaufener Link oder ein Netzproblem beim Upload in Teilen. | Link prüfen, erneut hochladen. Große Dateien gehen in Teilen zu 10 MB; das ist an echten Tenants noch nicht erprobt. |
| `Dateiname mit Sonderzeichen oder Leerzeichen: bitte umbenennen ...` / `Dateiname mit Sonderzeichen: <Name>` | Dateinamen dürfen nur Buchstaben, Ziffern, Punkt, Bindestrich und Unterstrich enthalten. | Datei umbenennen. |
| `Die Datei <Name> ist nach dem Hochladen nicht im Tauschordner zu sehen.` oder `... hat im Tauschordner <n> Bytes statt <m>.` | Der Upload ist unvollständig oder die Liste noch nicht aktuell. | **Ordner prüfen** erneut, sonst erneut hochladen. |
| `Die Datei ist groesser als das Limit` / `Der Download ist groesser als das Limit ... abgebrochen.` | Datei überschreitet das Größenlimit für Downloads (Standard 2 GB, bei Print-Export 8 GB). | Prüfen, ob die Datei richtig ist. Das Limit schützt vor fremden, übergroßen Dateien. |
| `Der Download wurde auf ein unerlaubtes Ziel weitergeleitet. Abgebrochen.` | Die Antwort kam nicht von `*.sharepoint.com`. | Link und Netzumgebung (Proxy, der Inhalte umschreibt) prüfen. |

## Projektliste

| Meldung oder Status | Ursache | Lösung |
|---|---|---|
| `Das Kennwort ist zu kurz (mindestens 12 Zeichen, besser eine Passphrase).` | Das Kennwort der Liste oder des Exports hat weniger als 12 Zeichen. | Längere Passphrase wählen. |
| `Das Kennwort ist falsch oder die Datei wurde veraendert. Es wurden keine Daten gelesen.` | Falsches Kennwort, oder die Datei wurde beschädigt oder verändert. | Kennwort prüfen. Ist es sicher richtig, die Datei aus einer Sicherung oder Export wiederherstellen. |
| `Dort liegt noch keine Projektliste` | Im Ordner gibt es die Datei `ServerMigration-Projekte.smproj` nicht. | **Neue Liste anlegen** benutzen. |
| `Dort gibt es schon eine Projektliste` | Beim Anlegen liegt im Ordner schon eine Liste. | Mit **Verbinden** und dem Kennwort dieser Liste öffnen. Es wird nie überschrieben. |
| `Konflikt, nichts gespeichert` (Hinweis „Jemand anderes hat die Projektliste inzwischen gespeichert ...“) | Eine andere Person hat zwischenzeitlich gespeichert. Deine Änderung wurde nicht gespeichert, damit nichts überschrieben wird. | **Zusammenführen** (übernimmt deine Änderung je Projekt auf den neuen Stand, fragt bei Überschneidung) oder **Neu laden (Änderung verwerfen)**. |
| `Die Projektliste wird gerade von jemand anderem gespeichert. Bitte gleich nochmal versuchen.` | Mehrfache Konflikte hintereinander. | Kurz warten, erneut versuchen. |
| `Der Ablageort liefert keinen ETag. Ohne ETag kann die Projektliste nicht sicher gespeichert werden.` | Der Server liefert die Versionskennung nicht. | Link und Ordner prüfen. Tritt es an einem echten Tenant auf, bitte melden: Das ist noch nicht erprobt. |
| `Speichern der Projektliste fehlgeschlagen: ... Ist der Link auf Bearbeiten gestellt?` | Keine Schreibrechte oder Netzproblem. | Link auf **Bearbeiten** stellen. |
| `Die Datei hat Format <n>, dieses Tool kennt Format <m>. Bitte das Tool aktualisieren.` und ähnlich für das Schema | Die Liste wurde mit einer neueren Version angelegt. | Das Tool aktualisieren. |
| `Das ist keine Projektliste (eventuell ein einzelnes exportiertes Projekt).` / `Das ist keine exportierte Projektdatei (eventuell die ganze Projektliste).` | Listendatei und Projektexport verwechselt. | Die Liste über **Verbinden**, ein einzelnes Projekt über **Importieren** laden. |
| `Tauschordner-Link aus Projekt NICHT übernommen (Host nicht bestätigt)` (Protokoll) | Der Host des Projektlinks wurde noch nicht bestätigt. | Projekt über **Als aktives Projekt wählen** aktivieren und den Host bestätigen, wenn er stimmt. |
| `Projekt nicht aktiviert (Tauschordner nicht bestätigt)` | Die Rückfrage zum Host wurde verneint. | Erneut aktivieren und mit Ja bestätigen, wenn der Host der SharePoint des Kunden oder deiner Firma ist. |
| `Servername '<Name>' ist ungueltig` / `Rolle '<R>' ist nicht erlaubt (DNS, DHCP, Print, DC).` / `Status '<S>' ist nicht erlaubt.` | Eingabe im Projektdialog nicht zulässig. | Nur Buchstaben, Ziffern, Punkt und Bindestrich im Servernamen; Rolle und Status aus den Listen wählen. |

## DNS

| Meldung | Ursache | Lösung |
|---|---|---|
| `Seit dem Cumulative Update 2026-11 fuer Windows Server 2025 ignoriert der DNS-Server Log-Pfade ausserhalb von <Pfad> (Event 506). Erlaubt ist nur dieser Ordner, z. B. <Pfad>\dns.log.` | Die Logdatei liegt nicht in `%windir%\System32\dns`. Solche Pfade ignoriert der DNS-Server. Das Tool lässt sie deshalb gar nicht erst zu. | Pfad auf `%windir%\System32\dns\dns.log` setzen (Vorgabe). Gilt auch für den gesicherten und wiederhergestellten Pfad. Tritt in der Ereignisanzeige Ereignis 506 auf, prüfe den Pfad der Diagnoseprotokollierung. |
| `Die Logdatei muss auf .log oder .txt enden.` / `Die Logdatei muss auf einem lokalen Laufwerk liegen.` / `Der Pfad ist ein Ordner.` / `Der Ordner existiert nicht: <Pfad>` | Pfad nicht zulässig. | Zulässigen Pfad eintragen. |
| `Unter diesem Pfad liegt eine Datei, die kein DNS-Log ist. Bitte einen anderen Pfad waehlen.` | Eine vorhandene Datei hat nicht die Kopfzeile „DNS Server log file creation“. | Anderen Dateinamen im selben Ordner wählen. Das Tool überschreibt keine fremden Dateien. |
| `Die maximale Groesse muss zwischen 10 und 2048 MB liegen.` / `Die Groesse muss unter 4096 MB liegen (MaxMBFileSize ist ein 32-Bit-Wert in Byte).` | Größe außerhalb des erlaubten Bereichs. | Wert zwischen 10 und 2048 MB eintragen. |
| `Auf dem Laufwerk sind nur <x> MB frei, gebraucht werden etwa <y> MB.` | Zu wenig freier Platz. | Platz schaffen oder kleinere Größe wählen. |
| `Auf diesem Server gibt es keine DNS-Verwaltung (Get-DnsServerDiagnostics fehlt). Ist die DNS-Rolle installiert?` / `Set-DnsServerDiagnostics fehlt ...` | Die DNS-Rolle oder die DNS-Verwaltungs-Cmdlets fehlen. | Rolle bzw. Verwaltungswerkzeuge installieren. Die Seite zeigt **Nicht verfügbar**. |
| `Fuer das Setzen der Logdatei braucht Set-DnsServerDiagnostics lokale Administratorrechte. Bitte das Server-Fenster als Administrator starten.` | Fenster ohne Administratorrechte. | Als Administrator neu starten. |
| `Das Logging ist nach dem Einschalten nicht aktiv.` / `... nach dem Ausschalten noch aktiv.` | Die Nachprüfung zeigt einen anderen Zustand als erwartet. | **Status lesen** und die DNS-Diagnoseeinstellungen im DNS-Manager prüfen. |
| `Der Sicherungsordner ist nicht sicher, abgebrochen: ...` / `Sicherungsordner ist eine Verknuepfung, abgebrochen` / `Die Zugriffsrechte des Sicherungsordners konnten nicht gesetzt werden` | `%ProgramData%\ServerMigration` hat fremde Zugriffsrechte, einen anderen Besitzer oder ist eine Verknüpfung. Das Tool arbeitet dann nicht. | Ordner prüfen: Besitzer und Rechte dürfen nur Administratoren und SYSTEM sein. Im Zweifel umbenennen oder löschen und neu starten. |
| `Keine Logdatei gefunden: <Pfad>` / `Die Logdatei ist leer.` / `Keine Logdatei vorhanden.` | Das Logging lief nicht oder noch nicht lange genug. | Logging einschalten, warten, **Status lesen**. |
| `Im Temp-Ordner ist zu wenig Platz fuer das ZIP.` | Zu wenig Platz auf dem Laufwerk von `%TEMP%`. | Platz schaffen. |
| Berater: `Keine DNS-ZIPs (SM-DNS-*.zip) im Tauschordner` | Es liegt keine hochgeladene Datei vor, oder der Name passt nicht. | Auf dem Server **Logs hochladen**, im Berater-Tool erneut suchen. Nur `SM-DNS-*.zip` wird gezeigt. |
| Berater: `Keine DNS-Pakete gefunden` | Die Datei enthält keine erkennbaren Pakete (falsches Datumsformat, falsche Datei, Logging ohne Pakete). | **Datumsformat** statt „automatisch“ manuell wählen und neu laden. Prüfen, dass die Pakete Queries und Answers aktiv waren. |
| `Die ZIP-Datei ist zu gross.` / `Das ZIP hat zu viele Eintraege` / `Die Logs im ZIP sind zusammen zu gross.` / `Die Log-Datei ist zu gross.` / `Eintrag ist entpackt groesser als das Limit.` | Die Datei überschreitet ein Sicherheitslimit gegen feindliche ZIPs. | Kleinere Logs sammeln (Größe im Server-Fenster begrenzen) oder mehrere ZIPs. |

## DHCP

| Meldung | Ursache | Lösung |
|---|---|---|
| `Die eingegebene Pruefsumme passt nicht zur heruntergeladenen Datei. Nichts geoeffnet.` | Die eingegebene SHA256 stimmt nicht mit der Arbeitskopie überein: unvollständig eingegeben, von einem anderen Export, oder die Datei im Tauschordner wurde ausgetauscht. | Die **vollständige** SHA256 vom alten Server mit **SHA256 kopieren** holen und einfügen. Stimmt sie weiterhin nicht, den Export am alten Server neu erzeugen. Importiere nie ohne Treffer. |
| `Zusammenfassung und Export-XML weichen ab, es wird nichts importiert: <Abweichung>` | Bereiche oder Optionen 3, 6, 15, 44, 252 in der Zusammenfassung unterscheiden sich von der XML. | Export am alten Server neu erzeugen. Importiert wird immer nur, was in der XML steht. |
| `Das ZIP enthaelt nicht genau dhcp-export.xml und dhcp-summary.json.` / `Das ist kein DHCP-Export (DHCP-Export-<Server>-<Datum>.zip).` | Fremde oder falsche Datei im Tauschordner. | Den richtigen Export wählen. Der Dateiname muss dem Muster entsprechen. |
| `Das ZIP ist groesser als erlaubt.` / `Die Export-XML im ZIP ist groesser als erlaubt.` / `Die heruntergeladene Datei hat nicht die erwartete Groesse.` | Limit gegen feindliche Dateien oder unvollständiger Download. | Neu herunterladen. |
| `Vorpruefung nicht bestanden: Fehlt: <Cmdlets>. Ist die DHCP-Rolle samt Verwaltungswerkzeugen installiert?` | Modul `DhcpServer` fehlt. | Rolle und Verwaltungswerkzeuge installieren. |
| `Der Dienst DHCPServer ist auf diesem Server nicht vorhanden ...` / `Der Dienst DHCPServer laeuft nicht (Status <S>).` | DHCP-Rolle fehlt oder der Dienst ist gestoppt. | Rolle installieren bzw. Dienst starten. |
| `Dieser Server ist bereits in AD autorisiert. Nichts zu tun.` | Die Autorisierung ist schon erfolgt. | Nichts zu tun. |
| `Die Autorisierungsliste in AD ist nicht lesbar (Domaene erreichbar? Rechte als Enterprise Admin oder delegiert?).` | Keine Verbindung zu AD oder keine Rechte. | Domäne und Rechte prüfen, ggf. mit einem berechtigten Konto die Autorisierung vornehmen. |
| `Eintrag angelegt, in der Liste noch nicht zu sehen (Replikation abwarten)` | Autorisierung durchgeführt, aber noch nicht repliziert. | Kurz warten, Vorprüfung wiederholen. |
| `Diese Bereiche gibt es am neuen Server schon:` (Dreifach-Frage) | Der Import würde vorhandene Bereiche berühren. | Ja = löschen und neu anlegen (mit Sicherheitsabfrage), Nein = vorhandene behalten, Abbrechen. |
| `Bereich <Id> steht nicht in der Export-XML.` / `Bereiche nicht gefunden oder keine Auswahl: <Ids>` | Gewählter Bereich existiert nicht in der XML bzw. am Server. | Auswahl neu laden. |
| `Verknuepfung (ReparsePoint) statt Datei oder Ordner, abgebrochen: <Pfad>` | Im Arbeitsordner liegt eine Verknüpfung. Das Tool verweigert sie. | Arbeitsordner unter `%ProgramData%\ServerMigration\Dhcp` prüfen und aufräumen. |
| `Export-DhcpServer hat keine Datei geschrieben.` | Der Export am alten Server ist fehlgeschlagen. | Vorprüfung, Rechte, Platz prüfen und wiederholen. |
| Warnung beim Deaktivieren: `Bereich <Id> steht in der Failover-Beziehung <Name>: das Deaktivieren wird zum Partner repliziert.` | Der Bereich ist Teil einer Failover-Beziehung. | Nur deaktivieren, wenn die Auswirkung auf den Partner gewollt ist. Failover wird nicht mitübertragen: am neuen Server mit `Add-DhcpServerv4Failover` von Hand anlegen. |
| `ACHTUNG: Dieser Server (<Name>) hat in dieser Sitzung selbst importiert ...` | Du versuchst am **neuen** Server Bereiche zu deaktivieren. | Deaktivieren gehört an den **alten** Server. Nur fortfahren, wenn du das wirklich hier willst. |
| `Die Protokollzeile konnte nicht geschrieben werden: <Fehler>` | Das Protokoll im gehärteten Ordner ist nicht schreibbar. | Rechte und freien Platz von `%ProgramData%\ServerMigration` prüfen. |

## Print

| Meldung | Ursache | Lösung |
|---|---|---|
| `Die SHA256 stimmt nicht mit der Datei im Sicherungsordner ueberein. Nichts importiert.` / `Die SHA256 der Inventur stimmt nicht ...` | Eingegebene Prüfsumme stimmt nicht mit der heruntergeladenen Datei (Export bzw. Inventur) überein. Der Import-Knopf bleibt dann gesperrt. | Vollständige SHA256 mit **Beide SHA256 kopieren** am alten Server holen und beide Felder füllen. Der Zweizeiler (`Export: …`, `Inventur: …`) lässt sich in beide Felder einfügen. |
| `Die Pruefsumme muss aus 64 Hexzeichen bestehen (die vollstaendige SHA256 vom alten Server).` | Unvollständig oder falsch eingegeben. | Vollständig einfügen. |
| `Die Arbeitskopie hat sich seit der Pruefung veraendert. Nichts importiert.` / `Das Arbeitsverzeichnis gibt es schon, abgebrochen.` / `Die Arbeitskopie liegt nicht im Arbeitsverzeichnis ...` | Sicherheitsprüfung der Arbeitskopie schlägt an. | Neu herunterladen und erneut vorbereiten. Prüfe, ob jemand im Ordner `Print\Import-*` Dateien ändert. |
| `Die heruntergeladene Datei <Name> gehoert keinem Administrator oder ist eine Verknuepfung, abgebrochen.` / `Im Sicherungsordner liegt eine Verknuepfung oder ein Ordner statt der Datei` | Der Sicherungsordner enthält fremde Dateien. | Ordner `%ProgramData%\ServerMigration\Print` prüfen. Downloads ersetzen ältere Dateien. |
| `PrintBrm meldet Exitcode <n>. Details im Ereignisprotokoll PrintBRM.` | `PrintBrm` ist fehlgeschlagen (Export oder Import). Microsoft nennt keine Einzelwerte. | Ereignisprotokoll `PrintBRM` (Ereignisanzeige, Anwendungs- und Dienstprotokolle) lesen. Prüfe Platz, Spooler und Rechte. |
| `Zeitueberschreitung nach 7200 Sekunden: PrintBrm.exe` | `PrintBrm` lief länger als zwei Stunden und wurde beendet. | Prüfen, ob der Export sehr groß ist. Wiederholen. |
| `Datei zu gross (<x>, erlaubt <y>).` / `Zu wenig freier Platz fuer den Download.` | Limit (8 GB) oder zu wenig Platz. | Platz schaffen. |
| Vorprüfung `FEHLER Das Fenster muss als Administrator laufen.` / `Die Rolle Druckserver (Print-Server) ist nicht installiert.` / `PrintBrm.exe fehlt (erwartet: <Pfad>).` | Voraussetzung fehlt. | Als Administrator starten, Rolle installieren. |
| `Zu wenig freier Platz auf dem Systemlaufwerk: frei <x>, noetig etwa <y>.` | Import braucht Dateigröße mal zwei plus 500 MB. | Platz schaffen. |
| `Der Dienst Druckspooler laeuft nicht.` | Spooler gestoppt. | Dienst starten. |
| Hinweis `Namenskonflikte: <n> schon vorhanden, werden nicht ersetzt (<Namen>)` | Drucker gleichen Namens gibt es am neuen Server schon. | Entscheiden, ob **Vorhandene Drucker gleichen Namens überschreiben (-O FORCE)** gewollt ist. Ohne Inventur wird nicht geprüft („Namenskonflikte nicht pruefbar“). |
| `Es gibt keinen gesicherten alten Zustand. Das Druckprotokoll wurde von diesem Fenster nicht eingeschaltet.` | Beim Ausschalten gibt es keine gesicherte Zustandsdatei. | Das Protokoll in der Ereignisanzeige von Hand zurücksetzen. |
| `wevtutil meldet Exitcode <n>: <Meldung>` / `Die Ausgabe von wevtutil ist nicht lesbar.` | `wevtutil` konnte das Protokoll nicht ändern oder lesen. | Rechte, Protokollname `Microsoft-Windows-PrintService/Operational` und Größe prüfen. |
| `Die Groesse muss eine ganze Zahl von 1 bis 4096 (MB) sein.` / `Tage: 1 bis 3650.` | Eingabe außerhalb des Bereichs. | Wert korrigieren. |
| `Pseudonyme brauchen den zufaelligen Schluessel (64 Hexzeichen ...)` / `Rechnernamen werden nur zusammen mit den Benutzernamen pseudonymisiert.` | Schlüssel fehlt oder wurde geändert, oder nur Rechnernamen gewählt. | **Neuen Schlüssel** erzeugen, nicht von Hand ändern. Benutzernamen und Rechnernamen gemeinsam wählen. |
| Hinweise im Sofortbild (`SMB-Sitzungen nicht ermittelbar` usw.) | Ein Teil des Sofortbilds war nicht lesbar. | Kein Fehler: Der Rest ist enthalten. Der Hinweis steht in der Datei. |
| Auswertung: wenig oder keine Zugriffe | Das Druckprotokoll war nicht lange genug an, oder Ereignis 307 wird nicht geschrieben. | Zeitraum über der Tabelle prüfen und das Protokoll am alten Server länger laufen lassen. Ungenutzte Drucker sind nur im Zeitraum der Daten ungenutzt. |
| `Das ist keine Druckserver-Inventur.` / `Das ist keine Datei mit Druckzugriffen.` / `Unbekannte Schemaversion ...` / `Datei zu gross` / `Keine gueltige JSON-Datei` | Falsche oder beschädigte Datei geladen. | Die richtige Datei wählen. |

## Active Directory

| Meldung | Ursache | Lösung |
|---|---|---|
| `Das PowerShell-Modul ActiveDirectory fehlt. Es ist auf Domaenencontrollern dabei, sonst: Install-WindowsFeature RSAT-AD-PowerShell.` | Das Modul fehlt. | Modul installieren. Bis dahin sind die AD-Aktionen gesperrt. |
| `Vorpruefung nicht bestanden, nichts geaendert: <Punkte>` | Mindestens ein blockierender Punkt (Rechte, Replikation, `dcdiag`, Erreichbarkeit). | Die Details in der Prüfanzeige lesen (`[FEHLT]`), beheben und neu prüfen. |
| `<Inhaber> antwortet nicht. Bei dauerhaft ausgefallenem Server gibt es den getrennten Schritt Seize.` | Der aktuelle Rolleninhaber ist nicht erreichbar. | Ist er nur kurz weg: erreichbar machen und normal übertragen. Ist er dauerhaft verloren: Seize (siehe unten). |
| `Der Inhaber <Name> ist erreichbar (<Versuche>). Seize ist dafuer nicht erlaubt: bitte normal uebertragen.` | Beim Seize hat Ping, LDAP (389) oder RPC (135) in einer der drei Prüfungen geantwortet. | Rolle normal übertragen. Seize nur, wenn der Inhaber wirklich nicht mehr antwortet. |
| `Der getippte Rollenname stimmt nicht, nichts geaendert.` / `Es fehlt die Bestaetigung, dass der alte Inhaber dauerhaft entfernt ist ...` | Name nicht exakt (Groß-/Kleinschreibung) oder Haken fehlt. | Rollennamen genau so tippen (zum Beispiel `RIDMaster`) und den Haken setzen. |
| `Rechte fehlen: Mitglied von <Gruppe>` / `Das angemeldete Konto ist (in diesem Anmeldevorgang) nicht Mitglied. Neu anmelden, wenn es gerade aufgenommen wurde.` | Das Konto ist nicht in der nötigen Gruppe oder die Mitgliedschaft ist noch nicht im Token. | Mitgliedschaft prüfen, neu anmelden und das Server-Fenster neu starten. |
| `Nachpruefung: diese Rollen liegen noch nicht hier: <Rollen>` | Die Übertragung wurde ausgeführt, aber die Rollen stehen noch nicht auf diesem Server. | Replikation abwarten, **Übersicht erstellen** wiederholen, ggf. Ereignisprotokoll des DCs prüfen. |
| **ntdsutil-Timeout:** `ntdsutil nimmt das Kennwort hier nicht an – bitte die Variante Synchronisieren nutzen. (ntdsutil antwortete nicht und wurde beendet; Variante B ist im Labor zu pruefen.)` | `ntdsutil` hat nach 60 Sekunden nicht geantwortet (ohne Konsole kann es hängen) und wurde vom Tool beendet. Ob es das Kennwort über die Standardeingabe annimmt, ist noch nicht an einem echten System geprüft. Es gilt als **nicht gesetzt**. | **Weg A (Synchronisieren)** nutzen: Domänenkonto, am besten ein eigenes deaktiviertes Konto. Weg B ist noch nicht an einem echten System erprobt. |
| `ntdsutil hat das Kennwort nicht bestaetigt (Exitcode <n>, keine Erfolgsmeldung). Status: <Zeile>. Bitte die Variante Synchronisieren nutzen.` / `ntdsutil hat die Synchronisierung nicht bestaetigt ...` | Das Tool wertet die Ausgabe aus: Erfolg nur mit Erfolgsmeldung („Password has been set successfully“ oder die deutsche Entsprechung), nicht allein am Exitcode. Die deutsche Meldung ist noch nicht an einem echten System geprüft. | Status-Zeile lesen. Konto und Rechte prüfen, Weg A versuchen. Bei einer anderssprachigen Meldung, die als Fehler gewertet wird: bitte melden. |
| `Das Kennwort ist nicht komplex genug: mindestens 12 Zeichen; mindestens drei von: ...; keine Anfuehrungszeichen` / `Die beiden Eingaben stimmen nicht ueberein.` | Eingabe erfüllt die Regeln nicht. | Kennwort anpassen. |
| `ACHTUNG: Das Konto ist Mitglied privilegierter Gruppen (...)` / `ACHTUNG: Das Konto ist aktiviert ...` | Das Konto für die Synchronisierung ist privilegiert oder kann sich anmelden. Sein Kennwort wäre zugleich das DSRM-Kennwort. | Ein eigenes, deaktiviertes Konto ohne Gruppenmitgliedschaften verwenden. |
| `Dieser Server ist ein RODC und kann keine Rollen halten.` | Das Fenster läuft auf einem schreibgeschützten DC. | Auf einem beschreibbaren DC starten. |
| Ebenen-Vorprüfung: `Zu alt: <DC> (<Betriebssystem>)` / `Nicht erkennbar: <DC>` / `Erst die Domaene(n) anheben: ...` / `Replikationsfehler oder nicht pruefbar` | Ein DC trägt die Zielebene nicht, das Betriebssystem ist nicht erkennbar, bei der Gesamtstruktur steht eine Domäne noch darunter, oder die Replikation hat Fehler. | DCs aktualisieren oder abstufen, Domänen zuerst anheben, Replikation reparieren. |
| `Der getippte Name stimmt nicht, nichts geaendert.` | Domänen- oder Gesamtstrukturname nicht richtig getippt. | Den Namen genau eintippen (zum Beispiel `contoso.local`). |
| `Als Quelle ist nur ein eingebundenes Installationsmedium erlaubt ...` / `Das ist kein eingebundenes Installationsmedium (Laufwerk vom Typ CD-ROM). Das ISO erst einbinden ...` | Kein Medium, sondern ein Ordner, Netzwerkpfad oder ein nicht eingebundenes ISO. | ISO per Rechtsklick **Bereitstellen** einbinden, dann **Laufwerk suchen**. |
| `Auf dem Medium fehlt support\adprep\adprep.exe.` | Das ISO enthält den Ordner nicht (zum Beispiel falsches Medium). | Das originale Windows-Server-ISO verwenden. |
| `Pruefung der Kopie nicht bestanden, nichts gestartet: <Punkte>` (zum Beispiel `adprep.exe: keine gueltige Microsoft-Signatur ...` oder `<Datei>: die Kopie weicht von der Quelle ab`) | Die kopierten Dateien bestehen die Prüfung nicht: ungültige Signatur, falscher Dateiname, Hash-Abweichung, Verknüpfungen oder Ordner zu groß. | Nur ein **originales Microsoft-ISO** verwenden. Ist das Medium sicher original, Quelle (Laufwerk) prüfen und erneut versuchen. adprep wird nicht gestartet. |
| `Dieser Server ist der Schemamaster` / `... der Infrastrukturmaster` (Vorprüfung nicht ok) | adprep läuft nur auf dem Inhaber der jeweiligen Rolle. | Rolle zuerst hierher übertragen oder dort ausführen. |
| `adprep meldete einen Fehler (Exitcode <n>); Ausgabe in <Datei>` | adprep ist fehlgeschlagen. | Die Ausgabedatei unter `%ProgramData%\ServerMigration\AD` lesen. Schema-Version vorher und nachher mit der Übersicht prüfen. |
| `Die Aktion wurde ausgefuehrt, aber das Protokoll konnte nicht geschrieben werden: <Fehler>` | Die Aktion lief, aber die Protokollzeile nicht. | Zustand per **Übersicht erstellen** prüfen. Rechte von `%ProgramData%\ServerMigration\AD` prüfen. |

## Allgemein

| Bild | Ursache | Lösung |
|---|---|---|
| Ein Knopf ist ausgegraut | Das Fenster läuft nicht als Administrator, ein Modul fehlt, eine Voraussetzung (Prüfsumme, Haken, getippter Name) ist noch nicht erfüllt, oder ein anderer Auftrag läuft. | Hinweise oben im Fenster und die Vorprüfung lesen. |
| Das Fenster zeigt `Kein Tauschordner verbunden` | Der Server hat den Ordner nicht erreicht. | **Ordner prüfen** auf der Seite **Dieser Server**. Ursachen siehe [Tauschordner](#tauschordner). |
| Berater-Tool: `Zuerst auf der Seite Tauschordner verbinden.` | Auswertungen holen Dateien aus dem aktiven Tauschordner. | Auf der Seite **Tauschordner** **Verbinden** klicken. |
| Tabellenexport: `Der Tabellenexport (Modules\SmExport.ps1) ist in dieser Version noch nicht enthalten.` | Eine Teilkopie des Repos ohne diese Datei. | Das vollständige Release verwenden. |
| Tests melden `FAIL` | Eine Änderung hat eine geprüfte Eigenschaft verletzt, oder die Tests liefen in PowerShell 7. | Mit Windows PowerShell 5.1 und `-STA` starten (siehe [README](../README.md#tests-ausführen)). |
