# Sicherheit

Diese Seite beschreibt, was das Tool absichert, was nicht, und was du als Anwender beachten musst. Die Prüfpunkte für Entwickler stehen in der [Sicherheits-Checkliste](security-checklist.md). Die Bedienung steht in der [Anleitung](ANLEITUNG.md).

## Inhalt

1. [Das Modell in drei Sätzen](#das-modell-in-drei-sätzen)
2. [Was die Prüfsummen schützen und was nicht](#was-die-prüfsummen-schützen-und-was-nicht)
3. [Akzeptiertes Risiko: Link im Verlauf und in den Protokollen](#akzeptiertes-risiko-link-im-verlauf-und-in-den-protokollen)
4. [Personenbezogene Daten und Löschen nach Projektende](#personenbezogene-daten-und-löschen-nach-projektende)
5. [Was jede ändernde Aktion prüft](#was-jede-ändernde-aktion-prüft)
6. [Rechte, die nötig sind](#rechte-die-nötig-sind)

## Das Modell in drei Sätzen

Der **Tauschordner-Link ist der Schlüssel**: Wer ihn kennt, kann im Ordner lesen, schreiben und löschen. Alles, was vom Tauschordner auf einen Server kommt und dort etwas ausführt oder verändert, wird vorher per Prüfsumme bestätigt, deren Wert nicht über den Tauschordner kommt. Alles, was aus dem Tauschordner nur gelesen wird (Logs, Berichte, Inventuren), gilt als nicht vertrauenswürdig und wird mit Größenlimits und strengen Parsern gelesen.

## Was die Prüfsummen schützen und was nicht

Das Tool nutzt SHA256 an drei Stellen:

| Prüfsumme | Woher der Sollwert kommt | Was sie verhindert |
|---|---|---|
| **Server-Paket** (Einzeiler) | Steht im Einzeiler, den das Berater-Tool erzeugt. | Dass jemand das Paket im Tauschordner austauscht: Der Einzeiler prüft die Bytes im Speicher, bevor etwas geschrieben, entpackt oder gestartet wird. |
| **DHCP-Export** | Wird am alten Server angezeigt und von dir am neuen Server **vollständig eingegeben**. | Dass ein ausgetauschtes oder verändertes ZIP importiert wird. Verglichen wird über genau die Bytes der Arbeitskopie, die danach gesperrt gehalten wird. |
| **Print-Export und Inventur** | Wie bei DHCP, für beide Dateien. | Dasselbe. Eine Exportdatei mit Treibern gilt wie ein Skript: ohne Treffer kein Import. |

**Was sie nicht schützen:**

- **Vertraulichkeit.** Die Dateien im Tauschordner sind nicht verschlüsselt. Wer den Link hat, kann sie lesen (DNS-Logs, DHCP-Leases, Druckprotokolle, Berichte).
- **Den Einzeiler selbst.** Die Prüfsumme steht im Einzeiler neben dem Link. Wer den Einzeiler ändert, kann Link und Prüfsumme gemeinsam ändern. Gib den Einzeiler nur über einen Kanal weiter, dem du vertraust.
- **Einen manipulierten alten Server.** Die Prüfsumme sagt, dass die Datei dieselbe ist, die am alten Server erzeugt wurde, nicht dass ihr Inhalt richtig ist.
- **Den Inhalt der Daten.** Auswertungen (DNS, Print, AD-Berichte) und der DHCP-Vergleich haben keine Prüfsumme. Sie werden mit Größenlimits, XML ohne DTD und JSON über feste Parser gelesen und nie ausgeführt.
- **Den Starter von GitHub.** Die Zeile `irm … | iex` lädt das Tool aus einem Release auf GitHub. Eine veröffentlichte Prüfsumme oder Signatur dafür gibt es noch nicht. Verwende ein Release (`$env:TOOL_REF`), nicht `main`, wenn du es kontrolliert einsetzt.
- **Eine ältere Projektliste.** Die Projektliste ist verschlüsselt und gegen Verändern geschützt, aber wer den Ordnerlink hat, kann eine ältere Fassung zurückspielen.

Weitere Schutzmaßnahmen bei Download und Weiterleitung:

- Nur `https` auf `*.sharepoint.com`, auch nach Weiterleitungen. TLS 1.2 oder höher, keine Zertifikatsausnahmen.
- Downloads brechen ab, sobald das Größenlimit überschritten ist.
- Dateinamen aus dem Tauschordner werden nur als Dateiname übernommen und gegen eine Whitelist geprüft.
- Niemals wird XML aus dem Tauschordner mit `Import-Clixml` geöffnet.

## Akzeptiertes Risiko: Link im Verlauf und in den Protokollen

Der Einzeiler enthält den Tauschordner-Link. Weil du ihn auf dem Kundenserver einfügst, kann der Link dort an Stellen landen, die das Tool nicht kontrolliert:

- im **Verlauf** der PowerShell-Sitzung (PSReadLine speichert eingegebene Zeilen),
- in **Protokollen**, die der Kunde eingeschaltet hat (zum Beispiel PowerShell Script Block Logging oder Transkription, Prozessprotokollierung der Bastion).

Das Tool selbst schreibt den Link nie in Logs, Dateien, Fehlermeldungen oder den Tauschordner. Das Risiko beim Einfügen des Einzeilers bleibt aber bestehen und ist **bewusst akzeptiert**. So begrenzt du es:

1. Lege den Link mit einem **kurzen Ablaufdatum** an.
2. **Lösche die Freigabe nach dem Projekt**, damit der Link wertlos wird.
3. Auch ohne Link schützt die Prüfsumme das Paket gegen Austausch. Wer den Link aus einem Protokoll liest, kann aber Dateien im Tauschordner lesen. Rechne also damit, dass dort nichts steht, was nicht auch der Kunde sehen darf.
4. Prüfe den Verlauf des Servers nach dem Projekt und bereinige ihn nach den Vorgaben des Kunden.

## Personenbezogene Daten und Löschen nach Projektende

| Daten | Enthält | Wo sie liegen |
|---|---|---|
| DNS-Logs | Client-Adressen und abgefragte Namen | `%windir%\System32\dns` (Logdatei), ZIP im Tauschordner, auf dem Berater-Rechner bei der Auswertung und im Export |
| DHCP-Export und -Stand | MAC-Adressen und Hostnamen der Leases (mit Leases), Gerätenamen und MAC-Adressen der Reservierungen | ZIP und JSON im Tauschordner, Arbeitsordner und Sicherungsordner auf dem Server |
| Druckprotokoll und Sofortbild | Benutzer- und Rechnernamen, SMB-Sitzungen, offene Dateien | `Print-Zugriffe-*.json` im Sicherungsordner, im Tauschordner und im Berater-Tool |
| Print-Export und -Inventur | Druckernamen, Standorte, Kommentare, Treiber (Programmcode) | Sicherungsordner, Tauschordner |
| AD-Bericht | Namen der DCs, Standorte, Betriebssysteme, Replikationszustand | Sicherungsordner, Tauschordner |
| Projektliste | Kundennamen, Notizen, Servernamen, Tauschordner-Links (verschlüsselt) | Ordner der Projektliste, Arbeitsspeicher des Berater-Tools |

**Was das Tool dafür tut:**

- Es sammelt nur, was die Auswertung braucht (zum Beispiel keine Dokumentnamen aus dem Druckprotokoll).
- Vor Export, Sammeln und Hochladen weist der Dialog auf personenbezogene Daten hin.
- DHCP: **Ohne Leases** exportieren oder den Stand ohne Lease-Liste hochladen. Die Lease-Liste in der Zusammenfassung enthält nur Adresse und MAC, keine Hostnamen.
- Print: Benutzernamen (und Rechnernamen) lassen sich **pseudonymisieren**: HMAC-SHA256 mit einem zufälligen Schlüssel aus dem Zufallsgenerator, Ausgabe 12 Hexzeichen. Der Schlüssel steht nie in einer Datei, im Tauschordner oder im Protokoll. Das Berater-Tool kann Benutzernamen in Anzeige und Export zusätzlich kürzen, mit einem eigenen Schlüssel je Sitzung.
- Sicherungsordner `%ProgramData%\ServerMigration` wird vor jeder Nutzung gehärtet: Besitzer und Zugriffsliste nur Administratoren und SYSTEM, keine Verknüpfung, sonst bricht das Tool ab.

**Was du nach Projektende löschen musst** (das Tool löscht nichts davon automatisch außer seinen kurzlebigen Arbeitsordnern):

1. **Tauschordner**: alle Dateien und die Freigabe.
2. **Kundenserver**: `%ProgramData%\ServerMigration` (Exporte, Sicherungen, Protokolle, gesicherte Zustände) und `%TEMP%\ServerMigration-*`. Die DNS-Logdatei nach Absprache mit dem Kunden löschen oder behalten.
3. **Berater-Rechner**: heruntergeladene ZIPs, exportierte CSV- und Excel-Dateien, exportierte Projektdateien. **Gemerkte Verbindung löschen** (Seite Projekte).
4. **Projektliste**: Projekt löschen oder auf Abgeschlossen setzen.
5. **Pseudonym-Schlüssel**: vernichten, wenn die Berichte nicht mehr verglichen werden müssen. Ohne Schlüssel lassen sich die Kürzel nicht mehr zuordnen.

Ob und wie lange Daten aufbewahrt werden dürfen, richtet sich nach der Vereinbarung mit dem Kunden und den geltenden Datenschutzvorgaben. Das Tool nimmt dir diese Entscheidung nicht ab.

## Was jede ändernde Aktion prüft

Jede Aktion, die etwas am Server verändert, folgt demselben Muster: **Vorprüfung, Bestätigung im Fenster, danach eine Protokollzeile ohne Geheimnisse.** In der Protokollzeile stehen nie Links, Kennwörter oder Schlüssel. Protokolle: DHCP `%ProgramData%\ServerMigration\dhcp-protokoll.log`, Print `…\Print\Protokoll.log`, AD `…\AD\Protokoll.log`. Das DNS-Logging protokolliert im Fenster.

| Aktion | Vorprüfung und zusätzliche Sicherungen |
|---|---|
| **DNS-Logging ein** | Administrator; DNS-Cmdlets vorhanden; Pfad nur in `%windir%\System32\dns`, Endung `.log` oder `.txt`, lokales Laufwerk, kein Ordner, vorhandene Datei muss die Kopfzeile „DNS Server log file creation“ haben; Größe 10 bis 2048 MB; freier Platz mindestens 110 % der Größe; Sicherungsordner gehärtet; vorheriger Zustand gesichert; Nachprüfung, dass das Logging aktiv ist. |
| **DNS-Logging aus** | Administrator; DNS-Cmdlets; gesicherter Zustand wird streng geprüft (Ordner gehärtet, Größe, Werte, Pfad) und wiederhergestellt; Nachprüfung. |
| **DNS-Logs hochladen** | Pfad wie oben; Logdatei vorhanden und nicht leer; genug Platz im Temp-Ordner; Arbeitsordner nur unter `%TEMP%\ServerMigration-dns-<Zufall>`, danach gelöscht. |
| **DHCP-Export** | Modul `DhcpServer`, Dienst läuft, Administrator. Ändert nichts am DHCP-Server. Hinweisdialog zu personenbezogenen Daten. |
| **DHCP-Import** | Wie Export; vollständige Prüfsumme; ZIP enthält genau `dhcp-export.xml` und `dhcp-summary.json`; Größenlimits; XML ohne DTD; Zusammenfassung stimmt bei Bereichen und Optionen 3, 6, 15, 44, 252 mit der XML überein, sonst kein Import; Arbeitskopie im gehärteten Ordner ohne Verknüpfungen, durch ein Handle gesperrt; Bestätigung mit Inhalt der XML; Dreifach-Frage bei vorhandenen Bereichen; Datenbanksicherung vor dem Import. |
| **DHCP-Autorisierung** | Modul, Dienst, Administrator; Server ist noch nicht autorisiert; Autorisierungsliste lesbar; Bestätigung; Nachprüfung der Liste. |
| **DHCP-Bereiche deaktivieren** | Bereiche existieren; Failover-Beziehungen werden gemeldet; Bestätigung nennt den Server; zusätzliche Warnung, wenn dieses Fenster selbst importiert hat. |
| **Print-Export** | Administrator, Rolle Druckserver, `PrintBrm.exe`; Bestätigung; Exitcode von `PrintBrm`; Datei vorhanden und nicht leer. |
| **Print-Import** | Wie Export plus: Export- und Inventur-Prüfsumme vollständig; Arbeitskopie im gehärteten Ordner, nicht als Verknüpfung, Besitzer Administrator oder SYSTEM, per Handle gesperrt und erneut gehasht; Platz (Datei mal zwei plus 500 MB); Druckspooler läuft; Namenskonflikte gegen die Inventur; Bestätigung mit Inhalt der Exportdatei (`PrintBrm -Q`); „Freigaben nicht übernehmen“ wirkt nur auf neu angelegte Drucker. |
| **Druckprotokoll ein und aus** | Administrator; alter Zustand wird gesichert und beim Ausschalten wiederhergestellt; Größe 1 bis 4096 MB; Bestätigung. |
| **Zugriffe sammeln** | Administrator; Bestätigung mit Datenschutzhinweis; Tage 1 bis 3650; Pseudonyme nur mit gültigem Schlüssel. |
| **FSMO übertragen** | Administrator; AD-Modul; beschreibbarer DC; Gruppenmitgliedschaft im Token; Inhaber erreichbar; Replikation ohne Fehler; `dcdiag` ohne Fehler; Bestätigung; Nachprüfung der Rollen. |
| **Seize** | Dazu drei Prüfungen des Inhabers (Ping, LDAP 389, RPC 135 im Abstand von 10 s, antwortet eines, ist Seize verboten); Haken „alter Inhaber dauerhaft entfernt“; getippter Rollenname; Rechte; Bestätigung; Nachprüfung. |
| **DSRM-Kennwort** | Administrator; kein RODC. Weg A: Konto wird gelesen und bei aktiviertem oder privilegiertem Konto gewarnt; Erfolg nur bei Erfolgsmeldung von `ntdsutil`. Weg B: Kennwort zweimal, mindestens 12 Zeichen, drei von vier Zeichenarten; nur über die Standardeingabe; kurzer Timeout; nie protokolliert. |
| **Funktionsebene anheben** | Administrator; alle DCs tragen die Zielebene; bei Gesamtstruktur alle Domänen auf Zielebene; Replikation in Ordnung; Rechte (Domain Admins bzw. Enterprise Admins); getippter Name der Domäne bzw. Gesamtstruktur; Bestätigung; Nachprüfung. |
| **adprep** | Administrator; nur eingebundenes Installationsmedium; Rolle des Servers (Schemamaster bzw. Infrastrukturmaster); Rechte; Replikation in Ordnung; Probekopie und Prüfung der Kopie (Signaturen, SHA256 gegen die Quelle); Bestätigung; Start nur aus der geprüften Kopie, die dabei gesperrt bleibt. |

Scheitert die Protokollzeile, meldet das Tool das als Fehler und schreibt es nicht still weg.

## Rechte, die nötig sind

| Wo | Recht | Wofür |
|---|---|---|
| Berater-Rechner | Normaler Benutzer; Zugriff auf `*.sharepoint.com` und für den Start auf GitHub | Projektliste, Tauschordner, Auswertung. |
| Tauschordner | Link „Jeder mit dem Link kann bearbeiten“ | Lesen, Schreiben und Löschen von Dateien für Berater und Server. |
| Kundenserver, alle Bereiche | **Lokaler Administrator** (Windows PowerShell „Als Administrator ausführen“), Zugriff auf `*.sharepoint.com` | Schreiben in `%ProgramData%\ServerMigration`, ändernde Aktionen. Ohne Administrator sind die ändernden Aktionen gesperrt. |
| DNS | DNS-Rolle oder DNS-Verwaltungs-Cmdlets | `Get-DnsServerDiagnostics`, `Set-DnsServerDiagnostics`. Metadaten: `Get-DnsServerForwarder`, `Get-DnsServerZone`; das AD-Modul nur für die Liste der DCs (fehlt es, steht ein Hinweis in der Metadatei). |
| DHCP | Modul `DhcpServer`, Dienst `DHCPServer` läuft | Export, Import, Deaktivieren. Autorisierung in AD: Enterprise Admin oder entsprechend delegiert. |
| Print | Rolle Druckserver, `PrintBrm.exe`, Druckspooler läuft | Export und Import. Druckprotokoll: `wevtutil`. Sofortbild: SMB-Cmdlets (nicht ermittelbare Teile werden als Hinweis vermerkt). |
| AD, alle Aktionen | Modul `ActiveDirectory` auf dem neuen DC, Mitglied von **Domain Admins** | FSMO übertragen, Seize, Ebene der Domäne, adprep `/domainprep`. |
| AD, Schemamaster | zusätzlich **Schema Admins** | FSMO-Rolle Schemamaster, adprep `/forestprep`. |
| AD, Domänennamenmaster und Gesamtstruktur | zusätzlich **Enterprise Admins** | FSMO-Rolle Domänennamenmaster, Ebene der Gesamtstruktur, adprep `/forestprep`. |

Die Gruppenmitgliedschaft wird im Token der **aktuellen Anmeldung** geprüft. Wurde das Konto gerade erst aufgenommen, melde dich neu an.
