#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 5 (Print): Ereignis 307 parsen (Beispiel-XML, XXE/DTD), Auswertung inklusive ungenutzter Drucker,
    Inventurvergleich, feindliche Dateien (Groessenlimit, falscher Typ, Texte nur als Daten), Pseudonyme,
    Export-SmTable (gemockt), gehaerteter Sicherungsordner, Vorpruefungen, Export und Import mit PrintBrm-Stub,
    Druckprotokoll mit wevtutil-Stub (alten Zustand sichern und wiederherstellen), Sammeln mit gemockten Cmdlets
    und beide Fenster mit -ParseOnly. Keine echten Drucker, kein echtes PrintBrm oder wevtutil, nur Beispieldaten (contoso.local).
    Wird von tests\Test-ServerMigration.ps1 aufgerufen und liefert die Zahl der Fehler zurueck. Allein:
    powershell.exe -NoProfile -STA -File tests\Test-Print.ps1
#>
[CmdletBinding()]
param([string]$Repo, [string]$Work)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
if (-not $Repo) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$ownWork = -not $Work
if (-not $Work) { $Work = Join-Path $env:TEMP ('sm-print-' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Force $Work | Out-Null }
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }
function ThrowsLike([scriptblock]$Block, [string]$Pattern) { try { & $Block | Out-Null; $false } catch { $_.Exception.Message -match $Pattern } }

. (Join-Path $Repo 'Modules\SmShell.ps1')
. (Join-Path $Repo 'Modules\SmTausch.ps1')
. (Join-Path $Repo 'Modules\SmPrint.ps1')
. (Join-Path $Repo 'server\SmDnsServer.ps1')
. (Join-Path $Repo 'server\SmPrintServer.ps1')
$pw = Join-Path $Work 'print'
New-Item -ItemType Directory -Force $pw | Out-Null

# ---------------------------------------------------------------- 1. Ereignis 307 parsen
function New-EventXml([string]$Time, [string]$User, [string]$Client, [string]$Printer, [string]$Port, [int]$Pages, [long]$Bytes, [int]$Id = 307, [long]$Rec = 1) {
    @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-PrintService" Guid="{747EF6FD-E535-4D16-B510-42C90F6873A1}"/><EventID>$Id</EventID><TimeCreated SystemTime="$Time"/><EventRecordID>$Rec</EventRecordID><Security UserID="S-1-5-21-1-2-3-1001"/></System><UserData><DocumentPrinted xmlns="http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events"><Param1>12</Param1><Param2>Quartalsbericht.docx</Param2><Param3>$User</Param3><Param4>$Client</Param4><Param5>$Printer</Param5><Param6>$Port</Param6><Param7>$Bytes</Param7><Param8>$Pages</Param8></DocumentPrinted></UserData></Event>
"@
}
$e1 = ConvertFrom-SmPrintEventXml -Xml (New-EventXml '2026-11-10T08:15:30.1234567Z' 'anna' '\\PC-ANNA.contoso.local' 'HP-Buero-1' 'IP_10.0.0.51' 3 45678)
Check 'Ereignis 307: Zeit (UTC), Benutzer, Rechner ohne \\, Drucker, Port, Seiten, Bytes' ($e1.Time -eq [datetime]::new(2026, 11, 10, 8, 15, 30, [DateTimeKind]::Utc).AddTicks(1234567) -and $e1.User -eq 'anna' -and $e1.Client -eq 'PC-ANNA.contoso.local' -and $e1.Printer -eq 'HP-Buero-1' -and $e1.Port -eq 'IP_10.0.0.51' -and $e1.Pages -eq 3 -and $e1.Bytes -eq 45678 -and $e1.RecordId -eq 1)
Check 'Ereignis 307: Dokumentname wird nicht uebernommen (Datenschutz)' (-not ($e1.PSObject.Properties.Name -match 'Doc') -and (($e1 | ConvertTo-Json) -notmatch 'Quartalsbericht'))
Check 'Ereignis anderer Nummer (308) wird verworfen' ($null -eq (ConvertFrom-SmPrintEventXml -Xml (New-EventXml '2026-11-10T08:00:00Z' 'a' 'b' 'c' 'd' 1 1 308)))
Check 'Ereignis ohne Zeit wird verworfen' ($null -eq (ConvertFrom-SmPrintEventXml -Xml '<Event><System><EventID>307</EventID></System></Event>'))
Check 'Ereignis kein XML: verworfen, kein Fehler' ($null -eq (ConvertFrom-SmPrintEventXml -Xml 'das ist kein xml'))
$dtd = '<?xml version="1.0"?><!DOCTYPE e [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]>' + (New-EventXml '2026-11-10T08:00:00Z' '&x;' 'b' 'c' 'd' 1 1)
Check 'Ereignis mit DTD/XXE (DtdProcessing=Prohibit): verworfen' ($null -eq (ConvertFrom-SmPrintEventXml -Xml $dtd))
$bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>' + (New-EventXml '2026-11-10T08:00:00Z' '&b;' 'b' 'c' 'd' 1 1)
Check 'Ereignis mit Entity-Bombe: verworfen' ($null -eq (ConvertFrom-SmPrintEventXml -Xml $bomb))
Check 'Ereignis zu gross (ueber 64 KB): verworfen' ($null -eq (ConvertFrom-SmPrintEventXml -Xml (New-EventXml '2026-11-10T08:00:00Z' ('x' * 70000) 'b' 'c' 'd' 1 1)))
$long = ConvertFrom-SmPrintEventXml -Xml (New-EventXml '2026-11-10T08:00:00Z' (('u' * 400) + '&#x9;') 'b' 'HP' 'p' 1 1)
Check 'Ereignistext: gekuerzt auf 256 und ohne Steuerzeichen (bleibt Text)' ($long.User.Length -eq 256 -and $long.User -notmatch '[\x00-\x1F]')
$odd = ConvertFrom-SmPrintEventXml -Xml (New-EventXml '2026-11-10T08:00:00Z' "=cmd|' /c calc'!A1" 'b' 'HP' 'p' 1 1)
Check 'Ereignistext mit Formel-Zeichen bleibt reiner Text (Export-SmTable schuetzt Tabellen)' ($odd.User -eq "=cmd|' /c calc'!A1")
$srcText = (Get-Content -LiteralPath (Join-Path $Repo 'Modules\SmPrint.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $Repo 'server\SmPrintServer.ps1') -Raw)
Check 'Quelltext: DtdProcessing Prohibit, kein Import-Clixml, kein Invoke-Expression auf Fremddaten' ($srcText -match 'DtdProcessing\]::Prohibit' -and $srcText -notmatch 'Import-Clixml' -and $srcText -notmatch 'Invoke-Expression|\biex\b')

# ---------------------------------------------------------------- 2. Daten fuer Auswertung und Vergleich
$t0 = [datetime]::new(2026, 10, 1, 8, 0, 0, [DateTimeKind]::Utc)
function Ev([int]$Day, [string]$User, [string]$Client, [string]$Printer, [int]$Pages = 2, [long]$Id = 0) {
    [pscustomobject]@{ Time = $t0.AddDays($Day); User = $User; Client = $Client; Printer = $Printer; Port = 'IP_10.0.0.5'; Pages = $Pages; Bytes = 1000L * $Pages; RecordId = $Id }
}
$events = @(
    (Ev 0 'anna' 'PC-ANNA' 'HP-Buero-1' 3 1), (Ev 1 'anna' 'PC-ANNA' 'HP-Buero-1' 2 2), (Ev 2 'anna' 'PC-ANNA' 'Kyocera-Flur' 10 3),
    (Ev 3 'bernd' 'PC-BERND' 'HP-Buero-1' 1 4), (Ev 40 'bernd' 'PC-ANNA' 'hp-buero-1' 5 5), (Ev 41 'clara' 'LAPTOP-CLARA' '\\ps01\Kyocera-Flur' 4 6)
)
$invOld = [pscustomobject]@{
    Computer = 'PS-ALT'; Created = $t0; Role = 'alt'
    Printers = @(
        [pscustomobject]@{ Name = 'HP-Buero-1'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = 'HP-Buero-1'; Shared = $true; Published = $true; Location = 'Haus A'; Comment = ''; Type = 'Local' }
        [pscustomobject]@{ Name = 'Kyocera-Flur'; DriverName = 'Kyocera KX'; PortName = 'IP_10.0.0.6'; ShareName = 'Kyocera-Flur'; Shared = $true; Published = $false; Location = 'Flur'; Comment = 'alt'; Type = 'Local' }
        [pscustomobject]@{ Name = 'Epson-Lager'; DriverName = 'Epson ESC'; PortName = 'IP_10.0.0.7'; ShareName = 'Epson-Lager'; Shared = $true; Published = $false; Location = 'Lager'; Comment = ''; Type = 'Local' }
        [pscustomobject]@{ Name = 'Brother-Alt'; DriverName = 'Brother'; PortName = 'LPT1:'; ShareName = ''; Shared = $false; Published = $false; Location = ''; Comment = ''; Type = 'Local' }
    )
    Drivers = @(
        [pscustomobject]@{ Name = 'HP Universal'; Version = '7.0.1.24923'; Architecture = 'x64'; DriverType = 3; Manufacturer = 'HP' }
        [pscustomobject]@{ Name = 'HP Universal'; Version = '7.0.1.24923'; Architecture = 'x86'; DriverType = 3; Manufacturer = 'HP' }
        [pscustomobject]@{ Name = 'Kyocera KX'; Version = '8.0.0.0'; Architecture = 'x64'; DriverType = 3; Manufacturer = 'Kyocera' }
    )
    Ports = @(
        [pscustomobject]@{ Name = 'IP_10.0.0.5'; Description = ''; Address = '10.0.0.5'; PortNumber = 9100 }
        [pscustomobject]@{ Name = 'IP_10.0.0.6'; Description = ''; Address = '10.0.0.6'; PortNumber = 9100 }
    )
}
$invNew = [pscustomobject]@{
    Computer = 'PS-NEU'; Created = $t0; Role = 'neu'
    Printers = @(
        [pscustomobject]@{ Name = 'HP-Buero-1'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = 'HP-Buero-1'; Shared = $true; Published = $true; Location = 'Haus A'; Comment = ''; Type = 'Local' }
        [pscustomobject]@{ Name = 'Kyocera-Flur'; DriverName = 'Kyocera KX V4'; PortName = 'IP_10.0.0.6'; ShareName = 'Kyocera-Flur'; Shared = $false; Published = $false; Location = 'Flur'; Comment = 'alt'; Type = 'Local' }
        [pscustomobject]@{ Name = 'Neu-Test'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = 'Neu-Test'; Shared = $true; Published = $false; Location = ''; Comment = ''; Type = 'Local' }
    )
    Drivers = @(
        [pscustomobject]@{ Name = 'HP Universal'; Version = '7.0.1.24923'; Architecture = 'x64'; DriverType = 3; Manufacturer = 'HP' }
        [pscustomobject]@{ Name = 'Kyocera KX'; Version = '9.0.0.0'; Architecture = 'x64'; DriverType = 4; Manufacturer = 'Kyocera' }
    )
    Ports = @([pscustomobject]@{ Name = 'IP_10.0.0.5'; Description = ''; Address = '10.0.0.5'; PortNumber = 9100 })
}

# ---------------------------------------------------------------- 3. Auswertung
$u = Get-SmPrintUsage -Events $events -Inventory $invOld
Check 'Zeitraum: von erstem bis letztem Ereignis, 6 Auftraege, 42 Tage' ($u.Period.Count -eq 6 -and $u.Period.From -eq $t0 -and $u.Period.To -eq $t0.AddDays(41) -and $u.Period.Days -eq 41)
$anna = $u.ByUser | Where-Object Name -eq 'anna'
Check 'je Benutzer: anna 2 Drucker, 3 Auftraege, 15 Seiten, letzte Nutzung' ($anna.Printers -eq 2 -and $anna.Jobs -eq 3 -and $anna.Pages -eq 15 -and $anna.LastUse -eq '2026-10-03 08:00')
Check 'je Benutzer: 3 Benutzer, haeufigster zuerst' (@($u.ByUser).Count -eq 3 -and $u.ByUser[0].Name -eq 'anna')
$pcAnna = $u.ByClient | Where-Object Name -eq 'PC-ANNA'
Check 'je Rechner: PC-ANNA benutzt von anna und bernd, 4 Auftraege' ($pcAnna.Jobs -eq 4 -and $pcAnna.Printers -eq 2)
$hp = $u.ByPrinter | Where-Object Printer -eq 'HP-Buero-1'
Check 'je Drucker: HP-Buero-1 (Gross/Klein egal) 4 Auftraege, 2 Benutzer, 2 Rechner, erste und letzte Nutzung' ($hp.Jobs -eq 4 -and $hp.Users -eq 2 -and $hp.Clients -eq 2 -and $hp.FirstUse -eq '2026-10-01 08:00' -and $hp.LastUse -eq '2026-11-10 08:00')
$ky = $u.ByPrinter | Where-Object Printer -eq 'Kyocera-Flur'
Check 'je Drucker: \\server\Name im Ereignis zaehlt zum Drucker (Kyocera 2 Auftraege)' ($ky.Jobs -eq 2)
Check 'ungenutzte Drucker: Epson-Lager und Brother-Alt (in der Inventur, kein Ereignis)' ((@($u.Unused | ForEach-Object Printer) -join ',') -eq 'Brother-Alt,Epson-Lager')
Check 'ungenutzte Drucker tragen Freigabe, Port, Treiber, Standort' ((($u.Unused | Where-Object Printer -eq 'Epson-Lager').Location -eq 'Lager') -and (($u.Unused | Where-Object Printer -eq 'Epson-Lager').Driver -eq 'Epson ESC'))
$uNone = Get-SmPrintUsage -Events $events
Check 'ohne Inventur: keine ungenutzten Drucker gemeldet' (@($uNone.Unused).Count -eq 0)
$uEmpty = Get-SmPrintUsage -Events @() -Inventory $invOld
Check 'ohne Ereignisse: alle Inventurdrucker ungenutzt, Zeitraum leer' (@($uEmpty.Unused).Count -eq 4 -and $uEmpty.Period.Count -eq 0 -and (Get-SmPrintPeriodText $uEmpty.Period) -match 'Keine Ereignisse')
Check 'Zeitraumtext nennt Daten und warnt bei weniger als einem Monat' ((Get-SmPrintPeriodText $u.Period) -match '2026-10-01 bis 2026-11-11' -and (Get-SmPrintPeriodText (Get-SmPrintUsage -Events $events[0..2] -Inventory $invOld).Period) -match 'kuerzer als ein Monat')
$m = Get-SmPrintUsage -Events $events -MaskUsers -Salt 'abc'
Check 'Pseudonyme: keine Klarnamen in der Auswertung, gleicher Name gleiches Kuerzel' (-not (@($m.ByUser | ForEach-Object Name) -match 'anna|bernd|clara') -and (@($m.ByUser | ForEach-Object Name) -match '^Benutzer-[0-9A-F]{12}$').Count -eq 3 -and (Get-SmPseudonym -Value 'ANNA' -Salt 'abc') -eq (Get-SmPseudonym -Value 'anna' -Salt 'abc') -and (Get-SmPseudonym -Value 'anna' -Salt 'abc') -ne (Get-SmPseudonym -Value 'anna' -Salt 'xyz'))
Check 'Pseudonyme: Originalereignisse bleiben unveraendert' ($events[0].User -eq 'anna')
$hk = New-SmPseudonymKey
$hk2 = New-SmPseudonymKey
Check 'Pseudonymschluessel: 64 Hexzeichen (32 Byte), zufaellig (zwei Aufrufe verschieden)' ($hk -match '^[0-9A-F]{64}$' -and $hk2 -match '^[0-9A-F]{64}$' -and $hk -ne $hk2)
$hm = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($hk))
$hx = -join ($hm.ComputeHash([Text.Encoding]::UTF8.GetBytes('anna')) | ForEach-Object { $_.ToString('X2') })
Check 'Pseudonym: HMAC-SHA256 ueber den kleingeschriebenen Namen, 12 Hexzeichen, Praefix' ((Get-SmPseudonym -Value 'ANNA' -Key $hk) -eq ('Benutzer-' + $hx.Substring(0, 12)) -and (Get-SmPseudonym -Value 'anna' -Key $hk -Prefix 'Rechner') -eq ('Rechner-' + $hx.Substring(0, 12)))
Check 'Pseudonym: anderer Schluessel anderes Kuerzel, ohne Schluessel nicht aus dem Namen ableitbar (kein einfaches SHA256 mit Salt)' ((Get-SmPseudonym -Value 'anna' -Key $hk) -ne (Get-SmPseudonym -Value 'anna' -Key $hk2) -and (Get-SmPseudonym -Value 'anna' -Key $hk) -ne ('Benutzer-' + (-join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($hk + '|anna')) | ForEach-Object { $_.ToString('X2') })).Substring(0, 12)))
$dup = Merge-SmPrintEvents -Events ($events + $events)
Check 'Zusammenfuehren mehrerer Zugriffsdateien entfernt Doppelte' (@($dup).Count -eq 6)

# Ansichten und Export
$vw = Get-SmPrintView -View Benutzer -Usage $u
Check 'Ansicht Benutzer: deutsche Ueberschriften als Spalten' ((@($vw.Headers) -join '|') -eq 'Benutzer|Drucker (Anzahl)|Drucker|Auftraege|Seiten|Letzte Nutzung' -and @($vw.Rows).Count -eq 3 -and $vw.Rows[0].'Benutzer' -eq 'anna')
Check 'Ansicht Ungenutzt und Sofortbild liefern Zeilen' (@((Get-SmPrintView -View Ungenutzt -Usage $u).Rows).Count -eq 2 -and @((Get-SmPrintView -View Sofortbild -Sessions @([pscustomobject]@{ Client = 'PC1'; User = 'anna'; Opens = 2; PrintOpen = $true }) -MaskUsers -Salt 's').Rows)[0].'Benutzer' -match '^Benutzer-')
$dt = ConvertTo-SmDataTable -Rows $vw.Rows -Properties $vw.Headers -Headers $vw.Headers
Check 'DataTable fuer die Anzeige: Spalten und Zeilen' ($dt.Columns.Count -eq 6 -and $dt.Rows.Count -eq 3)
Check 'Export ohne Export-SmTable: klare Meldung' (ThrowsLike { Invoke-SmPrintExportTable -Rows $vw.Rows -Path (Join-Path $Work 'x.csv') } 'SmExport')
$script:exported = $null
function Export-SmTable { param([object[]]$Rows, [string]$Path) $script:exported = @{ Rows = $Rows; Path = $Path } }
Invoke-SmPrintExportTable -Rows $vw.Rows -Path (Join-Path $Work 'auswertung.xlsx')
Check 'Export ruft Export-SmTable mit Zeilen und Pfad (Endung entscheidet dort)' ($script:exported.Rows.Count -eq 3 -and $script:exported.Path -like '*auswertung.xlsx')
Remove-Item Function:\Export-SmTable

# ---------------------------------------------------------------- 4. Vergleich
$cmp = Compare-SmPrintInventory -Old $invOld -New $invNew
function Row($area, $name) { $cmp | Where-Object { $_.Area -eq $area -and $_.Name -eq $name } }
Check 'Vergleich Drucker: gleich, abweichend (Treiber und Freigabe), nur alt, nur neu' ((Row 'Drucker' 'HP-Buero-1').Status -eq 'gleich' -and (Row 'Drucker' 'Kyocera-Flur').Status -eq 'abweichend' -and (Row 'Drucker' 'Kyocera-Flur').Detail -match 'DriverName' -and (Row 'Drucker' 'Kyocera-Flur').Detail -match 'Shared' -and (Row 'Drucker' 'Epson-Lager').Status -eq 'nur alt' -and (Row 'Drucker' 'Neu-Test').Status -eq 'nur neu')
Check 'Vergleich Treiber: je Architektur, x86 fehlt, Version/Typ abweichend' ((Row 'Treiber' 'HP Universal (x64)').Status -eq 'gleich' -and (Row 'Treiber' 'HP Universal (x86)').Status -eq 'nur alt' -and (Row 'Treiber' 'Kyocera KX (x64)').Status -eq 'abweichend' -and (Row 'Treiber' 'Kyocera KX (x64)').Detail -match 'DriverType')
Check 'Vergleich Ports: gleich und nur alt' ((Row 'Ports' 'IP_10.0.0.5').Status -eq 'gleich' -and (Row 'Ports' 'IP_10.0.0.6').Status -eq 'nur alt')
Check 'Vergleich Freigaben: Kyocera-Flur fehlt (nicht mehr freigegeben), Neu-Test nur neu' ((Row 'Freigaben' 'Kyocera-Flur').Status -eq 'nur alt' -and (Row 'Freigaben' 'Neu-Test').Status -eq 'nur neu' -and (Row 'Freigaben' 'HP-Buero-1').Status -eq 'gleich')
Check 'Vergleich: gleiche Namen mit anderer Gross/Kleinschreibung sind gleich' (@(Compare-SmPrintInventory -Old ([pscustomobject]@{ Printers = @($invOld.Printers[0]); Drivers = @(); Ports = @() }) -New ([pscustomobject]@{ Printers = @([pscustomobject]@{ Name = 'hp-buero-1'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = 'HP-Buero-1'; Shared = $true; Published = $true; Location = 'Haus A'; Comment = ''; Type = 'Local' }); Drivers = @(); Ports = @() }) | Where-Object Area -eq 'Drucker')[0].Status -eq 'gleich')
Check 'Vergleich identisch: keine Abweichung' (@(Compare-SmPrintInventory -Old $invOld -New $invOld | Where-Object Status -ne 'gleich').Count -eq 0)
Check 'Zusammenfassung nennt alle vier Bereiche' ((Get-SmPrintCompareSummary -Rows $cmp) -match 'Drucker: 1 gleich, 1 abweichend, 2 nur alt, 1 nur neu' -and (Get-SmPrintCompareSummary -Rows $cmp) -match 'Freigaben')

# ---------------------------------------------------------------- 5. Dateien lesen (feindlich)
$accFile = Join-Path $pw 'acc.json'
$acc = New-SmPrintAccessFile -Computer 'PS-ALT' -Events $events -Snapshot ([ordered]@{ Taken = '2026-11-10T09:00:00Z'; SmbSessions = @([ordered]@{ Client = 'PC-ANNA'; User = 'anna'; Opens = 3; PrintOpen = $true }); OpenFiles = @(); SpoolerConnections = $null; Notes = @() }) -RequestedFrom $t0
Write-SmPrintJson -Data $acc -Path $accFile
$racc = Read-SmPrintAccess -Path $accFile
Check 'Zugriffsdatei: Rundlauf (Ereignisse, Sitzungen, Computer)' (@($racc.Events).Count -eq 6 -and $racc.Computer -eq 'PS-ALT' -and @($racc.Sessions).Count -eq 1 -and $racc.Sessions[0].PrintOpen -eq $true -and $racc.Events[0].Time -eq $t0)
Check 'Zugriffsdatei: Ausgabe der Auswertung gleich wie aus den Originalereignissen' ((Get-SmPrintUsage -Events $racc.Events -Inventory $invOld).ByPrinter.Count -eq $u.ByPrinter.Count)
$invFile = Join-Path $pw 'inv.json'
Write-SmPrintJson -Data (New-SmPrintInventory -Computer 'PS-ALT' -Role 'alt' -Printers @([ordered]@{ Name = 'HP-Buero-1'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = 'HP'; Shared = $true; Published = $true; Location = 'Haus A'; Comment = 'x'; Type = 'Local' }) -Drivers @([ordered]@{ Name = 'HP Universal'; Version = '7.0.1.1'; Architecture = 'x64'; DriverType = 3; Manufacturer = 'HP' }) -Ports @([ordered]@{ Name = 'IP_10.0.0.5'; Description = ''; Address = '10.0.0.5'; PortNumber = 9100 })) -Path $invFile
$rinv = Read-SmPrintInventory -Path $invFile
Check 'Inventurdatei: Rundlauf' (@($rinv.Printers).Count -eq 1 -and $rinv.Printers[0].Shared -eq $true -and $rinv.Drivers[0].DriverType -eq 3 -and $rinv.Ports[0].PortNumber -eq 9100 -and $rinv.Role -eq 'alt')
Check 'Datei zu gross: abgelehnt (Groessenlimit)' (ThrowsLike { Read-SmPrintJson -Path $invFile -MaxBytes 100 } 'zu gross')
Check 'Falscher Typ: Zugriffsdatei als Inventur abgelehnt und umgekehrt' ((Throws { Read-SmPrintInventory -Path $accFile }) -and (Throws { Read-SmPrintAccess -Path $invFile }))
$bad = Join-Path $pw 'bad.json'; [IO.File]::WriteAllText($bad, '{ das ist kein json')
Check 'Kaputtes JSON: Fehler statt Absturz' (ThrowsLike { Read-SmPrintInventory -Path $bad } 'JSON')
$wrongSchema = Join-Path $pw 'schema.json'; [IO.File]::WriteAllText($wrongSchema, '{"Schema":99,"Kind":"PrintInventory","Printers":[]}')
Check 'Unbekannte Schemaversion abgelehnt' (ThrowsLike { Read-SmPrintInventory -Path $wrongSchema } 'Schema')
$hostile = Join-Path $pw 'hostile.json'
[IO.File]::WriteAllText($hostile, ('{"Schema":1,"Kind":"PrintInventory","Computer":"' + ('C' * 500) + '","Printers":["text",5,null,{"Name":"=HYPERLINK(\"http://x\")","DriverName":{"a":1},"Shared":"true","Location":"Zeile1\u0007Zeile2"},{"Name":""}],"Drivers":"keine Liste","Ports":{"Name":"P1"}}'))
$h = Read-SmPrintInventory -Path $hostile
Check 'Feindliche Inventur: Nicht-Objekte uebersprungen, Namenlose verworfen, Texte gekuerzt, Steuerzeichen raus' (@($h.Printers).Count -eq 1 -and $h.Computer.Length -eq 64 -and $h.Printers[0].Location -notmatch '[\x00-\x1F]' -and $h.Printers[0].Shared -eq $true -and @($h.Drivers).Count -eq 0 -and @($h.Ports).Count -eq 1)
$deep = Join-Path $pw 'deep.json'; [IO.File]::WriteAllText($deep, (('[' * 60) + (']' * 60)))
Check 'Zu tief verschachteltes JSON abgelehnt' (Throws { Read-SmPrintInventory -Path $deep })

# ---------------------------------------------------------------- 6. Server: Sicherungsordner (Haertung mit Protect-SmDnsStateDir aus server\SmDnsServer.ps1)
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:SmDnsStateSidsOverride = @($me, 'S-1-5-18')   # Test ohne Adminrechte: der aktuelle Benutzer ersetzt "Administratoren"
$script:SmPrintDataRoot = Join-Path $Work 'ProgramData-Neu'
$made = Initialize-SmPrintFolder
Check 'Anlegen: Ordner und Ueberordner entstehen, beide gehaertet und geprueft (kein eigener ACL-Code)' ((Test-Path $made) -and $made -eq (Join-Path $script:SmPrintDataRoot 'Print') -and -not @(Test-SmDnsStateDirAcl -Path $made).Count -and -not @(Test-SmDnsStateDirAcl -Path $script:SmPrintDataRoot).Count)
Check 'Sicherungsordner gehaertet: Assert ok' (-not (Throws { Assert-SmSecureFolder -Path $made }))
$acl = Get-Acl -LiteralPath $made
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'Read', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))); (New-Object IO.DirectoryInfo $made).SetAccessControl($acl)
Check 'Zusaetzlicher Benutzer-Zugriff (Users): Pruefung bricht ab' (ThrowsLike { Assert-SmSecureFolder -Path $made } 'nicht sicher')
$acl.RemoveAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'Read', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) | Out-Null; (New-Object IO.DirectoryInfo $made).SetAccessControl($acl)
Check 'Nach Entfernen des Eintrags ist der Ordner wieder in Ordnung' (-not (Throws { Assert-SmSecureFolder -Path $made }))
Check 'Sicherungsordner fehlt: Abbruch' (ThrowsLike { Assert-SmSecureFolder -Path (Join-Path $Work 'gibt-es-nicht') } 'fehlt')
$real = Join-Path $Work 'real-ordner'; $lroot = Join-Path $Work 'link-root'
New-Item -ItemType Directory -Force $real, $lroot | Out-Null
$linkOk = $false; try { New-Item -ItemType Junction -Path (Join-Path $lroot 'Print') -Target $real | Out-Null; $linkOk = $true } catch { }
if ($linkOk) {
    $script:SmPrintDataRoot = $lroot
    Check 'Sicherungsordner als Junction: Abbruch' (ThrowsLike { Initialize-SmPrintFolder } 'Verknuepfung')
    (Get-Item (Join-Path $lroot 'Print') -Force).Delete()
}
$script:SmPrintDataRoot = Join-Path $Work 'ProgramData-Neu'
# Ab hier ersetzt ein Stub die Haertung (Protect-SmDnsStateDir braucht ohne Adminrechte SeSecurityPrivilege, sobald der Ordner schon gehaertet ist); es wird nur geprueft, dass sie aufgerufen wird.
$script:protected = @()
function Protect-SmDnsStateDir { param($Path) $script:protected += $Path; if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Force $Path | Out-Null } }
[void](Initialize-SmPrintFolder)
Check 'Initialize ruft die Haertung fuer Ueberordner und Print bei jeder Nutzung auf' ($script:protected.Count -eq 2 -and $script:protected[0] -eq $script:SmPrintDataRoot -and $script:protected[1] -eq $made)
Check 'Dateiname: Pfad ausserhalb und Sonderzeichen abgelehnt' ((Throws { Resolve-SmPrintFile -Folder $made -Name '..\x.json' }) -and (Throws { Resolve-SmPrintFile -Folder $made -Name 'a b.json' }) -and (Throws { Resolve-SmPrintFile -Folder $made -Name 'x.exe' -Pattern $script:SmPrintExportPattern }) -and ((Resolve-SmPrintFile -Folder $made -Name 'ok-1.json') -eq [IO.Path]::GetFullPath((Join-Path $made 'ok-1.json'))))

# ---------------------------------------------------------------- 7. Server: Stubs und gemockte Cmdlets
# Ab hier: Sicherung immer als "gehaertet" behandeln (die ACL-Pruefung ist oben einzeln getestet), Administrator und Rolle simuliert.
$script:adminOk = $true; $script:roleOk = $true; $script:freeBytes = 100GB
function Test-SmAdmin { $script:adminOk }
function Get-SmPrintRoleInstalled { $script:roleOk }
function Get-SmFreeBytes { param($Path) $script:freeBytes }
function Get-Service { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = 'Spooler'; Status = 'Running' } }
$script:printers = @()
$script:unshared = @()
function Get-Printer { [CmdletBinding()] param() $script:printers }
function Set-Printer { [CmdletBinding()] param($Name, $Shared) $script:unshared += $Name }
function Get-PrinterDriver { [CmdletBinding()] param() @([pscustomobject]@{ Name = 'HP Universal'; DriverVersion = [uint64]0x000700000001615B; PrinterEnvironment = 'Windows x64'; MajorVersion = 3; Manufacturer = 'HP' }, [pscustomobject]@{ Name = 'MS Class'; DriverVersion = [uint64]0x000A000000000001; PrinterEnvironment = 'Windows NT x86'; MajorVersion = 4; Manufacturer = 'Microsoft' }) }
function Get-PrinterPort { [CmdletBinding()] param() @([pscustomobject]@{ Name = 'IP_10.0.0.5'; Description = 'Standard TCP/IP Port'; PrinterHostAddress = '10.0.0.5'; PortNumber = 9100 }) }
function New-Pr([string]$n, [bool]$shared = $true) { [pscustomobject]@{ Name = $n; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.5'; ShareName = $n; Shared = $shared; Published = $true; Location = 'Haus A'; Comment = 'Testdrucker'; Type = 'Local' } }
$script:printers = @((New-Pr 'HP-Buero-1'), (New-Pr 'Kyocera-Flur'))

$stubDir = Join-Path $Work 'stubs'; New-Item -ItemType Directory -Force $stubDir | Out-Null
$brm = Join-Path $stubDir 'PrintBrm.cmd'
[IO.File]::WriteAllText($brm, "@echo off`r`necho %* > `"%SM_STUB_LOG%`"`r`nif `"%SM_STUB_EXIT%`"==`"`" set SM_STUB_EXIT=0`r`nif `"%1`"==`"-B`" echo stub-export> %3`r`nif `"%1`"==`"-Q`" if exist `"%SM_STUB_Q%`" type `"%SM_STUB_Q%`"`r`nexit /b %SM_STUB_EXIT%`r`n")
$script:SmPrintBrmPath = $brm
$env:SM_STUB_LOG = Join-Path $stubDir 'brm-args.txt'; $env:SM_STUB_EXIT = '0'

# Vorpruefungen
$pre = Test-SmPrintPrecheck -Mode Export
Check 'Vorpruefung Export: Administrator, Rolle, PrintBrm vorhanden -> ok' ($pre.Ok -and @($pre.Checks).Count -eq 3)
$script:adminOk = $false
Check 'Vorpruefung: kein Administrator blockiert' (-not (Test-SmPrintPrecheck -Mode Export).Ok -and (Format-SmPrecheck (Test-SmPrintPrecheck -Mode Export)) -match 'FEHLER')
$script:adminOk = $true; $script:roleOk = $false
Check 'Vorpruefung: Rolle Druckserver fehlt blockiert' (-not (Test-SmPrintPrecheck -Mode Export).Ok)
$script:roleOk = $true
$script:SmPrintBrmPath = Join-Path $stubDir 'nicht-da.exe'
Check 'Vorpruefung: PrintBrm.exe fehlt blockiert' (-not (Test-SmPrintPrecheck -Mode Export).Ok)
$script:SmPrintBrmPath = $brm
Check 'Standardpfad von PrintBrm unter %windir%\System32\spool\tools' ((& { $script:SmPrintBrmPath = $null; Get-SmPrintBrmPath }) -eq (Join-Path ([Environment]::GetFolderPath('System')) 'spool\tools\PrintBrm.exe'))
$script:SmPrintBrmPath = $brm
Check 'Vorpruefung Protokoll braucht nur Administrator' ((Test-SmPrintPrecheck -Mode Log).Ok -and @((Test-SmPrintPrecheck -Mode Log).Checks).Count -eq 1)

# Export
Check 'Export ohne Bestaetigung: abgelehnt' (ThrowsLike { Invoke-SmPrintExport } 'nicht bestaetigt')
$ex = Invoke-SmPrintExport -Confirmed
$brmArgs = (Get-Content -LiteralPath $env:SM_STUB_LOG -Raw).Trim()
Check 'Export: PrintBrm -B -F <Datei im Sicherungsordner>' ($brmArgs -match '^-B -F "?[^"]+\.printerExport"?$' -and $brmArgs.Contains([IO.Path]::GetFullPath($made)))
Check 'Export: Datei, SHA256 und Groesse' ((Test-Path $ex.Export.Path) -and $ex.Export.Sha256 -eq (Get-FileHash $ex.Export.Path -Algorithm SHA256).Hash -and $ex.Export.Name -match '^Print-Export-[A-Za-z0-9\-]+-\d{8}-\d{6}-[0-9a-f]{12}\.printerExport$')
Check 'Export: PrintBrm schreibt in einen frischen Unterordner Export-<GUID> (nicht in den Sicherungsordner), danach verschoben ohne Ueberschreiben, Unterordner weg' ($brmArgs -match '\Export-[0-9a-f]{32}\Print-Export-' -and @(Get-ChildItem -LiteralPath $made -Directory -Filter 'Export-*').Count -eq 0 -and (Split-Path -Parent $ex.Export.Path) -eq [IO.Path]::GetFullPath($made).TrimEnd('\') -and @(Test-SmSecureFile -Path $ex.Export.Path).Count -eq 0)
$env:SM_STUB_EXIT = '5'
Check 'Export: PrintBrm-Fehler -> Abbruch, kein Export-<GUID>-Ordner bleibt liegen' ((Throws { Invoke-SmPrintExport -Confirmed }) -and @(Get-ChildItem -LiteralPath $made -Directory -Filter 'Export-*').Count -eq 0)
$env:SM_STUB_EXIT = '0'
$invJson = Get-Content -LiteralPath $ex.Inventory.Path -Raw | ConvertFrom-Json
Check 'Inventur: Drucker mit Freigabe, Veroeffentlichung, Standort, Kommentar' (@($invJson.Printers).Count -eq 2 -and $invJson.Printers[0].ShareName -eq 'HP-Buero-1' -and $invJson.Printers[0].Published -eq $true -and $invJson.Printers[0].Location -eq 'Haus A' -and $invJson.Printers[0].Comment -eq 'Testdrucker' -and $invJson.Role -eq 'alt')
Check 'Inventur: Treiber mit Version, Architektur x64/x86 und Typ 3/4' ($invJson.Drivers[0].Version -eq '7.0.1.24923' -and $invJson.Drivers[0].Architecture -eq 'x64' -and $invJson.Drivers[0].DriverType -eq 3 -and $invJson.Drivers[1].Architecture -eq 'x86' -and $invJson.Drivers[1].DriverType -eq 4)
Check 'Inventur: Ports mit Adresse' ($invJson.Ports[0].Address -eq '10.0.0.5' -and $invJson.Ports[0].PortNumber -eq 9100)
Check 'Inventur: von Berater-Tool lesbar (Rundlauf)' ((Read-SmPrintInventory -Path $ex.Inventory.Path).Printers.Count -eq 2)
$auditText = Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw
Check 'Protokoll: Export gestartet und fertig, mit SHA256, ohne Geheimnisse' ($auditText -match 'Export gestartet' -and $auditText -match ('Export fertig.*' + $ex.Export.Sha256) -and $auditText -notmatch '(?i)password|kennwort=|https://')
$env:SM_STUB_EXIT = '1'
Check 'Export: Exitcode ungleich 0 bricht ab und wird protokolliert' (ThrowsLike { Invoke-SmPrintExport -Confirmed } 'Exitcode 1')
Check 'Protokoll: Fehlschlag ohne Dateiinhalt' ((Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw) -match 'Export fehlgeschlagen: .*Exitcode 1')
$env:SM_STUB_EXIT = '0'
$script:roleOk = $false
Check 'Export: Vorpruefung nicht bestanden bricht vor PrintBrm ab' ((ThrowsLike { Invoke-SmPrintExport -Confirmed } 'Vorpruefung') -and -not (Test-Path (Join-Path $stubDir 'neu.txt')))
$script:roleOk = $true

# Download aus dem Tauschordner (Funktionen des Tauschordners ersetzt)
$script:remote = @([pscustomobject]@{ Name = 'Print-Export-PS-ALT-20261110-091500.printerExport'; Length = 12L })
function Get-SmShareFiles { param($Share) $script:remote }
$script:lastMax = $null
function Receive-SmShareFile { param($Share, $Name, $OutFile, $MaxBytes) $script:lastMax = $MaxBytes; [IO.File]::WriteAllBytes($OutFile, [byte[]](1..12)) }
$preOld = Join-Path $made 'Print-Export-PS-ALT-20261110-091500.printerExport'
[IO.File]::WriteAllBytes($preOld, [byte[]](99, 99, 99))   # aeltere Datei im Ordner
$dl = Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport'
Check 'Download: Receive-SmShareFile bekommt -MaxBytes (Export 8 GB)' ($script:lastMax -eq 8GB)
Check 'Download: aeltere Datei im Ordner wird nicht verwendet, sondern ersetzt (frischer Inhalt)' ((Get-Item -LiteralPath $dl.Path).Length -eq 12)
[void](Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport' -MaxBytes 64MB)
Check 'Download: -MaxBytes wird weitergegeben (Inventur 64 MB)' ($script:lastMax -eq 64MB)
Check 'Vertrauenspruefung: Datei vom Administrator-Besitzer ok, anderer Besitzer und fehlende Datei nicht' ((Test-SmPrintTrustedFile -Path $dl.Path) -and -not (Test-SmPrintTrustedFile -Path (Join-Path $made 'gibt-es-nicht.json')) -and -not (& { $o = $script:SmDnsStateSidsOverride; $script:SmDnsStateSidsOverride = @('S-1-5-18'); try { Test-SmPrintTrustedFile -Path $dl.Path } finally { $script:SmDnsStateSidsOverride = $o } }))
Check 'Download: Datei im Sicherungsordner, SHA256 berechnet, Protokollzeile' ((Test-Path $dl.Path) -and $dl.Sha256 -eq (Get-FileHash $dl.Path -Algorithm SHA256).Hash -and $dl.Log[0] -match 'Heruntergeladen')
Check 'Download: Name ausserhalb der Whitelist abgelehnt' ((Throws { Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name '..\boese.printerExport' }) -and (Throws { Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'datei.exe' }))
Check 'Download: Groessenlimit' (ThrowsLike { Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport' -MaxBytes 5 } 'zu gross')
$script:remote = @([pscustomobject]@{ Name = 'Print-Export-PS-ALT-20261110-091500.printerExport'; Length = 99L })
Check 'Download: unvollstaendige Datei wird erkannt' (ThrowsLike { Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport' } 'unvollstaendig')
$script:freeBytes = 1MB
Check 'Download: zu wenig Platz' (ThrowsLike { Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport' } 'Platz')
$script:freeBytes = 100GB
$script:remote = @([pscustomobject]@{ Name = 'Print-Export-PS-ALT-20261110-091500.printerExport'; Length = 12L })
$dl = Receive-SmPrintShareFile -Share ([pscustomobject]@{}) -Name 'Print-Export-PS-ALT-20261110-091500.printerExport'   # frisch (ein fehlgeschlagener Download loescht die alte Datei)
$impName = Split-Path -Leaf $dl.Path
$invSha = 'ABCDEF0123456789' * 4

# Import: SHA256 vollstaendig eingeben, gleiche Bytes hashen und importieren
Check 'SHA256 normalisieren: Leerzeichen, Kleinschreibung, nur 64 Hexzeichen' ((ConvertTo-SmShaNormal ('  ' + $dl.Sha256.ToLower().Insert(8, ' ') + ' ')) -eq $dl.Sha256 -and (Throws { ConvertTo-SmShaNormal 'abcd' }) -and (Throws { ConvertTo-SmShaNormal ('G' * 64) }) -and (Throws { ConvertTo-SmShaNormal '' }))
Check 'SHA256 vergleichen: vollstaendig, nicht nur Anfang; falsche und leere Eingabe: kein Treffer' ((Test-SmShaMatch -Entered $dl.Sha256.ToLower() -Actual $dl.Sha256) -and -not (Test-SmShaMatch -Entered $dl.Sha256.Substring(0, 60) -Actual $dl.Sha256) -and -not (Test-SmShaMatch -Entered ('0' * 64) -Actual $dl.Sha256) -and -not (Test-SmShaMatch -Entered '' -Actual $dl.Sha256))
$cp = Join-Path $Work 'cp.bin'
Check 'Kopieren mit Hash: SHA256 der geschriebenen Bytes gleich Get-FileHash' ((Copy-SmPrintHashed -Source $dl.Path -Dest $cp) -eq (Get-FileHash $cp -Algorithm SHA256).Hash -and (Get-FileHash $cp).Hash -eq (Get-FileHash $dl.Path).Hash)
$tempHome = Join-Path $Work 'tmp'; New-Item -ItemType Directory -Force $tempHome | Out-Null
$oldTemp = $env:TEMP; $env:TEMP = $tempHome
function Count-Tmp { @(Get-ChildItem -LiteralPath $made -Directory -Filter 'Import-*').Count }
function Count-OldTmp { @(Get-ChildItem -LiteralPath $tempHome -Directory -Filter 'ServerMigration-print-*').Count }
$fremd = Join-Path $tempHome 'wichtig'; New-Item -ItemType Directory -Force $fremd | Out-Null
$fremd = Join-Path $made 'wichtig'; New-Item -ItemType Directory -Force $fremd | Out-Null
Remove-SmPrintWork $fremd
Check 'Aufraeumen: Verzeichnis mit anderem Namen wird nicht geloescht' (Test-Path $fremd)
Remove-Item -LiteralPath $fremd -Recurse -Force
New-Item -ItemType Directory -Force (Join-Path $Work ('Import-' + ('a' * 32))) | Out-Null
Remove-SmPrintWork (Join-Path $Work ('Import-' + ('a' * 32)))
Check 'Aufraeumen: richtiger Name ausserhalb des Sicherungsordners wird nicht geloescht' (Test-Path (Join-Path $Work ('Import-' + ('a' * 32))))
# Beenden und Start: Arbeitsverzeichnis der Sitzung weg, verwaiste (aelter als 24 h, eigener Name und Besitzer) weg
$sess = Join-Path $made ('Import-' + ('d' * 32)); New-Item -ItemType Directory -Force $sess | Out-Null
$script:SmPS = @{ Plan = [pscustomobject]@{ WorkRoot = $sess } }
Close-SmPrintPage
$closeErr = $false; try { $script:SmPS = $null; Close-SmPrintPage } catch { $closeErr = $true }
Check 'Fenster schliessen: Arbeitsverzeichnis des Imports geloescht, ohne Sitzung kein Fehler' (-not (Test-Path $sess) -and -not $closeErr)
$orA = Join-Path $made ('Import-' + ('1' * 32)); $orB = Join-Path $made ('Import-' + ('2' * 32)); $orC = Join-Path $made 'Import-fremd'
foreach ($d in $orA, $orB, $orC) { New-Item -ItemType Directory -Force $d | Out-Null }
(Get-Item $orA).LastWriteTime = (Get-Date).AddHours(-30); (Get-Item $orC).LastWriteTime = (Get-Date).AddHours(-30)
$nPr = Clear-SmPrintOrphans
Check 'Start: verwaistes Import-Verzeichnis (aelter als 24 h) geloescht, neues und fremd benanntes bleiben' ($nPr -eq 1 -and -not (Test-Path $orA) -and (Test-Path $orB) -and (Test-Path $orC))
Remove-Item -LiteralPath $orB, $orC -Recurse -Force
$tmpD = Join-Path $Work 'dnstemp'; New-Item -ItemType Directory -Force $tmpD | Out-Null
$dA = Join-Path $tmpD ('ServerMigration-dns-' + ('3' * 32)); $dB = Join-Path $tmpD 'Eigene-Daten'
foreach ($d in $dA, $dB) { New-Item -ItemType Directory -Force $d | Out-Null; (Get-Item $d).LastWriteTime = (Get-Date).AddHours(-30) }
Check 'Start: verwaister DNS-Temp-Ordner geloescht, fremder Ordner bleibt' ((Clear-SmDnsOrphans -TempRoot $tmpD) -eq 1 -and -not (Test-Path $dA) -and (Test-Path $dB))
$qfile = Join-Path $stubDir 'q-out.txt'
[IO.File]::WriteAllText($qfile, "Printer: HP-Buero-1`r`nPrinter: Kyocera-Flur`r`nDriver: HP Universal`r`nPort: IP_10.0.0.5`r`n")
$env:SM_STUB_Q = $qfile
$invOk = [pscustomobject]@{ Printers = @([pscustomobject]@{ Name = 'HP-Buero-1' }, [pscustomobject]@{ Name = 'Kyocera-Flur' }) }
$script:getCalls = 99
$wrong = Throws { Initialize-SmPrintImport -FileName $impName -ExpectedSha ('0' * 64) -OldInventory $invOk -ExpectedInvSha $invSha -InventorySha $invSha }
Check 'Falsche SHA256: Abbruch, kein Arbeitsverzeichnis bleibt liegen, Fehler im Protokoll' ($wrong -and (Count-Tmp) -eq 0 -and (Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw) -match 'Import \(Vorbereitung\) fehlgeschlagen: .*SHA256 stimmt nicht')
Check 'Unvollstaendige SHA256: Abbruch vor dem Kopieren' ((Throws { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256.Substring(0, 40) -OldInventory $invOk -ExpectedInvSha $invSha -InventorySha $invSha }) -and (Count-Tmp) -eq 0)
$plan = Initialize-SmPrintImport -FileName $impName -ExpectedSha ($dl.Sha256.ToLower().Insert(10, ' ')) -OldInventory $invOk -ExpectedInvSha $invSha -InventorySha $invSha
Check 'Plan: Arbeitskopie im gehaerteten Ordner (Import-<GUID> unter Print), nie in %TEMP%, dieselben Bytes (SHA256)' ($plan.Ok -and (Count-Tmp) -eq 1 -and (Count-OldTmp) -eq 0 -and $plan.WorkRoot -match 'Import-[0-9a-f]{32}$' -and (Split-Path -Parent $plan.WorkRoot) -eq $made -and (Get-FileHash $plan.WorkFile -Algorithm SHA256).Hash -eq $dl.Sha256 -and $plan.WorkFile.StartsWith($made) -and -not $plan.WorkFile.StartsWith($tempHome) -and $plan.Sha256 -eq $dl.Sha256)
Check 'Plan: Arbeitsverzeichnis keine Verknuepfung, Zugriffsliste geprueft (nur Administratoren und SYSTEM)' (-not ((Get-Item -LiteralPath $plan.WorkRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -and -not @(Test-SmDnsStateDirAcl -Path $plan.WorkRoot).Count)
Check 'Plan: Inhalt aus der Exportdatei (PrintBrm -Q) und Abgleich mit der Inventur ohne Abweichung' ($plan.Lines.Count -eq 4 -and $plan.Lines[0] -eq 'Printer: HP-Buero-1' -and $plan.Missing.Count -eq 0 -and $plan.HasInventory -and ((Get-Content -LiteralPath $env:SM_STUB_LOG -Raw) -match '^-Q -F '))
$ct = Format-SmPrintImportConfirm -Plan $plan -Shares $true -Publish $false -Force $true
Check 'Bestaetigungstext zeigt den Inhalt der Exportdatei, die Optionen und die Pruefsumme-Kurzform' ($ct -match 'Printer: Kyocera-Flur' -and $ct -match 'Driver: HP Universal' -and $ct -match 'JA \(Namensgleiche' -and $ct -match 'Druckernamen der Inventur' -and $ct -match 'nicht verglichen' -and $ct -notmatch 'stimmen .berein' -and $ct.Contains($plan.Sha256.Substring(0, 12)))
Check 'Import ohne Bestaetigung: abgelehnt, Arbeitskopie wird aufgeraeumt' ((ThrowsLike { Invoke-SmPrintImport -Plan $plan } 'nicht bestaetigt') -and (Count-Tmp) -eq 0)
Remove-SmPrintWork $plan.WorkRoot
Check 'Abbruch durch den Benutzer: Arbeitsverzeichnis geloescht' ((Count-Tmp) -eq 0)
$invBad = [pscustomobject]@{ Printers = @([pscustomobject]@{ Name = 'HP-Buero-1' }, [pscustomobject]@{ Name = 'Epson-Lager' }) }
$planBad = Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invBad -ExpectedInvSha $invSha -InventorySha $invSha
Check 'Inventur und Export weichen ab (Epson-Lager fehlt im Export): Plan nicht ok, kein Import moeglich' (-not $planBad.Ok -and $planBad.Missing -contains 'Epson-Lager' -and ($planBad.Problems -join ' ') -match 'weichen ab' -and (ThrowsLike { Invoke-SmPrintImport -Plan $planBad -Confirmed } 'nicht vorbereitet'))
Remove-SmPrintWork $planBad.WorkRoot
$env:SM_STUB_EXIT = '1'
$planQ = Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -ExpectedInvSha $invSha -InventorySha $invSha
Check 'Inhalt der Exportdatei nicht lesbar (PrintBrm -Q scheitert): nicht ok' (-not $planQ.Ok -and ($planQ.Problems -join ' ') -match 'nicht lesbar')
Remove-SmPrintWork $planQ.WorkRoot
$env:SM_STUB_EXIT = '0'
$planNoInv = Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256
Check 'Ohne Inventur: Inhalt wird gezeigt, Hinweis "keine Inventur zum Abgleich"' ($planNoInv.Ok -and -not $planNoInv.HasInventory -and (Format-SmPrintImportConfirm -Plan $planNoInv -Shares $true -Publish $false -Force $false) -match 'Keine Inventur')
Remove-SmPrintWork $planNoInv.WorkRoot

function New-Plan { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -ExpectedInvSha $invSha -InventorySha $invSha }
Check 'Inventur-SHA256 falsch, unvollstaendig oder leer: Abbruch vor dem Kopieren, nichts liegt herum' ((ThrowsLike { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -ExpectedInvSha ('0' * 64) -InventorySha $invSha } 'Inventur stimmt nicht') -and (Throws { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -ExpectedInvSha $invSha.Substring(0, 40) -InventorySha $invSha }) -and (Throws { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -InventorySha $invSha }) -and (Count-Tmp) -eq 0)
Check 'Inventur-SHA256 mit Gross-/Kleinschreibung und Leerzeichen eingefuegt: wird akzeptiert' ((& { $pi = Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 -OldInventory $invOk -ExpectedInvSha ($invSha.ToLower().Insert(5, ' ')) -InventorySha $invSha; $o = $pi.Ok; Remove-SmPrintWork $pi.WorkRoot; $o }))
$script:SmDnsStateSidsOverride = @('S-1-5-18')
Check 'Exportdatei gehoert keinem Administrator (aelter, von einem Nicht-Administrator): wird nicht verwendet' ((ThrowsLike { Initialize-SmPrintImport -FileName $impName -ExpectedSha $dl.Sha256 } 'Administrator') -and (Count-Tmp) -eq 0)
$script:SmDnsStateSidsOverride = @($me, 'S-1-5-18')
$p1 = New-Plan
Remove-Item -LiteralPath $env:SM_STUB_LOG -Force -ErrorAction SilentlyContinue
$imp1 = Invoke-SmPrintImport -Plan $p1 -Confirmed
$a1 = (Get-Content -LiteralPath $env:SM_STUB_LOG -Raw).Trim()
Check 'Import einfach: PrintBrm -R -F <Arbeitskopie in TEMP>, ohne FORCE und ohne -P' ($a1 -match '^-R -F "?[^"]+\.printerExport"?$' -and $a1.Contains($p1.WorkRoot) -and $a1 -notmatch 'FORCE|-P ' -and -not $a1.Contains($tempHome))
Check 'Import: Arbeitsverzeichnis danach geloescht' ((Count-Tmp) -eq 0 -and -not (Test-Path $p1.WorkFile))
$p2 = New-Plan
[void](Invoke-SmPrintImport -Plan $p2 -Confirmed -Force -Publish)
$a2 = (Get-Content -LiteralPath $env:SM_STUB_LOG -Raw).Trim()
Check 'Import mit Optionen: -O FORCE und -P ORIG (Veroeffentlichung wie vorher)' ($a2 -match '-R -F ' -and $a2 -match '-O FORCE' -and $a2 -match '-P ORIG')
$aud = Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw
Check 'Protokoll: Pruefsumme bestaetigt, Import gestartet mit SHA256 und Optionen, fertig' ($aud -match 'Pruefsumme bestaetigt, Arbeitskopie im gehaerteten Ordner erstellt' -and $aud -match 'Inventur-SHA256 [0-9A-F]{64} bestaetigt' -and $aud -match 'Import gestartet: PrintBrm -R -F Print-Export.*SHA256 [0-9A-F]{64}.*Freigaben uebernehmen' -and $aud -match 'Import fertig: Exitcode 0')
$pH = New-Plan
$origNative = (Get-Command Invoke-SmNative -CommandType Function).ScriptBlock
$script:probe = $null
function Invoke-SmNative {
    param($Path, $Arguments, $TimeoutSec)
    if ($Arguments[0] -eq '-R') {
        $wf = $Arguments[2]; $p = [ordered]@{}
        try { $s = [IO.File]::Open($wf, 'Open', 'Write', 'ReadWrite'); $s.Dispose(); $p.Write = $true } catch { $p.Write = $false }
        try { Remove-Item -LiteralPath $wf -Force -ErrorAction Stop; $p.Delete = $true } catch { $p.Delete = $false }
        try { [IO.File]::Move($wf, $wf + '.x'); $p.Rename = $true } catch { $p.Rename = $false }
        try { $s = [IO.File]::Open($wf, 'Open', 'Read', 'ReadWrite'); $s.Dispose(); $p.Read = $true } catch { $p.Read = $false }
        $script:probe = $p
        return [pscustomobject]@{ ExitCode = 0; Raw = ''; Error = '' }
    }
    & $origNative -Path $Path -Arguments $Arguments -TimeoutSec $TimeoutSec
}
[void](Invoke-SmPrintImport -Plan $pH -Confirmed)
Set-Item -Path function:Invoke-SmNative -Value $origNative
Check 'Waehrend PrintBrm -R laeuft: Arbeitskopie gegen Schreiben, Loeschen und Umbenennen gesperrt (Handle FileShare.Read), Lesen geht' ($script:probe -and -not $script:probe.Write -and -not $script:probe.Delete -and -not $script:probe.Rename -and $script:probe.Read)
Check 'Nach dem Import: Handle zu, Arbeitsverzeichnis weg' ((Count-Tmp) -eq 0)
$pJ = New-Plan
$bak = $pJ.WorkRoot + '-bak'
Rename-Item -LiteralPath $pJ.WorkRoot -NewName (Split-Path -Leaf $bak)
$jOk = $false; try { New-Item -ItemType Junction -Path $pJ.WorkRoot -Target $bak | Out-Null; $jOk = $true } catch { }
if ($jOk) {
    Remove-Item -LiteralPath $env:SM_STUB_LOG -Force -ErrorAction SilentlyContinue
    Check 'Arbeitsverzeichnis durch Verknuepfung ersetzt: Import abgelehnt, PrintBrm nicht gestartet' ((ThrowsLike { Invoke-SmPrintImport -Plan $pJ -Confirmed } 'Verknuepfung') -and -not (Test-Path -LiteralPath $env:SM_STUB_LOG))
    (Get-Item -LiteralPath $pJ.WorkRoot -Force).Delete()
}
Remove-Item -LiteralPath $bak -Recurse -Force
$pJ2 = New-Plan
Remove-Item -LiteralPath $pJ2.WorkFile -Force
Check 'Arbeitskopie fehlt: Import abgelehnt' (ThrowsLike { Invoke-SmPrintImport -Plan $pJ2 -Confirmed } 'fehlt')
$pO = New-Plan
$pO.WorkRoot = $tempHome; $pO.WorkFile = Join-Path $tempHome 'x.printerExport'
Check 'Arbeitskopie ausserhalb des Sicherungsordners (manipulierter Plan): Import abgelehnt' (ThrowsLike { Invoke-SmPrintImport -Plan $pO -Confirmed } 'nicht im Arbeitsverzeichnis')
Get-ChildItem -LiteralPath $made -Directory -Filter 'Import-*' | Remove-Item -Recurse -Force
$p3 = New-Plan
[IO.File]::AppendAllText($p3.WorkFile, 'manipuliert')
Check 'Arbeitskopie nach der Pruefung veraendert: Import abgelehnt, nichts gestartet, aufgeraeumt' ((ThrowsLike { Invoke-SmPrintImport -Plan $p3 -Confirmed } 'veraendert') -and (Count-Tmp) -eq 0)
$p4 = New-Plan
$env:SM_STUB_EXIT = '5'
Check 'Import: Exitcode 5 bricht ab, steht im Protokoll, Arbeitsverzeichnis weg' ((ThrowsLike { Invoke-SmPrintImport -Plan $p4 -Confirmed } 'Exitcode 5') -and (Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw) -match 'Import fehlgeschlagen: .*Exitcode 5' -and (Count-Tmp) -eq 0)
$env:SM_STUB_EXIT = '0'
$p5 = New-Plan
$script:adminOk = $false
Check 'Import als Nicht-Administrator: Vorpruefung blockiert, Fehler im Protokoll, aufgeraeumt' ((ThrowsLike { Invoke-SmPrintImport -Plan $p5 -Confirmed } 'Vorpruefung') -and (Get-Content -LiteralPath (Join-Path $made 'Protokoll.log') -Raw) -match 'Import fehlgeschlagen: Vorpruefung' -and (Count-Tmp) -eq 0)
$script:adminOk = $true
# Protokoll nicht beschreibbar: Warnung wird angezeigt, nicht verschluckt
$lock = [IO.File]::Open((Join-Path $made 'Protokoll.log'), 'Open', 'ReadWrite', 'None')
try {
    $ll = New-Object System.Collections.ArrayList
    Add-SmPrintAudit -Folder $made -Log $ll -Line 'Testzeile'
    Check 'Protokoll nicht beschreibbar: Zeile und WARNUNG stehen in der Anzeige-Liste' ($ll.Count -eq 2 -and $ll[1] -match '^WARNUNG: .*nicht geschrieben')
    $p6 = New-Plan   # Vorbereitung schreibt ebenfalls ins Protokoll: gelingt, aber mit Warnung in Log
    Check 'Vorbereitung bei gesperrtem Protokoll: Warnung im Log des Plans' (($p6.Log -join ' ') -match 'WARNUNG')
    Remove-SmPrintWork $p6.WorkRoot
    $p7 = New-Plan
    $env:SM_STUB_EXIT = '5'
    Check 'Fehler eines aendernden Schritts bei gesperrtem Protokoll: Meldung nennt die Warnung' (ThrowsLike { Invoke-SmPrintImport -Plan $p7 -Confirmed } 'WARNUNG')
    $env:SM_STUB_EXIT = '0'
}
finally { $lock.Dispose() }
$script:adminOk = $true
$env:TEMP = $oldTemp
$script:getCalls = 0

# Freigaben nicht uebernehmen: neu angelegte Drucker werden aus der Freigabe genommen, Bestehende bleiben
$env:TEMP = $tempHome
$script:printers = @((New-Pr 'Bestand-1'))
function Get-Printer { [CmdletBinding()] param() $script:getCalls++; if ($script:getCalls -le 1) { @((New-Pr 'Bestand-1'), (New-Pr 'HP-Buero-1')) } else { @((New-Pr 'Bestand-1'), (New-Pr 'HP-Buero-1'), (New-Pr 'Neu-A'), (New-Pr 'Neu-B' $false)) } }
$script:getCalls = 0; $script:unshared = @()
$pS = New-Plan
$script:getCalls = 0
$r2 = Invoke-SmPrintImport -Plan $pS -Confirmed -KeepShares $false
Check 'Freigaben nicht uebernehmen: nur durch diesen Import NEU angelegte Drucker (Vorher-Nachher), nie bestehende (HP-Buero-1 steht schon vorher da, auch in der Inventur)' ((@($script:unshared) -join ',') -eq 'Neu-A' -and ($r2.Log -join ' ') -match 'Freigaben entfernt.*1 neu angelegte Drucker, bestehende unveraendert')
$script:getCalls = 0; $script:unshared = @()
$pT = New-Plan
[void](Invoke-SmPrintImport -Plan $pT -Confirmed)
Check 'Freigaben uebernehmen: Set-Printer wird nicht aufgerufen' ($script:unshared.Count -eq 0)
$env:TEMP = $oldTemp
function Get-Printer { [CmdletBinding()] param() $script:printers }

# Inventur nach dem Import
$inv2 = New-SmPrintInventoryFile -Role 'neu' -Stage 'nachimport'
Check 'Inventur nach Import: Datei Print-Inventur-...-nachimport-... und Rolle neu' ($inv2.Name -match '^Print-Inventur-[A-Za-z0-9\-]+-nachimport-\d{8}-\d{6}-[0-9a-f]{12}\.json$' -and (Read-SmPrintInventory -Path $inv2.Path).Role -eq 'neu')

# ---------------------------------------------------------------- 8. Druckprotokoll (wevtutil-Stub)
$wevState = Join-Path $stubDir 'wev-state.json'
$wevLog = Join-Path $stubDir 'wev-calls.txt'
$wevPs = Join-Path $stubDir 'wevtutil-stub.ps1'
[IO.File]::WriteAllText($wevPs, @'
param()
$state = $env:SM_WEV_STATE; $calls = $env:SM_WEV_CALLS
Add-Content -LiteralPath $calls -Value ($args -join ' ')
if ($env:SM_WEV_FAIL -eq '1' -and $args[0] -eq 'sl') { [Console]::Error.WriteLine('Zugriff verweigert'); exit 5 }
$s = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
if ($args[0] -eq 'gl') {
    "name: $($args[1])"; "enabled: $($s.enabled.ToString().ToLower())"; 'type: Operational'; 'logging:'; '  retention: false'; "  maxSize: $($s.max)"; 'publishing:'; '  fileMax: 1'
    exit 0
}
if ($args[0] -eq 'sl') {
    foreach ($a in $args[2..($args.Count - 1)]) {
        if ($a -match '^/e:(true|false)$') { $s.enabled = ($Matches[1] -eq 'true') }
        if ($a -match '^/ms:(\d+)$') { $s.max = [long]$Matches[1] }
    }
    $s | ConvertTo-Json | Set-Content -LiteralPath $state
    exit 0
}
exit 2
'@)
$wev = Join-Path $stubDir 'wevtutil.cmd'
[IO.File]::WriteAllText($wev, "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0wevtutil-stub.ps1`" %*`r`nexit /b %ERRORLEVEL%`r`n")
$script:SmWevtutilPath = $wev
$env:SM_WEV_STATE = $wevState; $env:SM_WEV_CALLS = $wevLog; $env:SM_WEV_FAIL = '0'
[IO.File]::WriteAllText($wevState, '{"enabled":false,"max":1052672}')
$st0 = Get-SmPrintLogStatus
Check 'Protokollstatus: ausgeschaltet, 1 MB (aus wevtutil gl gelesen)' ($st0.Enabled -eq $false -and $st0.MaxSize -eq 1052672)
Check 'Groesse: 100 MB = 104857600 Byte, Vielfache von 64 KB, ungueltige Eingaben abgelehnt' ((ConvertTo-SmLogBytes 100) -eq 104857600 -and (ConvertTo-SmLogBytes 1) % 65536 -eq 0 -and (Throws { ConvertTo-SmLogBytes 0 }) -and (Throws { ConvertTo-SmLogBytes 'abc' }) -and (Throws { ConvertTo-SmLogBytes 5000 }))
Check 'Einschalten ohne Bestaetigung: abgelehnt' (ThrowsLike { Enable-SmPrintLog -Megabytes 100 } 'nicht bestaetigt')
Check 'Einschalten: ungueltige Groesse wird vor jeder Aenderung abgelehnt' ((Throws { Enable-SmPrintLog -Megabytes 'x' -Confirmed }) -and -not (Test-Path (Join-Path $made 'Druckprotokoll-Zustand.json')))
[IO.File]::WriteAllText($wevLog, '')
$on = Enable-SmPrintLog -Megabytes 100 -Confirmed
$calls = Get-Content -LiteralPath $wevLog
Check 'Einschalten: wevtutil sl <Protokoll> /e:true /ms:104857600' (($calls -join '|') -match 'sl Microsoft-Windows-PrintService/Operational /e:true /ms:104857600' -and $on.Status.Enabled -eq $true -and $on.Status.MaxSize -eq 104857600)
$state = Get-Content -LiteralPath (Join-Path $made 'Druckprotokoll-Zustand.json') -Raw | ConvertFrom-Json
Check 'Einschalten: alter Zustand gesichert (aus, 1 MB) im Sicherungsordner' ($state.Enabled -eq $false -and $state.MaxSize -eq 1052672)
Check 'Einschalten: Protokollzeilen (gesichert, eingeschaltet)' (($on.Log -join ' ') -match 'gesichert' -and ($on.Log -join ' ') -match 'eingeschaltet')
$on2 = Enable-SmPrintLog -Megabytes 200 -Confirmed
$state2 = Get-Content -LiteralPath (Join-Path $made 'Druckprotokoll-Zustand.json') -Raw | ConvertFrom-Json
Check 'Zweites Einschalten ueberschreibt den gesicherten Ursprungszustand nicht' ($state2.Enabled -eq $false -and $state2.MaxSize -eq 1052672 -and (Get-SmPrintLogStatus).MaxSize -eq 209715200)
$off = Disable-SmPrintLog -Confirmed
$callsOff = (Get-Content -LiteralPath $wevLog) -join '|'
Check 'Ausschalten: stellt /e:false /ms:1052672 wieder her' ($callsOff -match 'sl Microsoft-Windows-PrintService/Operational /e:false /ms:1052672' -and -not (Get-SmPrintLogStatus).Enabled -and (Get-SmPrintLogStatus).MaxSize -eq 1052672)
Check 'Ausschalten: Zustandsdatei danach entfernt, Protokollzeile' (-not (Test-Path (Join-Path $made 'Druckprotokoll-Zustand.json')) -and ($off.Log -join ' ') -match 'alten Zustand')
Check 'Ausschalten ohne gesicherten Zustand: Abbruch ohne Aenderung' (ThrowsLike { Disable-SmPrintLog -Confirmed } 'kein.* gesicherten')
Check 'Ausschalten ohne Bestaetigung: abgelehnt' (ThrowsLike { Disable-SmPrintLog } 'nicht bestaetigt')
# war vorher schon eingeschaltet (Kunde): Zustand "an, 50 MB" bleibt erhalten
[IO.File]::WriteAllText($wevState, '{"enabled":true,"max":52428800}')
[void](Enable-SmPrintLog -Megabytes 100 -Confirmed); [void](Disable-SmPrintLog -Confirmed)
Check 'War es vorher an (50 MB): Ausschalten stellt "an, 50 MB" wieder her' ((Get-SmPrintLogStatus).Enabled -eq $true -and (Get-SmPrintLogStatus).MaxSize -eq 52428800)
# Fehler von wevtutil
[IO.File]::WriteAllText($wevState, '{"enabled":false,"max":1052672}'); $env:SM_WEV_FAIL = '1'
Check 'Einschalten: wevtutil-Fehler (Exitcode 5) bricht ab, keine Zustandsdatei bleibt liegen' ((ThrowsLike { Enable-SmPrintLog -Megabytes 100 -Confirmed } 'Exitcode 5') -and -not (Test-Path (Join-Path $made 'Druckprotokoll-Zustand.json')))
$env:SM_WEV_FAIL = '0'
$script:adminOk = $false
Check 'Einschalten als Nicht-Administrator: Vorpruefung blockiert' (ThrowsLike { Enable-SmPrintLog -Megabytes 100 -Confirmed } 'Vorpruefung')
$script:adminOk = $true
[IO.File]::WriteAllText((Join-Path $made 'Druckprotokoll-Zustand.json'), '{"Enabled":"ja","MaxSize":5}')
Check 'Manipulierte Zustandsdatei: abgelehnt, nichts an wevtutil gesendet' ((Throws { Disable-SmPrintLog -Confirmed }) -and ((Get-SmPrintLogStatus).MaxSize -eq 1052672))
Remove-Item -LiteralPath (Join-Path $made 'Druckprotokoll-Zustand.json') -Force

# ---------------------------------------------------------------- 9. Sammeln (Ereignis 307, Sofortbild)
$script:winEvents = @(
    (New-EventXml '2026-11-10T08:15:30Z' 'anna' '\\PC-ANNA' 'HP-Buero-1' 'IP_10.0.0.5' 3 45678 307 11),
    (New-EventXml '2026-11-11T09:00:00Z' 'bernd' '\\PC-BERND' 'Kyocera-Flur' 'IP_10.0.0.6' 1 2000 307 12),
    'kaputt'
) | ForEach-Object { $x = $_; $o = New-Object psobject; $o | Add-Member ScriptMethod ToXml { $x }.GetNewClosure(); $o }
$script:winFilter = $null
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable, $MaxEvents) $script:winFilter = $FilterHashtable; $script:winEvents }
function Get-SmbShare { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = 'print$'; Path = 'C:\Windows\system32\spool\drivers' } }
function Get-SmbSession { [CmdletBinding()] param() @([pscustomobject]@{ ClientComputerName = '10.0.0.21'; ClientUserName = 'CONTOSO\anna'; NumOpens = 4 }, [pscustomobject]@{ ClientComputerName = '10.0.0.22'; ClientUserName = 'CONTOSO\bernd'; NumOpens = 1 }) }
function Get-SmbOpenFile { [CmdletBinding()] param() @([pscustomobject]@{ ClientComputerName = '10.0.0.21'; ClientUserName = 'CONTOSO\anna'; Path = 'C:\Windows\system32\spool\drivers\x64\3\hp.dll' }, [pscustomobject]@{ ClientComputerName = '10.0.0.22'; ClientUserName = 'CONTOSO\bernd'; Path = 'D:\Daten\Budget.xlsx' }) }
function Get-Process { [CmdletBinding()] param($Name) [pscustomobject]@{ Id = 1234 } }
function Get-NetTCPConnection { [CmdletBinding()] param($OwningProcess, $State) @([pscustomobject]@{ RemoteAddress = '10.0.0.21'; RemotePort = 49500; LocalPort = 49152 }) }
$col = Invoke-SmPrintCollect -Days 30
Check 'Sammeln: Ereignis 307 im Protokoll PrintService/Operational abgefragt, StartTime gesetzt' ($script:winFilter.LogName -eq 'Microsoft-Windows-PrintService/Operational' -and $script:winFilter.Id -eq 307 -and $script:winFilter.StartTime -lt (Get-Date).AddDays(-29))
Check 'Sammeln: 2 gueltige Ereignisse, kaputtes uebersprungen' ($col.Count -eq 2 -and $col.Name -match '^Print-Zugriffe-[A-Za-z0-9\-]+-\d{8}-\d{6}-[0-9a-f]{12}\.json$')
$ra = Read-SmPrintAccess -Path $col.Path
Check 'Sammeln: Datei vom Berater-Tool lesbar, Zeitraum, Ereignisfelder' (@($ra.Events).Count -eq 2 -and $ra.Events[0].Printer -eq 'HP-Buero-1' -and $ra.Events[0].Client -eq 'PC-ANNA' -and $ra.Events[1].User -eq 'bernd' -and $ra.Events[1].Pages -eq 1)
$colRaw = Get-Content -LiteralPath $col.Path -Raw | ConvertFrom-Json
Check 'Sofortbild: SMB-Sitzungen mit Druckdatei-Kennzeichen, offene Dateien nur Druckfreigabe (Budget.xlsx nicht)' (@($colRaw.Snapshot.SmbSessions).Count -eq 2 -and ($colRaw.Snapshot.SmbSessions | Where-Object User -eq 'CONTOSO\anna').PrintOpen -eq $true -and ($colRaw.Snapshot.SmbSessions | Where-Object User -eq 'CONTOSO\bernd').PrintOpen -eq $false -and @($colRaw.Snapshot.OpenFiles).Count -eq 1 -and $colRaw.Snapshot.OpenFiles[0].Path -match 'spool' -and $col.Path -and ((Get-Content -LiteralPath $col.Path -Raw) -notmatch 'Budget'))
Check 'Sofortbild: Verbindungen des Spoolers, falls ermittelbar' (@($colRaw.Snapshot.SpoolerConnections).Count -eq 1 -and $colRaw.Snapshot.SpoolerConnections[0].LocalPort -eq 49152)
Check 'Sammeln: Dokumentname steht nicht in der Datei' ((Get-Content -LiteralPath $col.Path -Raw) -notmatch 'Quartalsbericht')
Check 'Sammeln: Protokollzeile mit Anzahl und SHA256, ohne Benutzernamen' (($col.Log -join ' ') -match '2 Ereignisse 307' -and ($col.Log -join ' ') -match $col.Sha256 -and ($col.Log -join ' ') -notmatch 'anna|bernd')
function Get-SmbSession { [CmdletBinding()] param() throw 'Zugriff verweigert' }
function Get-NetTCPConnection { [CmdletBinding()] param($OwningProcess, $State) throw 'nicht verfuegbar' }
$col2 = Invoke-SmPrintCollect -Days 7
$c2 = Get-Content -LiteralPath $col2.Path -Raw | ConvertFrom-Json
Check 'Sofortbild nicht ermittelbar: Sammeln gelingt trotzdem, Hinweise in der Datei' ($col2.Count -eq 2 -and @($c2.Snapshot.Notes).Count -ge 2 -and $null -eq $c2.Snapshot.SpoolerConnections)
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable, $MaxEvents) throw (New-Object System.Exception 'No events were found that match the specified selection criteria.') }
Check 'Keine Ereignisse im Zeitraum: leere Datei statt Fehler' ((Invoke-SmPrintCollect -Days 7).Count -eq 0)
Check 'Sammeln: ungueltige Tage abgelehnt' ((Throws { Invoke-SmPrintCollect -Days 0 }) -and (Throws { Invoke-SmPrintCollect -Days 99999 }))
$script:adminOk = $false
Check 'Sammeln als Nicht-Administrator: Vorpruefung blockiert' (ThrowsLike { Invoke-SmPrintCollect -Days 7 } 'Vorpruefung')
$script:adminOk = $true

# Pseudonyme beim Sammeln
$script:winEvents = @(
    (New-EventXml '2026-11-10T08:15:30Z' 'anna' '\\PC-ANNA' 'HP-Buero-1' 'IP_10.0.0.5' 3 45678 307 11),
    (New-EventXml '2026-11-11T09:00:00Z' 'bernd' '\\PC-BERND' 'Kyocera-Flur' 'IP_10.0.0.6' 1 2000 307 12)
) | ForEach-Object { $x = $_; $o = New-Object psobject; $o | Add-Member ScriptMethod ToXml { $x }.GetNewClosure(); $o }
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable, $MaxEvents) $script:winEvents }
function Get-SmbSession { [CmdletBinding()] param() @([pscustomobject]@{ ClientComputerName = '10.0.0.21'; ClientUserName = 'CONTOSO\anna'; NumOpens = 4 }) }
function Get-SmbOpenFile { [CmdletBinding()] param() @([pscustomobject]@{ ClientComputerName = '10.0.0.21'; ClientUserName = 'CONTOSO\anna'; Path = 'C:\Windows\system32\spool\drivers\x64\3\hp.dll' }) }
function Get-NetTCPConnection { [CmdletBinding()] param($OwningProcess, $State) @() }
$ck = New-SmPseudonymKey
$ps1 = Invoke-SmPrintCollect -Days 30 -Pseudonymize -Key $ck
$rawP = Get-Content -LiteralPath $ps1.Path -Raw
$jP = $rawP | ConvertFrom-Json
Check 'Pseudonymisiert: Benutzer als Benutzer-<12 Hex>, kein Klarname in Ereignissen und Sofortbild, Schluessel nicht in der Datei' (@($jP.Events | Where-Object { $_.User -notmatch '^Benutzer-[0-9A-F]{12}$' }).Count -eq 0 -and $rawP -cnotmatch 'anna|bernd' -and $rawP -notmatch $ck -and $jP.Snapshot.SmbSessions[0].User -match '^Benutzer-[0-9A-F]{12}$' -and $jP.Snapshot.OpenFiles[0].User -match '^Benutzer-' -and $jP.Pseudonymized -eq $true)
Check 'Pseudonymisiert: PrintOpen bleibt richtig (vor dem Ersetzen berechnet)' ($jP.Snapshot.SmbSessions[0].PrintOpen -eq $true)
$ps2 = Invoke-SmPrintCollect -Days 30 -Pseudonymize -Key $ck
Check 'Pseudonyme sind mit demselben Schluessel stabil und mit anderem Schluessel verschieden' ((@((Get-Content -LiteralPath $ps2.Path -Raw | ConvertFrom-Json).Events.User) -join ',') -eq (@($jP.Events.User) -join ',') -and (@((Invoke-SmPrintCollect -Days 30 -Pseudonymize -Key (New-SmPseudonymKey) | ForEach-Object { Get-Content -LiteralPath $_.Path -Raw | ConvertFrom-Json }).Events.User) -join ',') -ne (@($jP.Events.User) -join ','))
Check 'Pseudonymisiert: Berater-Tool liest die Datei und meldet Pseudonymisierung' ((Read-SmPrintAccess -Path $ps1.Path).Pseudonymized -eq $true -and (Read-SmPrintAccess -Path $ps1.Path).Events[0].User -match '^Benutzer-')
Check 'Pseudonyme: kein oder kein zufaelliger 64-Hex-Schluessel (getippt, zu kurz) abgelehnt' ((Throws { Invoke-SmPrintCollect -Days 30 -Pseudonymize -Key 'kurz' }) -and (Throws { Invoke-SmPrintCollect -Days 30 -Pseudonymize -Key 'contoso-projekt-2026-contoso-projekt-2026-contoso-projekt-2026!' }) -and (Throws { Invoke-SmPrintCollect -Days 30 -Pseudonymize }) -and (Throws { Invoke-SmPrintCollect -Days 30 -PseudonymizeClients -Key $ck }))
$psC = Invoke-SmPrintCollect -Days 30 -Pseudonymize -PseudonymizeClients -Key $ck
$rawC = Get-Content -LiteralPath $psC.Path -Raw
$jC = $rawC | ConvertFrom-Json
Check 'Rechnernamen pseudonymisiert: Rechner-<12 Hex> in Ereignissen und Sofortbild, kein Rechnername, keine Adresse, Kennzeichen in der Datei' (@($jC.Events | Where-Object { $_.Client -notmatch '^Rechner-[0-9A-F]{12}$' }).Count -eq 0 -and $rawC -cnotmatch 'PC-ANNA|PC-BERND|10\.0\.0\.2' -and $jC.Snapshot.SmbSessions[0].Client -match '^Rechner-[0-9A-F]{12}$' -and $jC.Snapshot.OpenFiles[0].Client -match '^Rechner-' -and $jC.ClientsPseudonymized -eq $true -and $rawC -notmatch $ck)
Check 'Ohne Rechner-Option bleiben Rechnernamen im Klartext (Kennzeichen false)' (($rawP | ConvertFrom-Json).Events[0].Client -match 'PC-' -and ($rawP | ConvertFrom-Json).ClientsPseudonymized -eq $false)
Check 'Schluessel steht nirgends im Sicherungsordner (Dateien, Protokoll)' (-not (Get-ChildItem -LiteralPath $made -File -Recurse | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue) -match $ck }))
Check 'Berater-Tool liest Rechner-Kennzeichen' ((Read-SmPrintAccess -Path $psC.Path).ClientsPseudonymized -eq $true)
Check 'Ohne Pseudonymisierung steht der Name im Klartext, Protokollzeile nennt es' (((Invoke-SmPrintCollect -Days 30).Log -join ' ') -match 'im Klartext' -and ($ps1.Log -join ' ') -match 'pseudonymisiert' -and ($ps1.Log -join ' ') -notmatch ('anna|' + $ck))

# Hochladen in den Tauschordner
$script:sent = $null
function Send-SmShareFile { param($Share, $Path, $Progress) $script:sent = $Path; [pscustomobject]@{ Name = (Split-Path -Leaf $Path); Length = (Get-Item -LiteralPath $Path).Length } }
$up = Send-SmPrintFile -Share ([pscustomobject]@{}) -Name $col.Name
Check 'Hochladen: Datei aus dem Sicherungsordner, SHA256 der lokalen Datei, Protokollzeile' ([IO.Path]::GetFullPath($script:sent) -eq [IO.Path]::GetFullPath($col.Path) -and $up.Sha256 -eq (Get-FileHash -LiteralPath $col.Path -Algorithm SHA256).Hash -and $up.Log[0] -match 'Hochgeladen')
Check 'Hochladen: Name ausserhalb des Sicherungsordners abgelehnt' (Throws { Send-SmPrintFile -Share ([pscustomobject]@{}) -Name '..\..\Windows\win.ini' })

# ---------------------------------------------------------------- 10. Fenster (-ParseOnly) und Paket
foreach ($mode in 'Light', 'Dark') {
    foreach ($entry in @(@('Berater-Tool', 'Start-ServerMigration.ps1'), @('Server-Fenster', 'server\Start-SmServer.ps1'))) {
        $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $Repo $entry[1]) -ParseOnly -Theme $mode 2>&1 | Out-String
        Check ("$($entry[0]) mit Seite Print -ParseOnly ($mode): $($out.Trim())") ($out.Trim() -eq 'PARSE OK')
    }
}
foreach ($x in 'Print.xaml', 'PrintServer.xaml') { $xml = $null; try { [xml]$xml = [IO.File]::ReadAllText((Join-Path $Repo "UI\$x")) } catch { }; Check "$x ist gueltiges XML" ($null -ne $xml) }
$names = @(Get-SmXamlNames ([IO.File]::ReadAllText((Join-Path $Repo 'UI\PrintServer.xaml'))))
Check 'Server-Seite: alle erwarteten Steuerelemente vorhanden' (-not (Get-SmPrintServerUiNames | Where-Object { $_ -notin $names }))
$namesB = @(Get-SmXamlNames ([IO.File]::ReadAllText((Join-Path $Repo 'UI\Print.xaml'))))
Check 'Berater-Seite: alle erwarteten Steuerelemente vorhanden' (-not (Get-SmPrintPageUiNames | Where-Object { $_ -notin $namesB }))
. (Join-Path $Repo 'Modules\SmPaket.ps1')
Check 'Server-Paket enthaelt die Print-Dateien' (($script:SmServerFiles -contains 'Modules/SmPrint.ps1') -and ($script:SmServerFiles -contains 'server/SmPrintServer.ps1') -and ($script:SmServerFiles -contains 'UI/PrintServer.xaml'))

Write-Host ''
Write-Host "Print: $fails Fehler"
if ($ownWork) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
if ($MyInvocation.InvocationName -eq '&') { return $fails }   # von der Suite aufgerufen
exit $fails
