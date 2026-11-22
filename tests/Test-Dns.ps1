#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 3 (DNS): Parser mit Beispielzeilen in mehreren Kulturen und allen Opcodes, Namen, Datumserkennung, Auswertung
    (Clients, DNS-Server-Erkennung, Fehler, Namen, Zonen, Typen, Updates), Rohdaten mit Filter, CSV-Escaping, ZIP-Import mit feindlichem Inhalt,
    Geschwindigkeit, Server-Funktionen mit gemockten DnsServer-Cmdlets, Gegentests zu den Fehlern aus #8 (Altbestand aus git), -ParseOnly beider Fenster.
    Beispieldaten nur mit contoso.local und Adressen aus 10.0.0.0/8. Keine echten Server, keine Netzzugriffe.
    Mit Windows PowerShell 5.1: powershell.exe -NoProfile -STA -File tests\Test-Dns.ps1 [-LargeMB 500]
.PARAMETER LargeMB
    Groesse des erzeugten Logs fuer die Geschwindigkeitsmessung in MB (Standard 40; 500 fuer die volle Messung).
.PARAMETER CompareOld
    Laesst zusaetzlich den alten Parser (git show 3326a3c:DNSParser.ps1) und den neuen auf derselben Datei laufen und gibt die Zeiten aus (#8).
.PARAMETER CompareMB
    Groesse der Vergleichsdatei in MB (Standard 1, damit die Suite schnell bleibt; der alte Parser braucht fuer 500 MB Stunden).
#>
[CmdletBinding()]
param([int]$LargeMB = 40, [switch]$CompareOld, [int]$CompareMB = 1)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = Join-Path $env:TEMP ('sm-dns-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force $work | Out-Null
$script:fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

. (Join-Path $repo 'Modules\SmTausch.ps1')
. (Join-Path $repo 'Modules\SmExport.ps1')
. (Join-Path $repo 'Modules\SmDns.ps1')
. (Join-Path $repo 'server\SmDnsServer.ps1')
Initialize-SmDnsEngine

# ---------------------------------------------------------------- Hilfen: Beispielzeilen
function L([string]$Date, [string]$Time, [string]$Dir, [string]$Ip, [string]$Xid, [string]$R, [string]$Op, [string]$Hex, [string]$Fl, [string]$Rc, [string]$Type, [string]$Name, [string]$Proto = 'UDP') {
    $rflag = if ($R) { 'R' } else { ' ' }
    ('{0} {1} 0F30 PACKET  000001A2B3C4D5E6 {2} {3} {4,-15} {5} {6} {7} [{8} {9,3}  {10,-8}] {11,-6} {12}' -f $Date, $Time, $Proto, $Dir, $Ip, $Xid, $rflag, $Op, $Hex, $Fl, $Rc, $Type, $Name)
}
function Write-Log([string]$Path, [string[]]$Lines) { [IO.File]::WriteAllText($Path, ($Lines -join "`r`n") + "`r`n", [Text.Encoding]::ASCII) }
function Parse-Lines([string[]]$Lines, [string]$Order = $null, [string]$Name = 'x.log') {
    $f = Join-Path $work $Name; Write-Log $f $Lines
    $l = New-SmDnsLog; $l.ParseFile($f, $Order); $l
}
function Raw($Log) { @($Log.Query('Roh', '')) }
$T = { param([int]$y, [int]$mo, [int]$d, [int]$h, [int]$mi, [int]$s) (New-Object DateTime $y, $mo, $d, $h, $mi, $s).Ticks }

# ---------------------------------------------------------------- 1. Dateien: Syntax, Kodierung
foreach ($f in 'Modules\SmDns.ps1', 'Modules\SmDnsUi.ps1', 'Modules\SmExport.ps1', 'server\SmDnsServer.ps1', 'tests\Test-Dns.ps1', 'DNSParser.ps1') {
    $p = Join-Path $repo $f
    $errs = $null; $tok = $null
    [void][Management.Automation.Language.Parser]::ParseFile($p, [ref]$tok, [ref]$errs)
    $bytes = [IO.File]::ReadAllBytes($p)
    Check "Syntax und Kodierung (ASCII oder UTF-8 mit BOM): $f" ((-not $errs) -and (($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) -or -not ($bytes | Where-Object { $_ -gt 127 } | Select-Object -First 1)))
}
foreach ($f in 'UI\Dns.xaml', 'UI\DnsServer.xaml') { Check "XAML laesst sich lesen: $f" ($(try { [xml](Get-Content -LiteralPath (Join-Path $repo $f) -Raw -Encoding UTF8) | Out-Null; $true } catch { $false })) }
Check 'Oberflaeche: Hinweis neben Reverse-Lookup (fragt beim DNS des Berater-Rechners ab)' ((Get-Content -LiteralPath (Join-Path $repo 'UI\Dns.xaml') -Raw -Encoding UTF8).Contains('Fragt die internen IPs beim DNS des Berater-Rechners ab.'))

# ---------------------------------------------------------------- 2. Namen
Check 'Name: (3)www(7)contoso(5)local(0)' ((ConvertFrom-SmDnsName '(3)www(7)contoso(5)local(0)') -eq 'www.contoso.local')
Check 'Name: zweistellige Laenge (12)' ((ConvertFrom-SmDnsName '(12)abcdefghijkl(7)contoso(5)local(0)') -eq 'abcdefghijkl.contoso.local')
Check 'Name: Wurzel (0) = .' ((ConvertFrom-SmDnsName '(0)') -eq '.')
Check 'Name: PTR' ((ConvertFrom-SmDnsName '(2)15(1)0(1)0(2)10(7)in-addr(4)arpa(0)') -eq '15.0.0.10.in-addr.arpa')
Check 'Name: Klammern im Label bleiben' ((ConvertFrom-SmDnsName '(5)a(1)b(7)contoso(5)local(0)') -eq 'a(1)b.contoso.local')
Check 'Name: kaputt bleibt Text, keine Steuerzeichen' ((ConvertFrom-SmDnsName "(3)ab") -eq 'ab' -and (ConvertFrom-SmDnsName 'kein.format') -eq 'kein.format' -and (ConvertFrom-SmDnsName "(x)a`tb") -eq "(x)a?b")
Check 'Name: Laenge groesser als Rest wird begrenzt' ((ConvertFrom-SmDnsName '(50)abc') -eq 'abc')

# ---------------------------------------------------------------- 3. Zeilen, Felder, alle Opcodes (deutsches Format)
$de = @(
    'DNS Server log file creation at 22.11.2026 14:00:00'
    'Message logging key (for packets - other items use a subset of these fields):'
    'Internal packet identifier:  000001A2B3C4D5E6'
    ''
    (L '22.11.2026' '14:05:09' 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:09' 'Snd' '10.0.0.15' 'a3f2' 'R' 'Q' '8081' 'DR' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:10' 'Rcv' '10.0.0.16' 'b001' '' 'Q' '0001' 'D' 'NOERROR' 'AAAA' '(4)host(2)ab(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:10' 'Snd' '10.0.0.16' 'b001' 'R' 'Q' '8381' 'DR' 'NXDOMAIN' 'AAAA' '(4)host(2)ab(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:11' 'Rcv' '10.0.0.20' 'c001' '' 'U' '0028' '' 'NOERROR' 'SOA' '(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:11' 'Snd' '10.0.0.20' 'c001' 'R' 'U' '00A8' '' 'NOERROR' 'SOA' '(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:12' 'Rcv' '10.0.0.2' 'd001' '' 'N' '0024' 'A' 'NOERROR' 'SOA' '(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:13' 'Rcv' '10.0.0.30' 'e001' '' '?' '0078' '' 'NOERROR' 'A' '(3)odd(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:14' 'Rcv' '10.0.0.15' 'f001' '' 'Q' '0001' 'D' 'NOERROR' 'PTR' '(2)15(1)0(1)0(2)10(7)in-addr(4)arpa(0)' 'TCP')
    (L '22.11.2026' '14:05:15' 'Rcv' '::ffff:10.0.0.31' 'f002' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(12)abcdefghijkl(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:16' 'Snd' '10.0.0.15' 'f003' 'R' 'Q' '8585' 'A DR' 'REFUSED' 'MX' '(7)contoso(5)local(0)')
    '22.11.2026 14:05:17 0F30 PACKET  broken line without fields'
    '22.11.2026 14:05:18 0F30 EVENT   The DNS server has started.'
)
$log = Parse-Lines $de
$rows = Raw $log
Check "Parser: 11 Pakete gelesen, defekte Zeile gezaehlt (Pakete $($log.RowCount), uebersprungen $($log.Skipped))" ($log.RowCount -eq 11 -and $log.Skipped -eq 1)
Check 'Parser: Datum dd.MM.yyyy erkannt (DMY)' ($log.DetectedOrder -eq 'DMY')
Check 'Parser: Zeitraum von bis' ($log.MinTicks -eq (& $T 2026 11 22 14 5 9) -and $log.MaxTicks -eq (& $T 2026 11 22 14 5 16) -and $log.FirstText -eq '2026-11-22 14:05:09' -and $log.LastText -eq '2026-11-22 14:05:16')
$q = $rows[0]
Check 'Feld Query: Zeit, Richtung, Protokoll, IP, Art, Opcode, Flags, RCODE, Typ, Name' ($q.Zeit -eq '2026-11-22 14:05:09' -and $q.Richtung -eq 'Rcv' -and $q.Protokoll -eq 'UDP' -and $q.Ip -eq '10.0.0.15' -and $q.Art -eq 'Anfrage' -and $q.Opcode -eq 'Query' -and $q.Flags -eq 'D' -and $q.FlagsHex -eq '0001' -and $q.Rcode -eq 'NOERROR' -and $q.Typ -eq 'A' -and $q.Name -eq 'www.contoso.local' -and $q.Xid -eq 'a3f2')
$a = $rows[1]
Check 'Feld Antwort (R): Snd, Antwort, Flags DR' ($a.Richtung -eq 'Snd' -and $a.Art -eq 'Antwort' -and $a.Flags -eq 'DR' -and $a.FlagsHex -eq '8081')
Check 'RCODE NXDOMAIN, Name mit (2) ab' ($rows[3].Rcode -eq 'NXDOMAIN' -and $rows[3].Name -eq 'host.ab.contoso.local' -and $rows[3].Typ -eq 'AAAA')
Check 'Opcode Update (U) bei leeren Flags' ($rows[4].Opcode -eq 'Update' -and $rows[4].Typ -eq 'SOA' -and $rows[4].Art -eq 'Anfrage' -and $rows[5].Art -eq 'Antwort' -and $rows[5].Opcode -eq 'Update')
Check 'Opcode Notify (N)' ($rows[6].Opcode -eq 'Notify' -and $rows[6].Ip -eq '10.0.0.2')
Check 'Opcode unbekannt (?)' ($rows[7].Opcode -eq 'Unknown')
Check 'TCP und PTR-Name' ($rows[8].Protokoll -eq 'TCP' -and $rows[8].Typ -eq 'PTR' -and $rows[8].Name -eq '15.0.0.10.in-addr.arpa')
Check 'IPv6-Adresse und zweistellige Namenslaenge' ($rows[9].Ip -eq '::ffff:10.0.0.31' -and $rows[9].Name -eq 'abcdefghijkl.contoso.local')
Check 'Flags mit Leerzeichen (A DR) und REFUSED' ($rows[10].Flags -eq 'ADR' -and $rows[10].Rcode -eq 'REFUSED' -and $rows[10].Typ -eq 'MX')
$more = Parse-Lines @(
    (L '22.11.2026' '09:00:00' 'Rcv' '10.0.0.15' '0001' '' 'I' '0009' 'D' 'NOERROR' 'A' '(1)a(7)contoso(5)local(0)')
    (L '22.11.2026' '09:00:01' 'Rcv' '10.0.0.15' '0002' '' 'S' '0031' 'D' 'NOERROR' 'A' '(1)a(7)contoso(5)local(0)')) -Name 'op.log'
Check 'Opcodes IQuery (I) und Status (S)' ((Raw $more | ForEach-Object Opcode) -join ',' -eq 'IQuery,Status')

# ---------------------------------------------------------------- 4. Kulturen und Datumsformate
$stamp = (& $T 2026 11 22 14 5 9)
function OneLine([string]$Date, [string]$Time) { L $Date $Time 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)' }
function Block([string]$Date, [string]$Time) { 1..3 | ForEach-Object { OneLine $Date $Time } }
$cases = @(
    @('Deutsch dd.MM.yyyy HH:mm:ss', '22.11.2026', '14:05:09', 'DMY'),
    @('US M/d/yyyy h:mm:ss PM', '11/22/2026', '2:05:09 PM', 'MDY'),
    @('US mit fuehrenden Nullen hh:mm:ss PM', '11/22/2026', '02:05:09 PM', 'MDY'),
    @('ISO yyyy-MM-dd', '2026-11-22', '14:05:09', 'YMD'),
    @('Britisch dd/MM/yyyy', '22/11/2026', '14:05:09', 'DMY'),
    @('Franzoesisch d/M/yyyy', '22/11/2026', '14:05:09', 'DMY'),
    @('Niederlaendisch dd-MM-yyyy', '22-11-2026', '14:05:09', 'DMY')
)
foreach ($c in $cases) {
    $l = Parse-Lines (Block $c[1] $c[2]) -Name 'c.log'
    Check ("Kultur $($c[0]): Zeit richtig, Format $($c[3]) erkannt") ($l.RowCount -eq 3 -and $l.MinTicks -eq $stamp -and $l.DetectedOrder -eq $c[3])
}
$am = Parse-Lines @((OneLine '11/22/2026' '12:00:01 AM'), (OneLine '11/22/2026' '12:30:00 PM'), (OneLine '11/22/2026' '11:59:59 PM')) -Name 'ampm.log'
Check 'AM/PM: 12:00:01 AM = 00:00:01, 12:30 PM = 12:30, 11:59:59 PM = 23:59:59' ($am.RowCount -eq 3 -and $am.MinTicks -eq (& $T 2026 11 22 0 0 1) -and $am.MaxTicks -eq (& $T 2026 11 22 23 59 59))
$amb = @((OneLine '03/04/2026' '10:00:00'))
Check 'Mehrdeutig 03/04/2026: Formatangabe DMY -> 3. April' ((Parse-Lines $amb 'DMY').MinTicks -eq (& $T 2026 4 3 10 0 0))
Check 'Mehrdeutig 03/04/2026: Formatangabe MDY -> 4. Maerz' ((Parse-Lines $amb 'MDY').MinTicks -eq (& $T 2026 3 4 10 0 0))
Check 'Mehrdeutig 03/04/2026 ohne Angabe: Schraegstrich = MDY' ((Parse-Lines $amb).MinTicks -eq (& $T 2026 3 4 10 0 0))
Check 'Mehrdeutig 03.04.2026 ohne Angabe: Punkt = DMY' ((Parse-Lines @((OneLine '03.04.2026' '10:00:00'))).MinTicks -eq (& $T 2026 4 3 10 0 0))
$mixed = Parse-Lines @((OneLine '05/04/2026' '10:00:00'), (OneLine '13/04/2026' '10:00:00'), (OneLine '20/04/2026' '10:00:00'))
Check 'Erkennung ueber mehrere Tage (13 und 20 kann nur ein Tag sein) -> DMY' ($mixed.DetectedOrder -eq 'DMY' -and $mixed.MinTicks -eq (& $T 2026 4 5 10 0 0) -and $mixed.MaxTicks -eq (& $T 2026 4 20 10 0 0))
Check 'Falsche Formatangabe (YMD fuer dd.MM.yyyy) wird verworfen, Automatik greift' ((Parse-Lines (Block '22.11.2026' '14:05:09') 'YMD').MinTicks -eq $stamp)
Check 'ConvertTo-SmDnsDateOrder: Muster' ((ConvertTo-SmDnsDateOrder 'dd.MM.yyyy') -eq 'DMY' -and (ConvertTo-SmDnsDateOrder 'M/d/yyyy') -eq 'MDY' -and (ConvertTo-SmDnsDateOrder 'yyyy-MM-dd') -eq 'YMD' -and -not (ConvertTo-SmDnsDateOrder 'quatsch') -and -not (ConvertTo-SmDnsDateOrder ''))
$twoDay = Parse-Lines @((OneLine '2026-11-22' '23:59:59'), (OneLine '2026-11-23' '00:00:01'))
Check 'Zeitraum ueber Mitternacht' ($twoDay.MinTicks -eq (& $T 2026 11 22 23 59 59) -and $twoDay.MaxTicks -eq (& $T 2026 11 23 0 0 1))

# ---------------------------------------------------------------- 5. Auswertung: Clients und Erkennung anderer DNS-Server
$lines = New-Object System.Collections.Generic.List[string]
function Add-Q([string]$Ip, [string]$Name, [string]$Time, [string]$Hex = '0001', [string]$Type = 'A') { $lines.Add((L '22.11.2026' $Time 'Rcv' $Ip 'aaaa' '' 'Q' $Hex 'D' 'NOERROR' $Type $Name)) }
for ($i = 0; $i -lt 3; $i++) { Add-Q '10.0.0.15' '(3)www(7)contoso(5)local(0)' ('10:00:0{0}' -f $i) }
for ($i = 0; $i -lt 2; $i++) { Add-Q '10.0.0.15' '(4)mail(7)contoso(5)local(0)' ('11:00:0{0}' -f $i) }
for ($i = 0; $i -lt 100; $i++) { Add-Q '10.0.0.9' ('(2)h{0}(7)contoso(5)local(0)' -f ($i % 10)) '12:00:00' }
for ($i = 0; $i -lt 3; $i++) { Add-Q '10.0.0.2' '(2)dc(7)contoso(5)local(0)' '13:00:00' }
$lines.Add((L '22.11.2026' '13:00:05' 'Rcv' '10.0.0.2' 'bbbb' '' 'N' '0024' 'A' 'NOERROR' 'SOA' '(7)contoso(5)local(0)'))
for ($i = 0; $i -lt 60; $i++) { Add-Q '10.0.0.77' ('({0})x{1}(3)ext(7)contoso(5)local(0)' -f (1 + ([string]$i).Length), $i) '14:00:00' $(if ($i % 2) { '0000' } else { '0001' }) }   # 30 Anfragen ohne Rekursionswunsch: rekursive Muster
for ($i = 0; $i -lt 4; $i++) { Add-Q '10.0.0.1' '(4)self(7)contoso(5)local(0)' '15:00:00' }
for ($i = 0; $i -lt 3; $i++) { Add-Q '10.0.0.88' '(3)fwd(7)contoso(5)local(0)' '15:30:00' }
$f = Join-Path $work 'clients.log'; Write-Log $f $lines.ToArray()
$cl = New-SmDnsLog; $cl.ParseFile($f, $null)
$meta = [pscustomobject]@{
    Server = 'dc01'; Culture = 'de-DE'; SystemLocale = 'de-DE'; DateFormat = 'dd.MM.yyyy'; TimeFormat = ''; TimeZone = ''
    OwnIps = @('10.0.0.1'); Forwarders = @('10.0.0.88'); ConditionalForwarders = @(); SecondaryServers = @()
    DomainControllers = @([pscustomobject]@{ Name = 'dc02.contoso.local'; Ips = @('10.0.0.2') }); Zones = @([pscustomobject]@{ Name = 'contoso.local'; Type = 'Primary' })
}
Add-SmDnsMetaToLog -Log $cl -Meta $meta
$clients = @($cl.Query('Clients', ''))
function Cl([string]$Ip) { $clients | Where-Object Ip -eq $Ip }
Check 'Clients: sortiert nach Anzahl, 6 IPs' ($clients.Count -eq 6 -and $clients[0].Ip -eq '10.0.0.9' -and $clients[0].Anzahl -eq 100)
Check 'Clients: Anzahl, erste und letzte Anfrage, Namen, Top-Namen' ((Cl '10.0.0.15').Anzahl -eq 5 -and (Cl '10.0.0.15').ErsteAnfrage -eq '2026-11-22 10:00:00' -and (Cl '10.0.0.15').LetzteAnfrage -eq '2026-11-22 11:00:01' -and (Cl '10.0.0.15').Namen -eq 2 -and (Cl '10.0.0.15').TopNamen -eq 'www.contoso.local (3); mail.contoso.local (2)')
Check 'Clients: gewoehnlicher Client bleibt Client' ((Cl '10.0.0.15').Rolle -eq 'Client' -and (Cl '10.0.0.9').Rolle -eq 'Client')
Check 'Erkennung: DC aus Metadatei, plus Notify' ((Cl '10.0.0.2').Rolle -eq 'DNS-Server (bekannt)' -and (Cl '10.0.0.2').Hinweis -match 'dc02.contoso.local')
Check 'Erkennung: Forwarder aus Metadatei' ((Cl '10.0.0.88').Rolle -eq 'DNS-Server (bekannt)' -and (Cl '10.0.0.88').Hinweis -match 'Forwarder')
Check 'Erkennung: eigene IP = Dieser Server' ((Cl '10.0.0.1').Rolle -eq 'Dieser Server')
Check 'Erkennung per Muster: Anfragen ohne Rekursionswunsch = vermutet' ((Cl '10.0.0.77').Rolle -eq 'DNS-Server (vermutet)' -and (Cl '10.0.0.77').Hinweis -match 'rekursive Muster' -and (Cl '10.0.0.77').Namen -eq 60)
Check 'Ansicht DNS-Server: nur markierte' ((@($cl.Query('DnsServer', '')) | ForEach-Object Ip | Sort-Object) -join ',' -eq '10.0.0.1,10.0.0.2,10.0.0.77,10.0.0.88')
$nots = New-SmDnsLog; $nots.ParseFile($f, $null)
Check 'Ohne Metadatei: 10.0.0.2 mit Notify wird vermutet, Forwarder 10.0.0.88 nicht' ((@($nots.Query('Clients', '')) | Where-Object Ip -eq '10.0.0.2').Rolle -eq 'DNS-Server (vermutet)' -and (@($nots.Query('Clients', '')) | Where-Object Ip -eq '10.0.0.88').Rolle -eq 'Client')
$cl.SetReverse('10.0.0.15', 'pc15.contoso.local')
Check 'Reverse-Name optional: erscheint in der Ansicht und im Filter' ((@($cl.Query('Clients', 'pc15')) | ForEach-Object Ip) -join ',' -eq '10.0.0.15' -and (@($cl.Query('Clients', '')) | Where-Object Ip -eq '10.0.0.9').Name -eq '')
Check 'Filter: mehrere Begriffe (UND), Gross-/Kleinschreibung egal' (@($cl.Query('Clients', 'WWW contoso')).Count -eq 1 -and @($cl.Query('Clients', 'vermutet')).Count -eq 1)

# Fehler, Namen, Zonen, Typen, Updates
$ev = Parse-Lines $de -Name 'ev.log'
Add-SmDnsMetaToLog -Log $ev -Meta $meta
$err = @($ev.Query('Fehler', ''))
Check 'Fehler: NXDOMAIN und REFUSED je Name und Client' ($err.Count -eq 2 -and (($err | Where-Object Antwort -eq 'NXDOMAIN').Name -eq 'host.ab.contoso.local') -and (($err | Where-Object Antwort -eq 'REFUSED').Client -eq '10.0.0.15') -and (($err | Where-Object Antwort -eq 'NXDOMAIN').Typ -eq 'AAAA'))
$names = @($ev.Query('Namen', ''))
Check 'Namen: Zone, Anzahl, Clients, Typen' ((($names | Where-Object Name -eq 'www.contoso.local').Zone -eq 'contoso.local') -and (($names | Where-Object Name -eq 'www.contoso.local').Anzahl -eq 1) -and (($names | Where-Object Name -eq '15.0.0.10.in-addr.arpa').Zone -ne 'contoso.local'))
$zones = @($ev.Query('Zonen', ''))
Check 'Zonen: eigene Zone aus der Metadatei markiert' ((($zones | Where-Object Zone -eq 'contoso.local').Herkunft -eq 'Zone dieses Servers') -and (($zones | Where-Object Zone -eq 'contoso.local').Namen -ge 2))
$types = @($ev.Query('Typen', ''))
Check 'Typen: A und AAAA, Anteile ergeben 100' ((($types | Where-Object Typ -eq 'A').Anzahl -ge 1) -and ([math]::Abs((($types | Measure-Object AnteilProzent -Sum).Sum) - 100) -lt 1))
$up = @($ev.Query('Updates', ''))
Check 'Updates und Notify: Art, Client, Anzahl' ((($up | Where-Object Art -eq 'Update').Client -eq '10.0.0.20') -and (($up | Where-Object Art -eq 'Notify').Client -eq '10.0.0.2') -and $up.Count -eq 2)
Check 'Rohdaten mit Filter (IP, Typ, RCODE, Opcode, Richtung)' (@($ev.Query('Roh', '10.0.0.15')).Count -eq 4 -and @($ev.Query('Roh', 'nxdomain')).Count -eq 1 -and @($ev.Query('Roh', 'notify')).Count -eq 1 -and @($ev.Query('Roh', 'snd aaaa')).Count -eq 1 -and @($ev.Query('Roh', 'tcp')).Count -eq 1 -and @($ev.Query('Roh', 'gibtesnicht')).Count -eq 0)
$page = $ev.GetPage('Roh', '', 5)
Check 'Seite: Begrenzung und Gesamtzahl' ($page.Items.Count -eq 5 -and $page.Total -eq 11 -and $page.Cut -and $page.Items.GetType().GetGenericArguments()[0].Name -eq 'SmRawRow')
Check 'Seite: gefilterte Gesamtzahl' ($ev.GetPage('Roh', 'a3f2', 1).Total -eq 2)

# ---------------------------------------------------------------- 6. Export (Export-SmTable: CSV und Excel, Formel-Injection, Checkliste 7)
Initialize-SmExportEngine
Check 'Export: = + - @ Tab CR bekommen ein Anfuehrungszeichen davor' ((@('=1+1', '+SUM(1)', '-2', '@A1', "`tx", "`rx") | ForEach-Object { [SmTable]::Guard($_) } | Where-Object { $_ -notmatch "^'" }).Count -eq 0 -and [SmTable]::Guard('abc') -eq 'abc')
$injLog = Join-Path $work 'inj.log'
Write-Log $injLog @(
    (L '22.11.2026' '10:00:00' 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(4)=cmd(5)local(0)')
    (L '22.11.2026' '10:00:01' 'Rcv' '10.0.0.15' 'a3f3' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)a;b(5)local(0)')
    (L '22.11.2026' '10:00:02' 'Rcv' '10.0.0.15' 'a3f4' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(9)-1+cmd|zz(0)'))
$ci = New-SmDnsLog; $ci.ParseFile($injLog, $null)
$csv = Join-Path $work 'out.csv'
$n = Export-SmTable -Rows ($ci.Query('Roh', '')) -Path $csv
$text = [IO.File]::ReadAllText($csv, [Text.Encoding]::UTF8)
$csvBytes = [IO.File]::ReadAllBytes($csv)
Check 'CSV-Export Rohdaten: 3 Zeilen, UTF-8 mit BOM, Kopfzeile mit Leerzeichen' ($n -eq 3 -and $csvBytes[0] -eq 0xEF -and $csvBytes[1] -eq 0xBB -and $csvBytes[2] -eq 0xBF -and $text -match 'Zeit;Richtung;Protokoll;Ip;Art;Opcode;Flags;Flags Hex;Rcode;Typ;Name;Xid')
Check 'CSV-Export: gefaehrliche Namen sind entschaerft, Trenner gequotet' ($text -match ";'=cmd\.local;" -and $text -match ';"a;b\.local";' -and $text -match ";'-1\+cmd\|zz;" -and $text -notmatch ';=cmd' -and $text -notmatch ';-1\+cmd')
Check 'CSV-Export gefilterte Ansicht enthaelt nur Treffer' ((Export-SmTable -Rows ($ci.Query('Roh', 'cmd')) -Path $csv) -eq 2)
$csv2 = Join-Path $work 'out2.csv'
$m = Export-SmTable -Rows @([pscustomobject]@{ Name = '=evil'; Anzahl = 5 }, [pscustomobject]@{ Name = 'ok'; Anzahl = -3 }) -Path $csv2
$t2 = [IO.File]::ReadAllText($csv2, [Text.Encoding]::UTF8)
Check 'CSV: Text entschaerft, Zahlen unveraendert (auch negative), CRLF' ($m -eq 2 -and $t2 -match "'=evil;5" -and $t2 -match 'ok;-3' -and $t2 -match "`r`n")

# Excel (xlsx): selbst gebautes OpenXML
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function Read-ZipText([string]$Zip, [string]$Entry) {
    $z = [IO.Compression.ZipFile]::OpenRead($Zip)
    try { $e = $z.GetEntry($Entry); if (-not $e) { return $null }; $r = New-Object IO.StreamReader($e.Open(), [Text.Encoding]::UTF8); try { $r.ReadToEnd() } finally { $r.Dispose() } } finally { $z.Dispose() }
}
$xl = Join-Path $work 'out.xlsx'
$ctrl = [string][char]1
$xrows = @(
    [pscustomobject]@{ Name = '=1+1'; Anzahl = 5; ErsteAnfrage = [datetime]'2026-11-22 10:00:00'; Preis = -2.5; Text = 'a<b>&"c"' }
    [pscustomobject]@{ Name = '@SUM(A1)'; Anzahl = -3; ErsteAnfrage = $null; Preis = 1.25; Text = "x${ctrl}y" }
    [pscustomobject]@{ Name = 'ok'; Anzahl = 0; ErsteAnfrage = [datetime]'2026-01-02 03:04:05'; Preis = 100; Text = '+49 123' })
$xn = Export-SmTable -Rows $xrows -Path $xl
$zipOk = $true; try { $zx = [IO.Compression.ZipFile]::OpenRead($xl); $names = @($zx.Entries | ForEach-Object FullName); $zx.Dispose() } catch { $zipOk = $false; $names = @() }
Check 'xlsx: laesst sich als ZIP oeffnen, Pflichtteile vorhanden' ($zipOk -and $xn -eq 3 -and ($names -contains '[Content_Types].xml') -and ($names -contains '_rels/.rels') -and ($names -contains 'xl/workbook.xml') -and ($names -contains 'xl/worksheets/sheet1.xml') -and ($names -contains 'xl/styles.xml'))
$sheetText = Read-ZipText $xl 'xl/worksheets/sheet1.xml'
$sheet = $null; try { $sheet = [xml]$sheetText } catch { }
Check 'xlsx: sheet1.xml, workbook.xml und styles.xml sind gueltiges XML' ($sheet -and $(try { [xml](Read-ZipText $xl 'xl/workbook.xml') | Out-Null; [xml](Read-ZipText $xl 'xl/styles.xml') | Out-Null; [xml](Read-ZipText $xl '[Content_Types].xml') | Out-Null; $true } catch { $false }))
$nsm = New-Object Xml.XmlNamespaceManager($sheet.NameTable); $nsm.AddNamespace('m', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main')
function Cell([string]$Ref) { $sheet.SelectSingleNode("//m:c[@r='$Ref']", $nsm) }
function CellText($c) { if ($c.t -eq 'inlineStr') { $c.SelectSingleNode('m:is/m:t', $nsm).InnerText } else { $c.SelectSingleNode('m:v', $nsm).InnerText } }
Check 'xlsx: Kopfzeile fett (Stil 1), Namen mit Leerzeichen getrennt' ((Cell 'A1').s -eq '1' -and (CellText (Cell 'A1')) -eq 'Name' -and (CellText (Cell 'B1')) -eq 'Anzahl' -and (CellText (Cell 'C1')) -eq 'Erste Anfrage' -and ($sheet.SelectNodes('//m:row[@r="1"]/m:c', $nsm) | Where-Object { $_.s -ne '1' }).Count -eq 0)
Check 'xlsx: AutoFilter ueber Kopfzeile und alle Daten (A1:E4)' ($sheet.SelectSingleNode('//m:autoFilter', $nsm).ref -eq 'A1:E4')
Check 'xlsx: Zahlen sind Zahlen (auch negativ und Komma-Werte), Text ist Inline-String' ((Cell 'B2').t -ne 'inlineStr' -and (CellText (Cell 'B2')) -eq '5' -and (CellText (Cell 'B3')) -eq '-3' -and (CellText (Cell 'D2')) -eq '-2.5' -and (CellText (Cell 'D4')) -eq '100' -and (Cell 'A4').t -eq 'inlineStr' -and (CellText (Cell 'A4')) -eq 'ok')
Check 'xlsx: Datum als Text im ISO-Format, leere Zelle (null) fehlt' ((Cell 'C2').t -eq 'inlineStr' -and (CellText (Cell 'C2')) -eq '2026-11-22 10:00:00' -and (CellText (Cell 'C4')) -eq '2026-01-02 03:04:05' -and $null -eq (Cell 'C3'))
Check 'xlsx: Formel-Injection: "=1+1" und "@SUM(A1)" sind Text mit Anfuehrungszeichen, kein Formel-Element in der Datei' ((CellText (Cell 'A2')) -eq "'=1+1" -and (Cell 'A2').t -eq 'inlineStr' -and (CellText (Cell 'A3')) -eq "'@SUM(A1)" -and (CellText (Cell 'E4')) -eq "'+49 123" -and $sheet.SelectNodes('//*[local-name()="f"]').Count -eq 0 -and $sheetText -notmatch '<f[ >]')
Check 'xlsx: Sonderzeichen (<, >, &, Anfuehrungszeichen) bleiben erhalten, Steuerzeichen werden zu ?' ((CellText (Cell 'E2')) -eq 'a<b>&"c"' -and (CellText (Cell 'E3')) -eq 'x?y')
$xh = Join-Path $work 'hash.xlsx'
[void](Export-SmTable -Rows @([ordered]@{ Name = 'h1'; Wert = 1 }, [ordered]@{ Name = '=h2'; Wert = 2 }) -Path $xh)
$sheet = [xml](Read-ZipText $xh 'xl/worksheets/sheet1.xml')
Check 'xlsx: Hashtables als Zeilen (Schluessel = Spalten), Injection auch hier' ((CellText (Cell 'A2')) -eq 'h1' -and (CellText (Cell 'B3')) -eq '2' -and (CellText (Cell 'A3')) -eq "'=h2")
$xe = Join-Path $work 'leer.xlsx'
Check 'xlsx und csv ohne Zeilen: gueltige Datei, 0 Zeilen' ((Export-SmTable -Rows @() -Path $xe) -eq 0 -and $(try { [xml](Read-ZipText $xe 'xl/worksheets/sheet1.xml') | Out-Null; $true } catch { $false }) -and (Export-SmTable -Rows @() -Path (Join-Path $work 'leer.csv')) -eq 0)
$xd = Join-Path $work 'dns.xlsx'
$xdn = Export-SmTable -Rows ($ci.Query('Roh', '')) -Path $xd
$sheet = [xml](Read-ZipText $xd 'xl/worksheets/sheet1.xml')
Check 'xlsx: DNS-Rohdaten (typisierte Objekte aus dem Parser) mit entschaerften Namen' ($xdn -eq 3 -and (CellText (Cell 'K2')) -eq "'=cmd.local" -and (CellText (Cell 'K4')) -eq "'-1+cmd|zz" -and (CellText (Cell 'A2')) -eq '2026-11-22 10:00:00')
$bigRows = [Linq.Enumerable]::Repeat([object]([pscustomobject]@{ A = 1; B = 'x' }), 1048577)
$tooMany = Join-Path $work 'zuviele.xlsx'
Check 'xlsx: mehr als 1.048.575 Zeilen werden abgelehnt (Hinweis auf CSV), keine halbe Datei bleibt' ((Throws { Export-SmTable -Rows $bigRows -Path $tooMany }) -and -not (Test-Path $tooMany))
Check 'Export: falsche Endung und fehlender Ordner abgelehnt' ((Throws { Export-SmTable -Rows @() -Path (Join-Path $work 'x.txt') }) -and (Throws { Export-SmTable -Rows @() -Path (Join-Path $work 'gibt\es\nicht.xlsx') }))

# ---------------------------------------------------------------- 7. Metadatei und ZIP (feindliche Daten)
$goodMeta = @{
    Version = 1; Server = 'DC01'; TimeZone = 'W. Europe Standard Time'; Culture = 'de-DE'; SystemLocale = 'de-DE'; DateFormat = 'dd.MM.yyyy'; TimeFormat = 'HH:mm:ss'
    OwnIps = @('10.0.0.1'); Forwarders = @('10.0.0.88'); UseRootHint = $true
    ConditionalForwarders = @(@{ Zone = 'branch.contoso.local'; Servers = @('10.0.0.50') }); SecondaryServers = @(@{ Zone = 'contoso.local'; Servers = @('10.0.0.60', '10.0.0.61') })
    DomainControllers = @(@{ Name = 'dc02.contoso.local'; Site = 'Default'; Ips = @('10.0.0.2') }); Zones = @(@{ Name = 'contoso.local'; Type = 'Primary' })
} | ConvertTo-Json -Depth 6
$gm = ConvertFrom-SmDnsMeta -Json $goodMeta
Check 'Metadaten: Felder gelesen' ($gm.Server -eq 'DC01' -and $gm.DateFormat -eq 'dd.MM.yyyy' -and $gm.Forwarders -contains '10.0.0.88' -and $gm.SecondaryServers[0].Servers.Count -eq 2 -and $gm.ConditionalForwarders[0].Servers[0] -eq '10.0.0.50' -and $gm.DomainControllers[0].Ips[0] -eq '10.0.0.2')
$bad = @{
    Server = 'dc01;calc.exe & whoami'; TimeZone = ('x' * 500); Culture = '<script>'; DateFormat = 'Invoke-Expression'; OwnIps = @('10.0.0.1', 'evil', '999.1.1.1', '<script>', ('1' * 100)); Forwarders = 'not-an-array'
    DomainControllers = @(@{ Name = '$(calc)'; Ips = @('10.0.0.9', 'x') }); Zones = @(@{ Name = "contoso.local'; Remove-Item C:\ -Recurse; '"; Type = 'Primary' }); Extra = @{ Evil = 'ignored' }
} | ConvertTo-Json -Depth 6
$bm = ConvertFrom-SmDnsMeta -Json $bad
Check 'Metadaten feindlich: Text bereinigt, ungueltige IPs verworfen, Fremdfelder ignoriert' (($bm.Server -notmatch '[;&]') -and $bm.TimeZone.Length -le 80 -and ($bm.OwnIps -join ',') -eq '10.0.0.1' -and -not $bm.DateFormat -and $bm.DomainControllers[0].Ips.Count -eq 1 -and $bm.Zones[0].Name -notmatch "[';]" -and -not $bm.PSObject.Properties['Extra'] -and $bm.Culture -notmatch '[<>]')
Check 'Metadaten: zu grosse Datei abgelehnt' (Throws { ConvertFrom-SmDnsMeta -Json ('x' * 3MB) })
Check 'Metadaten: kein JSON abgelehnt' (Throws { ConvertFrom-SmDnsMeta -Json '{{{ kaputt' })

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function New-TestZip([string]$Path, [hashtable]$Entries) {
    $z = [IO.Compression.ZipFile]::Open($Path, 'Create')
    try { foreach ($k in $Entries.Keys) { $e = $z.CreateEntry($k); $s = $e.Open(); $b = [Text.Encoding]::UTF8.GetBytes([string]$Entries[$k]); $s.Write($b, 0, $b.Length); $s.Dispose() } } finally { $z.Dispose() }
}
$logText = ($de -join "`r`n")
$zip1 = Join-Path $work 'SM-DNS-DC01-20261122-140000.zip'
New-TestZip $zip1 @{ 'dns.log' = $logText; 'meta.json' = $goodMeta }
$zl = New-SmDnsLog
$imp = Import-SmDnsZip -Log $zl -Path $zip1
Check 'ZIP: dns.log und meta.json gelesen, Server-Erkennung aus der Metadatei' ($zl.RowCount -eq 11 -and $imp.Meta.Server -eq 'DC01' -and $zl.Known.ContainsKey('10.0.0.2') -and $zl.Known.ContainsKey('10.0.0.60') -and $zl.Known.ContainsKey('10.0.0.50') -and $zl.Zones.Contains('contoso.local') -and $imp.Warnings.Count -eq 0)
$zip2 = Join-Path $work 'hostile.zip'
New-TestZip $zip2 @{ '../evil.log' = $logText; 'sub/x.log' = $logText; 'readme.txt' = 'hi'; 'we ird;name.log' = $logText; 'dns.log' = $logText; 'meta.json' = '{{{ kaputt' }
$hl = New-SmDnsLog
$imp2 = Import-SmDnsZip -Log $hl -Path $zip2
Check 'ZIP feindlich: nur Leaf-Namen der Whitelist gelesen (Pfade, fremde Namen, Sonderzeichen uebersprungen)' ($hl.RowCount -eq 11 -and $imp2.Warnings.Count -ge 4 -and ($imp2.Warnings -join ' ') -match 'Unterordner' -and ($imp2.Warnings -join ' ') -match 'meta.json ist ungueltig')
Check 'ZIP feindlich: nichts ausserhalb geschrieben (es wird nicht entpackt)' (-not (Test-Path (Join-Path $work '..\evil.log')) -and -not (Test-Path (Join-Path $work 'evil.log')) -and -not (Test-Path (Join-Path $work 'sub')))
$lim = $script:SmDnsLimits.Clone()
try {
    $script:SmDnsLimits.MaxLogBytes = 1000
    $big = New-SmDnsLog; $impBig = Import-SmDnsZip -Log $big -Path $zip1
    Check 'ZIP Limit: zu grosses Log uebersprungen' ($big.RowCount -eq 0 -and ($impBig.Warnings -join ' ') -match 'zu gross')
    $script:SmDnsLimits.MaxLogBytes = $lim.MaxLogBytes; $script:SmDnsLimits.MaxZipEntries = 2
    Check 'ZIP Limit: zu viele Eintraege abgelehnt' (Throws { Import-SmDnsZip -Log (New-SmDnsLog) -Path $zip2 })
    $script:SmDnsLimits.MaxZipEntries = $lim.MaxZipEntries; $script:SmDnsLimits.MaxZipBytes = 100
    Check 'ZIP Limit: zu grosse ZIP-Datei abgelehnt' (Throws { Import-SmDnsZip -Log (New-SmDnsLog) -Path $zip1 })
}
finally { foreach ($k in $lim.Keys) { $script:SmDnsLimits[$k] = $lim[$k] } }
$ms = New-Object SmLimitStream (New-Object IO.MemoryStream (, (New-Object byte[] 5000))), 1000
Check 'Limit-Strom: bricht ab, wenn mehr entpackt wird als erlaubt (auch bei falscher Groessenangabe im ZIP)' (Throws { $buf = New-Object byte[] 400; while ($ms.Read($buf, 0, 400) -gt 0) { } })
# Gelesene Bytes werden ueber alle Eintraege gezaehlt (gemeinsames Budget), nicht nur je Eintrag
$bud = New-Object SmByteBudget -ArgumentList 1000
$b1 = New-Object SmLimitStream (New-Object IO.MemoryStream (, (New-Object byte[] 800))), 5000, $bud
$b2 = New-Object SmLimitStream (New-Object IO.MemoryStream (, (New-Object byte[] 800))), 5000, $bud
$rd1 = New-Object byte[] 800
$first = $b1.Read($rd1, 0, 800)
Check 'Byte-Budget: zwei Eintraege, jeder unter seinem Limit, zusammen ueber dem Gesamtlimit: der zweite bricht ab' ($first -eq 800 -and $bud.Used -eq 800 -and (Throws { $x = New-Object byte[] 800; [void]$b2.Read($x, 0, 800) }))
$lim2 = $script:SmDnsLimits.Clone()
try {
    $script:SmDnsLimits.MaxTotalBytes = 600
    $twoLogs = Join-Path $work 'two.zip'
    New-TestZip $twoLogs @{ 'a.log' = $logText; 'b.log' = $logText }
    Check 'ZIP: Gesamtlimit ueber alle Logs wird erzwungen' (Throws { Import-SmDnsZip -Log (New-SmDnsLog) -Path $twoLogs })
}
finally { foreach ($k in $lim2.Keys) { $script:SmDnsLimits[$k] = $lim2[$k] } }
$longName = Join-Path $work 'longname.zip'
New-TestZip $longName @{ (('a' * 300) + '.log') = $logText; 'dns.log' = $logText }
$lnl = New-SmDnsLog; $lni = Import-SmDnsZip -Log $lnl -Path $longName
Check 'ZIP: Eintragsname ueber 255 Zeichen wird uebersprungen, Warnung ohne den langen Namen' ($lnl.RowCount -eq 11 -and ($lni.Warnings -join ' ') -match 'zu langem Namen' -and (($lni.Warnings -join ' ').Length -lt 300))
$longDomain = '(63)' + ('a' * 63) + '(63)' + ('b' * 63) + '(63)' + ('c' * 63) + '(63)' + ('d' * 63) + '(5)local(0)'
$lg = Parse-Lines @((L '22.11.2026' '10:00:00' 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' $longDomain)) -Name 'longname.log'
Check 'Namen werden auf 255 Zeichen begrenzt' ($lg.RowCount -eq 1 -and (Raw $lg)[0].Name.Length -eq 255)
# Namenstabellen haben eine feste Obergrenze, der Rest wird als (weitere) gezaehlt
$oldMaxN = [SmDnsLog]::MaxNames; $oldMaxI = [SmDnsLog]::MaxIps
try {
    [SmDnsLog]::MaxNames = 5; [SmDnsLog]::MaxIps = 3
    $many = 1..20 | ForEach-Object { (L '22.11.2026' ('10:00:{0:00}' -f $_) 'Rcv' ('10.0.0.' + $_) ('a{0:000}' -f $_) '' 'Q' '0001' 'D' 'NOERROR' 'A' ('(3)n{0:00}(5)local(0)' -f $_)) }
    $ml = Parse-Lines $many -Name 'many.log'
    $mr = Raw $ml
    Check 'Tabellen: Obergrenze fuer Namen und IPs, alle Zeilen bleiben, Rest als (weitere)' ($ml.RowCount -eq 20 -and $ml.Names.Count -le 6 -and $ml.Ips.Count -le 4 -and $ml.Names[0] -eq '(weitere)' -and @($mr | Where-Object { $_.Name -eq '(weitere)' }).Count -eq 16 -and @($mr | Where-Object { $_.Ip -eq '(weitere)' }).Count -eq 18)
    Check 'Tabellen: Auswertung laeuft mit der Obergrenze weiter (Clients, Namen)' (@($ml.Query('Clients', '')).Count -ge 3 -and @($ml.Query('Namen', '')).Count -ge 4)
}
finally { [SmDnsLog]::MaxNames = $oldMaxN; [SmDnsLog]::MaxIps = $oldMaxI }
# Regex: kein quadratisches Backtracking, Zeitlimit je Zeile
Check 'Regex: Zeitlimit je Zeile gesetzt' ([SmDnsLog]::MatchTimeout.TotalMilliseconds -gt 0 -and [SmDnsLog]::MatchTimeout.TotalSeconds -le 10)
$gap = (' ' * 700)
$evilLines = 1..400 | ForEach-Object { (L '22.11.2026' '10:00:00' 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' ("a${gap}b${gap}c${gap}d")) + (' ' * 700) }
$evilFile = Join-Path $work 'evil-spaces.log'; Write-Log $evilFile $evilLines
$swE = [Diagnostics.Stopwatch]::StartNew()
$el = New-SmDnsLog; $el.ParseFile($evilFile, $null)
$swE.Stop()
Check ("Regex: Zeilen mit langen Leerraeumen (Leerzeichen im Namen und am Ende) werden in {0:N1} s gelesen, Ende abgeschnitten" -f $swE.Elapsed.TotalSeconds) ($el.RowCount -eq 400 -and $swE.Elapsed.TotalSeconds -lt 8 -and (Raw $el)[0].Name.Length -eq 255 -and (Raw $el)[0].Name.StartsWith('a' + $gap.Substring(0, 50)))
$capLog = New-SmDnsLog -MaxRows 5
$capLog.ParseFile((Join-Path $work 'clients.log'), $null)
Check 'Zeilenlimit: Parser haelt bei MaxRows an und meldet gekuerzt' ($capLog.RowCount -eq 5 -and $capLog.Truncated)
$longLine = Join-Path $work 'long.log'
Write-Log $longLine @(('22.11.2026 10:00:00 0F30 PACKET  ' + ('A' * 20000)), (OneLine '22.11.2026' '10:00:01'))
$ll = New-SmDnsLog; $ll.ParseFile($longLine, $null)
Check 'Zu lange Zeile wird uebersprungen, die naechste gelesen' ($ll.RowCount -eq 1 -and $ll.Skipped -ge 1)
$emp = New-SmDnsLog; $empF = Join-Path $work 'empty.log'; [IO.File]::WriteAllBytes($empF, [byte[]]@()); $emp.ParseFile($empF, $null)
Check 'Leere Datei: keine Pakete, kein Fehler' ($emp.RowCount -eq 0 -and -not $emp.HasData)
$locked = Join-Path $work 'locked.log'
$ws = [IO.File]::Open($locked, 'Create', 'Write', 'ReadWrite, Delete')
try {
    $b = [Text.Encoding]::ASCII.GetBytes(($de -join "`r`n") + "`r`n"); $ws.Write($b, 0, $b.Length); $ws.Flush()
    $lk = New-SmDnsLog; $lk.ParseFile($locked, $null)
    Check 'Parser liest auch eine Datei, die ein anderer Prozess offen haelt' ($lk.RowCount -eq 11)
}
finally { $ws.Dispose() }

# ---------------------------------------------------------------- 8. Geschwindigkeit
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text;
public static class SmTestGen {
    static string Enc(string n) { StringBuilder sb = new StringBuilder(); foreach (string p in n.Split('.')) { sb.Append('(').Append(p.Length).Append(')').Append(p); } return sb.Append("(0)").ToString(); }
    public static long Generate(string path, long targetBytes, string style, int seed) {
        Random r = new Random(seed); long written = 0; long lines = 0;
        string[] pop = new string[60]; for (int i = 0; i < pop.Length; i++) pop[i] = Enc("srv" + i + ".contoso.local");
        string[] tail = new string[30000]; for (int i = 0; i < tail.Length; i++) tail[i] = Enc("host" + i + ".dept" + (i % 50) + ".contoso.local");
        string[] types = { "A", "AAAA", "PTR", "SRV", "MX", "TXT", "SOA" };
        DateTime t = new DateTime(2026, 11, 20, 8, 0, 0);
        using (StreamWriter w = new StreamWriter(path, false, Encoding.ASCII, 1 << 20)) {
            w.Write("DNS Server log file creation at 20.11.2026 08:00:00\r\n");
            while (written < targetBytes) {
                if (r.Next(40) == 0) t = t.AddSeconds(1);
                int c = r.Next(3000); string ip = "10." + (1 + c / 250) + "." + (c % 250) + "." + (1 + r.Next(250));
                if (r.Next(200) == 0) ip = "10.0.0.2";
                string name = r.Next(3) == 0 ? tail[r.Next(tail.Length)] : pop[r.Next(pop.Length)];
                string type = types[r.Next(types.Length)];
                string xid = r.Next(65536).ToString("x4");
                string date; string time;
                if (style == "us") { date = t.ToString("M/d/yyyy", System.Globalization.CultureInfo.InvariantCulture); time = t.ToString("h:mm:ss tt", System.Globalization.CultureInfo.InvariantCulture); }
                else if (style == "iso") { date = t.ToString("yyyy-MM-dd"); time = t.ToString("HH:mm:ss"); }
                else { date = t.ToString("dd.MM.yyyy"); time = t.ToString("HH:mm:ss"); }
                bool nx = r.Next(50) == 0;
                string q = date + " " + time + " 0F30 PACKET  000001A2B3C4D5E6 UDP Rcv " + ip.PadRight(15) + " " + xid + "   Q [0001   D   NOERROR] " + type.PadRight(6) + " " + name + "\r\n";
                string a = date + " " + time + " 0F30 PACKET  000001A2B3C4D5E6 UDP Snd " + ip.PadRight(15) + " " + xid + " R Q [8081   DR  " + (nx ? "NXDOMAIN" : "NOERROR ") + "] " + type.PadRight(6) + " " + name + "\r\n";
                w.Write(q); w.Write(a); written += q.Length + a.Length; lines += 2;
            }
        }
        return lines;
    }
}
'@
$bigFile = Join-Path $work 'big.log'
$gen = [SmTestGen]::Generate($bigFile, [long]$LargeMB * 1MB, 'de', 42)
$bigSize = (Get-Item $bigFile).Length
$sw = [Diagnostics.Stopwatch]::StartNew()
$bl = New-SmDnsLog; $bl.ParseFile($bigFile, $null)
$sw.Stop()
$secs = [math]::Max(0.001, $sw.Elapsed.TotalSeconds)
$mbs = ($bigSize / 1MB) / $secs
Write-Host ('INFO Geschwindigkeit: {0:N0} MB, {1:N0} Zeilen in {2:N1} s = {3:N0} Zeilen/s, {4:N1} MB/s, hochgerechnet 500 MB in {5:N0} s' -f ($bigSize / 1MB), $gen, $secs, ($gen / $secs), $mbs, (500 / $mbs)) -ForegroundColor Cyan
Check "Geschwindigkeit: alle Zeilen gelesen ($($bl.RowCount) von $gen)" ($bl.RowCount -eq $gen)
Check 'Geschwindigkeit: hochgerechnet 500 MB in unter 3 Minuten' ((500 / $mbs) -lt 180)
$sw.Restart()
$bc = @($bl.Query('Clients', '')); $be = @($bl.Query('Fehler', '')); $bn = @($bl.Query('Namen', '')); [void]$bl.GetPage('Roh', 'srv7', 5000)
$sw.Stop()
Write-Host ('INFO Auswertung (Clients, Fehler, Namen, Zonen, Typen, Rohfilter): {0:N1} s, {1:N0} Clients, {2:N0} Fehlerzeilen' -f $sw.Elapsed.TotalSeconds, $bc.Count, $be.Count) -ForegroundColor Cyan
Check 'Auswertung des grossen Logs: Clients, Fehler und Namen vorhanden, DC (10.0.0.2) steht vorn' ($bc.Count -gt 1000 -and $be.Count -gt 0 -and $bn.Count -gt 1000 -and $bc[0].Ip -eq '10.0.0.2')
$usGen = Join-Path $work 'us.log'; [void][SmTestGen]::Generate($usGen, 2MB, 'us', 7)
$ul = New-SmDnsLog; $ul.ParseFile($usGen, $null)
Check 'Erzeugtes Log im US-Format (M/d/yyyy h:mm:ss tt) wird gelesen' ($ul.RowCount -gt 10000 -and $ul.DetectedOrder -eq 'MDY' -and $ul.Skipped -eq 0 -and $ul.FirstText.StartsWith('2026-11-20'))
$isoGen = Join-Path $work 'iso.log'; [void][SmTestGen]::Generate($isoGen, 2MB, 'iso', 8)
$il = New-SmDnsLog; $il.ParseFile($isoGen, $null)
Check 'Erzeugtes Log im ISO-Format wird gelesen' ($il.RowCount -gt 10000 -and $il.DetectedOrder -eq 'YMD' -and $il.Skipped -eq 0)
Remove-Item $bigFile -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 9. Fehler aus #8: Gegentests gegen den Altbestand (aus git) und der neue Aufsatz
$oldText = $null
try { $oldText = (& git -C $repo show 3326a3c:DNSParser.ps1 2>$null) -join "`n" } catch { }
$small = Join-Path $work 'compat.log'
Write-Log $small @(
    (L '22.11.2026' '14:05:09' 'Snd' '10.0.0.15' 'a3f2' 'R' 'Q' '8081' 'DR' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:10' 'Rcv' '10.0.0.16' 'b001' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(12)abcdefghijkl(7)contoso(5)local(0)')
    (L '22.11.2026' '14:05:11' 'Rcv' '10.0.0.17' 'b002' '' 'Q' '0001' 'D' 'NOERROR' 'AAAA' '(3)www(7)contoso(5)local(0)'))
$usSmall = Join-Path $work 'compat-us.log'
Write-Log $usSmall @((L '11/22/2026' '2:05:09 PM' 'Rcv' '10.0.0.16' 'b001' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)'), (L '11/22/2026' '2:05:10 PM' 'Rcv' '10.0.0.16' 'b002' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)www(7)contoso(5)local(0)'))
if ($oldText) {
    $oldScript = Join-Path $work 'old-runner.ps1'
    $patched = $oldText.Replace('$FileNames = Read-OpenFileDialog C:\Temp -AllowMultiSelect', '$FileNames = [pscustomobject]@{ FileName = $env:SM_OLD_LOG }')
    [IO.File]::WriteAllText($oldScript, $patched, [Text.Encoding]::UTF8)
    $env:SM_OLD_LOG = $small
    $ErrorActionPreference = 'Continue'
    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $oldScript 2>&1
    $oldRows = @(Import-Clixml ($small + 'Parsed.XML'))
    $oldQ = @($oldRows | Where-Object { $_.SendReceiveIdentifier -eq 'Rcv' })
    Check 'Altbestand (Gegentest vor der Korrektur): Tippfehler $QueryRespond, Query-Zeilen haben kein/falsches QueryOrRespond' (@($oldQ | Where-Object { $_.QueryOrRespond -ne 'Query' }).Count -ge 1)
    Check 'Altbestand (Gegentest): zweistellige Namenslaenge bleibt unaufgeloest' (@($oldRows | Where-Object { $_.QuestionName -match '\(12\)' }).Count -eq 1)
    $env:SM_OLD_LOG = $usSmall
    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $oldScript 2>&1
    $ErrorActionPreference = 'Stop'
    $oldUs = @(Import-Clixml ($usSmall + 'Parsed.XML'))
    Check 'Altbestand (Gegentest): Datum fest dd.MM.yyyy, US-Format liefert keine Zeit' (@($oldUs | Where-Object { -not $_.LogTime }).Count -ge 1)
    if ($CompareOld) {
        # Optional (-CompareOld): alter und neuer Parser auf derselben Datei, Zeiten werden ausgegeben. Standard 1 MB, damit es schnell bleibt.
        $cmpLog = Join-Path $work 'compare.log'
        $cmpLines = [SmTestGen]::Generate($cmpLog, [long]$CompareMB * 1MB, 'de', 11)
        $env:SM_OLD_LOG = $cmpLog
        $ErrorActionPreference = 'Continue'
        $swO = [Diagnostics.Stopwatch]::StartNew()
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $oldScript 2>&1
        $swO.Stop()
        $oldCmp = @(Import-Clixml ($cmpLog + 'Parsed.XML'))
        Remove-Item ($cmpLog + 'Parsed.XML') -Force -ErrorAction SilentlyContinue
        $swN = [Diagnostics.Stopwatch]::StartNew()
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'DNSParser.ps1') -Path $cmpLog 2>&1
        $swN.Stop()
        $ErrorActionPreference = 'Stop'
        $newCmp = @(Import-Clixml ($cmpLog + 'Parsed.XML'))
        Remove-Item ($cmpLog + 'Parsed.XML') -Force -ErrorAction SilentlyContinue
        $swI = [Diagnostics.Stopwatch]::StartNew()
        $cl = New-SmDnsLog; $cl.ParseFile($cmpLog, $null)
        $swI.Stop()
        $cmpMb = (Get-Item $cmpLog).Length / 1MB
        Write-Host ('INFO Vergleich {0:N1} MB, {1:N0} Zeilen: alter Parser {2:N1} s, neuer Parser (DNSParser.ps1 als Prozess, mit Start) {3:N1} s, nur die Engine im Prozess {4:N2} s, Faktor alt/neu {5:N0}x' -f $cmpMb, $cmpLines, $swO.Elapsed.TotalSeconds, $swN.Elapsed.TotalSeconds, $swI.Elapsed.TotalSeconds, ($swO.Elapsed.TotalSeconds / [math]::Max(0.001, $swN.Elapsed.TotalSeconds))) -ForegroundColor Cyan
        Check ("Vergleich: gleiche Zeilenzahl (alt $($oldCmp.Count), neu $($newCmp.Count), Engine $($cl.RowCount))") ($oldCmp.Count -eq $cmpLines -and $newCmp.Count -eq $cmpLines -and $cl.RowCount -eq $cmpLines)
        Check 'Vergleich: neuer Parser ist nicht langsamer als der alte' ($swN.Elapsed.TotalSeconds -lt $swO.Elapsed.TotalSeconds)
        Remove-Item $cmpLog -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\SM_OLD_LOG -ErrorAction SilentlyContinue
}
else { Write-Host 'INFO git oder Altbestand (3326a3c) nicht verfuegbar, Gegentests gegen den Altbestand und der Vergleich alt/neu uebersprungen' -ForegroundColor Yellow }
if (-not $CompareOld) { Write-Host 'INFO Vergleich alter und neuer Parser: mit -CompareOld [-CompareMB n] einschaltbar (Standard aus)' -ForegroundColor DarkGray }
foreach ($pf in $small, $usSmall) { $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'DNSParser.ps1') -Path $pf 2>&1 }
$newRows = @(Import-Clixml ($small + 'Parsed.XML'))
$newQ = @($newRows | Where-Object { $_.SendReceiveIdentifier -eq 'Rcv' })
Check 'Neu: QueryOrRespond stimmt (Query/Respond), Opcode StandardQuery' ($newRows.Count -eq 3 -and @($newQ | Where-Object { $_.QueryOrRespond -eq 'Query' }).Count -eq 2 -and ($newRows | Where-Object SendReceiveIdentifier -eq 'Snd').QueryOrRespond -eq 'Respond' -and $newRows[0].Opcode -eq 'StandardQuery')
Check 'Neu: alte Eigenschaften bleiben (LogTime, RemoteIP, Xid, QuestionType, QuestionName ...)' ($newRows[0].LogTime -eq (New-Object DateTime 2026, 11, 22, 14, 5, 9) -and $newRows[0].RemoteIP -eq '10.0.0.15' -and $newRows[0].Xid -eq 'a3f2' -and $newRows[0].QuestionType -eq 'A' -and $newRows[0].QuestionName -eq 'www.contoso.local' -and $newRows[0].Responsecode -eq 'NOERROR' -and $newRows[0].TCPUDPIDENTIFIER -eq 'UDP' -and $newRows[0].Context -eq 'PACKET')
Check 'Neu: zweistellige Namenslaenge aufgeloest' ($newRows[1].QuestionName -eq 'abcdefghijkl.contoso.local')
$usRows = @(Import-Clixml ($usSmall + 'Parsed.XML'))
Check 'Neu: US-Datumsformat (M/d/yyyy h:mm:ss PM) wird gelesen' ($usRows.Count -eq 2 -and $usRows[0].LogTime -eq (New-Object DateTime 2026, 11, 22, 14, 5, 9))
$dfOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'DNSParser.ps1') -Path $usSmall -DateFormat 'M/d/yyyy' 2>&1 | Out-String
Check 'Neu: -DateFormat wird akzeptiert' ($dfOut -match 'Datum MDY')
$ErrorActionPreference = 'Continue'
$dfBad = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'DNSParser.ps1') -Path $usSmall -DateFormat 'quatsch' 2>&1 | Out-String
Check 'Neu: ungueltiges -DateFormat gibt eine klare Meldung' ($dfBad -match 'nicht lesbar')
$ErrorActionPreference = 'Stop'
$dnsText = Get-Content -LiteralPath (Join-Path $repo 'DNSParser.ps1') -Raw
Check 'Neu: kein += auf Arrays und kein Write-Host je Zeile im Aufsatz' (($dnsText -notmatch '\+=') -and ([regex]::Matches($dnsText, 'Write-Host')).Count -le 2)
$engine = Get-Content -LiteralPath (Join-Path $repo 'Modules\SmDns.ps1') -Raw
Check 'Parser: Streaming mit StreamReader und kompiliertem Regex, kein Get-Content, kein Write-Host' (($engine -match 'new StreamReader' -and $engine -match 'RegexOptions\.Compiled') -and ($engine -notmatch 'Get-Content') -and ($engine -notmatch 'Write-Host'))
Remove-Item ($small + 'Parsed.XML'), ($usSmall + 'Parsed.XML') -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 10. Server-Funktionen mit gemockten DnsServer-Cmdlets
$stateDir = Join-Path $work 'state'
$dnsDir = Join-Path $work 'dnsdir'; New-Item -ItemType Directory -Force $dnsDir | Out-Null
# Test-Umgebung: erlaubter Log-Ordner ist ein Testordner, im Sicherungsordner darf auch der aktuelle Benutzer stehen (die Tests laufen nicht als SYSTEM)
$script:SmDnsAllowedDirOverride = $dnsDir
$mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:SmDnsStateSidsOverride = @('S-1-5-32-544', 'S-1-5-18', $mySid)
# Get-DnsServerDiagnostics liefert 'Update', Set-DnsServerDiagnostics hat dafuer 'Updates' (Microsoft-Doku). MaxMBFileSize ist in Byte (Beispiel der Doku: 500000000).
$script:Diag = [pscustomobject]@{
    EnableLoggingToFile = $false; LogFilePath = (Join-Path $dnsDir 'dns.log'); MaxMBFileSize = [uint32]500000000
    Queries = $false; Answers = $true; SendPackets = $false; ReceivePackets = $false; UdpPackets = $false; TcpPackets = $true; Notifications = $false; Update = $false
    FullPackets = $false; IPFilterList = $null; EnableLogFileRollover = $false; UnmatchedResponse = $false; WriteThrough = $false; QuestionTransactions = $false
    EventLogLevel = [uint32]4; UseSystemEventLog = $false; SaveLogsToPersistentStorage = $false
}
$script:SetCalls = New-Object System.Collections.Generic.List[hashtable]
function Test-SmAdmin { $script:IsAdmin }
$script:IsAdmin = $true
function Get-DnsServerDiagnostics { [CmdletBinding()]param() $script:Diag }
function Set-DnsServerDiagnostics {
    # Parameterliste wie in der Microsoft-Doku. Der Parametersatz verlangt je mindestens einen aus jeder Gruppe.
    [CmdletBinding()]param(
        [bool]$Answers, [bool]$FullPackets, [string[]]$IPFilterList, [string]$LogFilePath, [uint32]$MaxMBFileSize, [bool]$EnableLogFileRollover, [bool]$EnableLoggingToFile,
        [bool]$UdpPackets, [bool]$TcpPackets, [bool]$UnmatchedResponse, [bool]$Updates, [bool]$WriteThrough, [bool]$Notifications, [bool]$Queries, [bool]$QuestionTransactions,
        [bool]$ReceivePackets, [bool]$SendPackets, [uint32]$EventLogLevel, [bool]$UseSystemEventLog, [bool]$SaveLogsToPersistentStorage, [string]$ComputerName, [switch]$PassThru)
    foreach ($g in @(@('ReceivePackets', 'SendPackets'), @('TcpPackets', 'UdpPackets'), @('Notifications', 'Updates', 'Queries'), @('QuestionTransactions', 'Answers'))) {
        if (-not ($g | Where-Object { $PSBoundParameters.ContainsKey($_) })) { throw "Der Parametersatz verlangt mindestens einen von: $($g -join ', ')" }
    }
    $copy = @{}; foreach ($k in $PSBoundParameters.Keys) { $copy[$k] = $PSBoundParameters[$k] }; $script:SetCalls.Add($copy)
    foreach ($k in $PSBoundParameters.Keys) {
        $prop = if ($k -eq 'Updates') { 'Update' } else { $k }
        if ($script:Diag.PSObject.Properties[$prop]) { $script:Diag.$prop = $PSBoundParameters[$k] }
    }
}
function Get-DnsServerForwarder { [CmdletBinding()]param() [pscustomobject]@{ IPAddress = @([ipaddress]'10.0.0.88', [ipaddress]'10.0.0.89'); UseRootHint = $false } }
function Get-DnsServerZone {
    [CmdletBinding()]param()
    [pscustomobject]@{ ZoneName = 'contoso.local'; ZoneType = 'Primary'; IsDsIntegrated = $true; IsReverseLookupZone = $false; SecondaryServers = @([ipaddress]'10.0.0.60'); NotifyServers = @([ipaddress]'10.0.0.61'); MasterServers = $null }
    [pscustomobject]@{ ZoneName = 'branch.contoso.local'; ZoneType = 'Forwarder'; IsDsIntegrated = $false; IsReverseLookupZone = $false; MasterServers = @([ipaddress]'10.0.0.50') }
    [pscustomobject]@{ ZoneName = '0.0.10.in-addr.arpa'; ZoneType = 'Primary'; IsDsIntegrated = $true; IsReverseLookupZone = $true; SecondaryServers = @(); MasterServers = $null }
}
function Get-ADDomainController { [CmdletBinding()]param([string]$Filter) [pscustomobject]@{ HostName = 'dc02.contoso.local'; Site = 'Default-First-Site-Name'; IPv4Address = '10.0.0.2'; IPv6Address = $null } }

$st = Get-SmDnsStatus
$good = Join-Path $dnsDir 'dns.log'
Check 'Status: Logging aus, Pfad, Pakete (nur die eingeschalteten, Update heisst im Set-Namen Updates)' (-not $st.LoggingOn -and $st.Path -eq $good -and ($st.Packets -join ',') -eq 'Answers,TcpPackets' -and -not $st.LogExists)
Check 'Status: MaxMBFileSize steht in Byte, die Anzeige rechnet in dezimalen MB (500000000 Byte = 500 MB, nicht 476,8)' ($st.MaxMB -eq 500 -and (ConvertFrom-SmDnsMaxBytes 500000000) -eq 500 -and (ConvertFrom-SmDnsMaxBytes 1500000) -eq 1.5)
Check 'Groesse: dezimale MB nach Byte (500 MB = 500000000, 1 MB = 1000000), Grenzen unter 4294 MB (uint32)' ((ConvertTo-SmDnsMaxBytes -MB 500) -eq 500000000 -and (ConvertTo-SmDnsMaxBytes -MB 1) -eq 1000000 -and (ConvertTo-SmDnsMaxBytes -MB 2048) -eq 2048000000 -and (ConvertTo-SmDnsMaxBytes -MB 4294) -eq 4294000000 -and (Throws { ConvertTo-SmDnsMaxBytes -MB 4295 }) -and (Throws { ConvertTo-SmDnsMaxBytes -MB 0 }) -and (ConvertTo-SmDnsMaxBytes -MB 500).GetType().Name -eq 'UInt32')
# Leerer LogFilePath bei aktivem Logging (Get-DnsServerDiagnostics liefert ihn nicht): Windows schreibt nach %windir%\System32\dns\dns.log (Fehler "Datei: , max. 476,8 MB", Karte zum Sammeln fehlte)
[IO.File]::WriteAllText($good, "DNS Server log file creation at 22.11.2026 10:00:00`r`n", [Text.Encoding]::ASCII)
$keepDiag = $script:Diag.PSObject.Copy(); $keepDefault = $script:SmDnsDefaultPath
$script:Diag.EnableLoggingToFile = $true; $script:Diag.LogFilePath = ''
$script:SmDnsDefaultPath = $good
$stE = Get-SmDnsStatus
Check 'Status: leerer LogFilePath bei aktivem Logging gilt als Windows-Standard (Pfad angezeigt, vollstaendiger Pfad, Datei gefunden, an)' ($stE.LoggingOn -and $stE.PathIsDefault -and $stE.Path -eq $good -and $stE.FullPath -eq $good -and $stE.LogExists -and $stE.LogBytes -gt 0 -and $stE.MaxMB -eq 500)
Check 'Pfad: leer, nur Leerraum und $null werfen nicht, sondern gelten als Standard' ((Test-SmDnsLogPath -Path '') -eq [IO.Path]::GetFullPath($good) -and (Test-SmDnsLogPath -Path '   ') -eq [IO.Path]::GetFullPath($good) -and (Test-SmDnsLogPath -Path $null) -eq [IO.Path]::GetFullPath($good))
$script:SmDnsDefaultPath = $keepDefault
$script:Diag.LogFilePath = [string]$keepDiag.LogFilePath; $script:Diag.EnableLoggingToFile = $false
Remove-Item -LiteralPath $good -Force
$script:SmDnsAllowedDirOverride = $null
Check 'Pfad: leerer Pfad ohne Ersatz = der Standard %windir%\System32\dns\dns.log (gleiche Pruefung, gleiche Meldung)' ($(
        $a = try { Test-SmDnsLogPath -Path '' } catch { $_.Exception.Message }
        $b = try { Test-SmDnsLogPath -Path $script:SmDnsDefaultPath } catch { $_.Exception.Message }
        $a -eq $b))
$script:SmDnsAllowedDirOverride = $dnsDir
# Pfad
Check 'Pfad: gueltiger Pfad (Kurznamen werden aufgeloest)' ((Test-SmDnsLogPath -Path $good) -eq [IO.Path]::GetFullPath($good))
$script:SmDnsAllowedDirOverride = $null
Check 'Pfad: Standard %windir%\System32\dns\dns.log wird aufgeloest' ($(try { $x = Test-SmDnsLogPath -Path $script:SmDnsDefaultPath; $x -match '(?i)\\System32\\dns\\dns\.log$' } catch { $_.Exception.Message -match 'Ordner existiert nicht' }))
$out506 = ''; try { [void](Test-SmDnsLogPath -Path 'C:\ProgramData\ServerMigration\dns.log') } catch { $out506 = $_.Exception.Message }
Check 'Pfad: nur %windir%\System32\dns erlaubt (Windows Server 2025, CU 2026-11, Event 506), anderer Ordner mit klarer Meldung abgelehnt' ($out506 -match 'System32' -and $out506 -match '506' -and (Throws { Test-SmDnsLogPath -Path 'D:\Logs\dns.log' }) -and (Throws { Test-SmDnsLogPath -Path 'C:\Windows\System32\dns\sub\dns.log' }) -and (Throws { Test-SmDnsLogPath -Path 'C:\Windows\System32\drivers\dns.log' }))
$script:SmDnsAllowedDirOverride = $dnsDir
Check 'Pfad: Unterordner und Nachbarordner des erlaubten Ordners abgelehnt' ((Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'sub\dns.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $work 'dns.log') }))
Check 'Pfad: UNC, relativ, .., Laufwerk ohne Ordner, falsche Endung, Sonderzeichen abgelehnt' ((Throws { Test-SmDnsLogPath -Path '\\server\share\dns.log' }) -and (Throws { Test-SmDnsLogPath -Path 'dns.log' }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir '..\dns.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'dns.exe') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'a;b.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'a$b.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'gibt\es\nicht.log') }) -and (Throws { Test-SmDnsLogPath -Path '%nichtda%\dns.log' }))
$other = Join-Path $dnsDir 'setupapi.log'; [IO.File]::WriteAllText($other, 'fremde Datei', [Text.Encoding]::ASCII)
Check 'Pfad: vorhandene Datei, die kein DNS-Log ist, wird nicht ueberschrieben' (Throws { Test-SmDnsLogPath -Path $other })
$own = Join-Path $dnsDir 'old.log'; [IO.File]::WriteAllText($own, 'DNS Server log file creation at 22.11.2026 14:00:00', [Text.Encoding]::ASCII)
Check 'Pfad: vorhandenes DNS-Log ist erlaubt' ((Test-SmDnsLogPath -Path $own) -eq [IO.Path]::GetFullPath($own))
# Vorpruefung
$plan = Get-SmDnsEnablePlan -Path $good -MaxMB '500'
Check 'Vorpruefung: ok, Pakete Queries, Answers, Send, Receive, UDP, TCP, Notify, Updates (Set-Name)' ($plan.Ok -and $plan.MaxMB -eq 500 -and ($plan.Packets -join ',') -eq 'Queries,Answers,SendPackets,ReceivePackets,UdpPackets,TcpPackets,Notifications,Updates')
Check 'Vorpruefung: Groesse ausserhalb 10-2048, Text, leer' (-not (Get-SmDnsEnablePlan -Path $good -MaxMB '5').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB '99999').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB 'abc').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB '').Ok)
Check 'Vorpruefung: Platz auf dem Laufwerk (2048 MB passen nicht auf ein volles Laufwerk)' ($(try { $fr = (New-Object IO.DriveInfo ($dnsDir.Substring(0, 1))).AvailableFreeSpace; if ($fr -gt 2300MB) { $true } else { -not (Get-SmDnsEnablePlan -Path $good -MaxMB '2048').Ok } } catch { $true }))
$script:IsAdmin = $false
$noAdmin = Get-SmDnsEnablePlan -Path $good -MaxMB '500'
Check 'Vorpruefung: ohne Administrator abgelehnt (klare Meldung: lokale Administratorrechte), und Einschalten verweigert' (-not $noAdmin.Ok -and ($noAdmin.Errors -join ' ') -match 'Administrator' -and ($noAdmin.Errors -join ' ') -match 'lokale Administratorrechte' -and (Throws { Enable-SmDnsLogging -Plan $noAdmin -StateDir $stateDir }) -and $script:SetCalls.Count -eq 0)
Check 'Einschalten: auch ein Plan, der vorher als ok galt, wird ohne Administratorrechte verweigert' ($plan.Ok -and (Throws { Enable-SmDnsLogging -Plan $plan -StateDir $stateDir }) -and $script:SetCalls.Count -eq 0)
$script:IsAdmin = $true
# Einschalten
$logLines = New-Object System.Collections.Generic.List[string]
Enable-SmDnsLogging -Plan $plan -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
$call = $script:SetCalls[0]
Check 'Einschalten: Set-DnsServerDiagnostics mit Pfad, Groesse in BYTE (500 MB = 500000000) und allen Paketen' ($call.EnableLoggingToFile -eq $true -and $call.LogFilePath -eq [IO.Path]::GetFullPath($good) -and $call.MaxMBFileSize -eq 500000000 -and $call.Queries -and $call.Answers -and $call.SendPackets -and $call.ReceivePackets -and $call.UdpPackets -and $call.TcpPackets -and $call.Notifications -and $call.Updates)
Check 'Einschalten: der Parameter heisst Updates (nicht Update) und kommt wirklich an (Mock mit der Parameterliste der Doku)' (-not $call.ContainsKey('Update') -and $script:Diag.Update -eq $true -and $script:Diag.MaxMBFileSize -eq 500000000)
Check 'Einschalten: Protokollzeile ohne Geheimnisse (Pfad, Groesse, Pakete)' (($logLines -join '|') -match 'DNS-Logging eingeschaltet' -and ($logLines -join '|') -match '500 MB' -and ($logLines -join '|') -notmatch '(?i)passw|kennwort|http|token')
$stateFile = Join-Path $stateDir 'dns-diagnostics-before.json'
$sv = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
Check 'Einschalten: vorheriger Zustand gesichert (Eigenschaftsnamen des Get, MaxMBFileSize in Byte)' ((Test-Path $stateFile) -and $sv.Values.EnableLoggingToFile -eq $false -and $sv.Values.Answers -eq $true -and $sv.Values.Queries -eq $false -and $sv.Values.Update -eq $false -and $sv.Values.MaxMBFileSize -eq 500000000 -and $sv.Values.LogFilePath -eq $good)
Check 'Sicherungsordner: nach dem Einschalten gehaertet (Besitzer und Zugriffsliste nur erlaubte Konten)' (@(Test-SmDnsStateDirAcl -Path $stateDir).Count -eq 0)
Check 'Status nach dem Einschalten: an' ((Get-SmDnsStatus).LoggingOn -and (Get-SmDnsStatus).MaxMB -eq 500)
# Ausschalten stellt wieder her
$script:SetCalls.Clear(); $logLines.Clear()
Disable-SmDnsLogging -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
$d = $script:SetCalls[0]
Check 'Ausschalten: EnableLoggingToFile false und der vorherige Zustand zurueck (Updates statt Update, Pfad, Byte-Groesse)' ($d.EnableLoggingToFile -eq $false -and $d.Queries -eq $false -and $d.Answers -eq $true -and $d.TcpPackets -eq $true -and $d.UdpPackets -eq $false -and $d.Updates -eq $false -and -not $d.ContainsKey('Update') -and $d.LogFilePath -eq [IO.Path]::GetFullPath($good) -and $d.MaxMBFileSize -eq 500000000)
Check 'Ausschalten: Diagnose ist wie vorher, gesicherte Datei entfernt, Protokollzeile' ((-not $script:Diag.EnableLoggingToFile) -and $script:Diag.Queries -eq $false -and $script:Diag.Answers -eq $true -and $script:Diag.MaxMBFileSize -eq 500000000 -and -not (Test-Path $stateFile) -and ($logLines -join '|') -match 'wiederhergestellt')
$script:SetCalls.Clear(); $logLines.Clear()
Disable-SmDnsLogging -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
Check 'Ausschalten ohne gesicherten Zustand: nur ausschalten, Pfad und Groesse unveraendert, Paketwerte durchgereicht (der Parametersatz verlangt sie), klare Meldung' ($script:SetCalls[0].EnableLoggingToFile -eq $false -and -not $script:SetCalls[0].ContainsKey('LogFilePath') -and -not $script:SetCalls[0].ContainsKey('MaxMBFileSize') -and $script:SetCalls[0].ContainsKey('Updates') -and $script:SetCalls[0].ContainsKey('ReceivePackets') -and ($logLines -join '|') -match 'keinen gesicherten Zustand')
# manipulierte Zustandsdatei
New-Item -ItemType Directory -Force $stateDir | Out-Null
[IO.File]::WriteAllText($stateFile, '{"Version":1,"Values":{"LogFilePath":"C:\\..\\Windows\\x.log","MaxMBFileSize":"abc","Queries":"ja","Answers":true,"Evil":"x"}}', [Text.Encoding]::ASCII)
$rs = Read-SmDnsState -StateDir $stateDir
Check 'Zustandsdatei manipuliert: ungueltige Werte werden verworfen, nur gepruefte uebernommen' ($rs.Keys.Count -eq 1 -and $rs['Answers'] -eq $true)
[IO.File]::WriteAllText($stateFile, 'kein json', [Text.Encoding]::ASCII)
Check 'Zustandsdatei kaputt: ignoriert' ($null -eq (Read-SmDnsState -StateDir $stateDir))
# wiederhergestellter LogFilePath geht durch dieselbe Pruefung wie Test-SmDnsLogPath (Ordner dns, Endung, Kopfzeile)
function Test-StateRestore([string]$LogPath) {
    [IO.File]::WriteAllText($stateFile, (@{ Version = 1; Values = @{ LogFilePath = $LogPath; Answers = $true } } | ConvertTo-Json -Depth 4), [Text.Encoding]::ASCII)
    (Read-SmDnsState -StateDir $stateDir)
}
$rsOk = Test-StateRestore $good
$rsOtherDir = Test-StateRestore 'C:\Windows\System32\drivers\etc\hosts'
$rsOtherDir2 = Test-StateRestore (Join-Path $work 'dns.log')
$rsExt = Test-StateRestore (Join-Path $dnsDir 'dns.exe')
$rsHead = Test-StateRestore $other
$rsOwn = Test-StateRestore $own
Check 'Zustand wiederherstellen: LogFilePath nur im Ordner dns, mit .log/.txt und DNS-Kopfzeile, sonst verworfen' ($rsOk['LogFilePath'] -eq [IO.Path]::GetFullPath($good) -and -not $rsOtherDir.Contains('LogFilePath') -and -not $rsOtherDir2.Contains('LogFilePath') -and -not $rsExt.Contains('LogFilePath') -and -not $rsHead.Contains('LogFilePath') -and $rsOwn['LogFilePath'] -eq [IO.Path]::GetFullPath($own) -and $rsHead['Answers'] -eq $true)
# Sicherungsordner: Besitzer und Zugriffsliste pruefen, Verknuepfungen ablehnen, ein fremdes Konto in der Zugriffsliste sperrt das Lesen
$badDir = Join-Path $work 'statebad'; New-Item -ItemType Directory -Force $badDir | Out-Null
$acl = Get-Acl -LiteralPath $badDir
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $badDir -AclObject $acl
$problems = @(Test-SmDnsStateDirAcl -Path $badDir)
Check 'Sicherungsordner: Zugriff fuer "Jeder" wird erkannt' ($problems.Count -ge 1 -and ($problems -join ' ') -match 'S-1-1-0')
[IO.File]::WriteAllText((Join-Path $badDir 'dns-diagnostics-before.json'), '{"Version":1,"Values":{"Answers":true}}', [Text.Encoding]::ASCII)
Check 'Sicherungsordner: Zustandsdatei in einem ungesicherten Ordner wird nicht gelesen' ($null -eq (Read-SmDnsState -StateDir $badDir))
Protect-SmDnsStateDir -Path $badDir
Check 'Sicherungsordner: Protect setzt Besitzer und Zugriffsliste neu und prueft sie (danach lesbar)' (@(Test-SmDnsStateDirAcl -Path $badDir).Count -eq 0 -and (Read-SmDnsState -StateDir $badDir)['Answers'] -eq $true)
$ownerSid = (Get-Acl -LiteralPath $badDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
Check 'Sicherungsordner: nur erlaubte Konten in der Zugriffsliste, Vererbung aus ProgramData aus' ((Get-Acl -LiteralPath $badDir).AreAccessRulesProtected -and (@((Get-Acl -LiteralPath $badDir).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -notin $script:SmDnsStateSidsOverride }).Count -eq 0) -and $ownerSid -in $script:SmDnsStateSidsOverride)
$strict = @(Test-SmDnsStateDirAcl -Path $badDir -AllowedSids @('S-1-5-18'))
Check 'Sicherungsordner: ein nicht erlaubter Besitzer oder Eintrag fuehrt zum Abbruch (nur SYSTEM erlaubt: Test meldet Probleme)' ($strict.Count -ge 1)
$junctionTarget = Join-Path $work 'junction-target'; New-Item -ItemType Directory -Force $junctionTarget | Out-Null
$junction = Join-Path $work 'state-junction'
try { [void](New-Item -ItemType Junction -Path $junction -Target $junctionTarget) } catch { }
if (Test-Path $junction) {
    $cBefore = $script:SetCalls.Count
    Check 'Sicherungsordner: Verknuepfung (Junction) wird abgelehnt, nichts gesetzt' ((Throws { Protect-SmDnsStateDir -Path $junction }) -and (Throws { Save-SmDnsState -Before ([ordered]@{ EnableLoggingToFile = $false }) -StateDir $junction }) -and (Throws { Enable-SmDnsLogging -Plan $plan -StateDir $junction }) -and $script:SetCalls.Count -eq $cBefore)
    [IO.Directory]::Delete($junction)
}
else { Write-Host 'INFO Junction konnte nicht angelegt werden, Test uebersprungen' -ForegroundColor Yellow }
Remove-Item $stateFile -Force
# Metadaten
$mt = Get-SmDnsMeta
Check 'Metadaten: Servername, Zeitzone, Kultur, Datumsformat' ($mt.Server -eq $env:COMPUTERNAME -and $mt.TimeZone -and $mt.Culture -and $mt.DateFormat -and $mt.TimeFormat)
Check 'Metadaten: eigene IPs, Forwarder, bedingte Forwarder, Sekundaerserver, Zonen' ($mt.Forwarders -contains '10.0.0.88' -and $mt.ConditionalForwarders[0].Zone -eq 'branch.contoso.local' -and $mt.ConditionalForwarders[0].Servers -contains '10.0.0.50' -and ($mt.SecondaryServers[0].Servers -contains '10.0.0.60') -and ($mt.SecondaryServers[0].Servers -contains '10.0.0.61') -and $mt.Zones.Count -eq 3 -and $mt.PSObject -and $mt.Contains('OwnIps'))
Check 'Metadaten: Domaenencontroller mit IPs (AD-Modul gemockt)' ($mt.DomainControllers[0].Name -eq 'dc02.contoso.local' -and $mt.DomainControllers[0].Ips -contains '10.0.0.2')
Check 'Metadaten: ohne AD-Modul nur eine Warnung, kein Fehler' ($(try { $sb = { function Get-ADDomainController { throw 'nicht da' }; (Get-SmDnsMeta).Warnings -join '|' }; (& $sb) -match 'Domaenencontroller nicht lesbar' } catch { $false }))
# Logs hochladen: Datei offen gehalten, ZIP, Metadaten, Upload in Teilen (Send-SmShareFile gemockt)
$srvLog = Join-Path $dnsDir 'upload.log'
$ws2 = [IO.File]::Open($srvLog, 'Create', 'Write', 'ReadWrite, Delete')
$script:Uploaded = $null
function Send-SmShareFile { param($Share, [string]$Path, $ChunkSize, [scriptblock]$Progress, $Retries) $copy = Join-Path $script:work2 (Split-Path -Leaf $Path); Copy-Item -LiteralPath $Path -Destination $copy; $script:Uploaded = $copy; if ($Progress) { & $Progress 10 10 }; [pscustomobject]@{ Name = (Split-Path -Leaf $Path); Length = (Get-Item $Path).Length } }
$script:work2 = Join-Path $work 'uploaded'; New-Item -ItemType Directory -Force $script:work2 | Out-Null
try {
    $b = [Text.Encoding]::ASCII.GetBytes(($de -join "`r`n") + "`r`n"); $ws2.Write($b, 0, $b.Length); $ws2.Flush()
    $tmpRoot = Join-Path $work 'tmproot'; New-Item -ItemType Directory -Force $tmpRoot | Out-Null
    $prog = @(); $msgs = New-Object System.Collections.Generic.List[string]
    $remote = Publish-SmDnsLogs -Share ([pscustomobject]@{}) -LogPath $srvLog -TempRoot $tmpRoot -Progress { param($s, $t) $script:prog += , @($s, $t) } -Log { param($m) $msgs.Add($m) }
}
finally { $ws2.Dispose() }
Check 'Hochladen: Log wird gelesen, obwohl der DNS-Dienst (hier: ein Schreiber) sie offen haelt' ($remote -and $script:Uploaded -and (Test-Path $script:Uploaded))
Check 'Hochladen: Dateiname SM-DNS-<Server>-<Zeit>.zip (Whitelist)' ((Split-Path -Leaf $script:Uploaded) -match '^SM-DNS-[\w\-]+-\d{8}-\d{6}\.zip$')
$zz = [IO.Compression.ZipFile]::OpenRead($script:Uploaded)
try {
    $en = @($zz.Entries | ForEach-Object FullName)
    $rd = New-Object IO.StreamReader($zz.GetEntry('dns.log').Open()); $copied = $rd.ReadToEnd(); $rd.Dispose()
    $rm = New-Object IO.StreamReader($zz.GetEntry('meta.json').Open()); $mj = $rm.ReadToEnd(); $rm.Dispose()
}
finally { $zz.Dispose() }
Check 'Hochladen: ZIP enthaelt nur dns.log und meta.json, Log vollstaendig kopiert' (($en -join ',') -eq 'dns.log,meta.json' -and $copied -eq (($de -join "`r`n") + "`r`n"))
$pm = ConvertFrom-SmDnsMeta -Json $mj
Check 'Hochladen: meta.json laesst sich vom Berater-Tool lesen (Server, Forwarder, DC, Zonen)' ($pm.Server -eq $env:COMPUTERNAME -and $pm.Forwarders -contains '10.0.0.89' -and $pm.DomainControllers[0].Ips -contains '10.0.0.2' -and $pm.Zones.Count -eq 3 -and $pm.DateFormat)
Check 'Hochladen: Fortschritt gemeldet, Temp-Ordner aufgeraeumt, Protokoll ohne Geheimnisse' ($script:prog.Count -ge 1 -and @(Get-ChildItem -LiteralPath $tmpRoot).Count -eq 0 -and ($msgs -join '|') -match 'Im Tauschordner')
$ei = New-SmDnsLog; $e2 = Import-SmDnsZip -Log $ei -Path $script:Uploaded
Check 'Ende zu Ende: ZIP vom Server wird im Berater-Tool eingelesen und ausgewertet' ($ei.RowCount -eq 11 -and @($ei.Query('Clients', '')).Count -ge 5 -and $e2.Meta.Forwarders -contains '10.0.0.88')
$notLog = Join-Path $work 'notlog.log'; [IO.File]::WriteAllText($notLog, 'DNS Server log file creation (nicht)', [Text.Encoding]::ASCII)
$elsewhere = Join-Path $work 'elsewhere.log'; [IO.File]::WriteAllText($elsewhere, 'DNS Server log file creation at 22.11.2026 14:00:00', [Text.Encoding]::ASCII)
$script:Uploaded = $null
Check 'Hochladen: Pfad, Endung und Kopfzeile werden wie beim Einschalten geprueft (fremde Datei, anderer Ordner, falsche Endung, keine Kopfzeile)' ((Throws { Publish-SmDnsLogs -Share @{} -LogPath $other -TempRoot $tmpRoot }) -and (Throws { Publish-SmDnsLogs -Share @{} -LogPath $elsewhere -TempRoot $tmpRoot }) -and (Throws { $x = Join-Path $dnsDir 'x.exe'; [IO.File]::WriteAllText($x, 'DNS Server log file creation at x', [Text.Encoding]::ASCII); Publish-SmDnsLogs -Share @{} -LogPath $x -TempRoot $tmpRoot }) -and (Throws { Publish-SmDnsLogs -Share @{} -LogPath 'C:\Windows\System32\drivers\etc\hosts' -TempRoot $tmpRoot }) -and -not $script:Uploaded)
Check 'Hochladen: leere Datei und fehlende Datei abgelehnt' ((Throws { $e = Join-Path $dnsDir 'leer.log'; [IO.File]::WriteAllBytes($e, [byte[]]@()); Publish-SmDnsLogs -Share @{} -LogPath $e -TempRoot $tmpRoot }) -and (Throws { Publish-SmDnsLogs -Share @{} -LogPath (Join-Path $dnsDir 'nix.log') -TempRoot $tmpRoot }))
Remove-Item Function:\Send-SmShareFile -ErrorAction SilentlyContinue
. (Join-Path $repo 'Modules\SmTausch.ps1')

# ---------------------------------------------------------------- 11. Fenster: -ParseOnly beider Fenster (hell und dunkel)
foreach ($mode in 'Light', 'Dark') {
    foreach ($entry in @(@('Berater-Tool', 'Start-ServerMigration.ps1'), @('Server-Fenster', 'server\Start-SmServer.ps1'))) {
        $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $repo $entry[1]) -ParseOnly -Theme $mode 2>&1 | Out-String
        Check ("$($entry[0]) -ParseOnly ($mode): $($out.Trim())") ($out.Trim() -eq 'PARSE OK')
    }
}
$pk = Get-Content -LiteralPath (Join-Path $repo 'Modules\SmPaket.ps1') -Raw
Check 'Server-Paket enthaelt den DNS-Teil des Server-Fensters, nicht den Parser des Berater-Tools' ($pk -match "server/SmDnsServer\.ps1" -and $pk -match 'UI/DnsServer\.xaml' -and $pk -notmatch 'SmDns\.ps1' -and $pk -notmatch 'UI/Dns\.xaml')

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "$script:fails Fehler"
exit $script:fails
