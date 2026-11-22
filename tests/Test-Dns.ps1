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
#>
[CmdletBinding()]
param([int]$LargeMB = 40)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = Join-Path $env:TEMP ('sm-dns-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force $work | Out-Null
$script:fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

. (Join-Path $repo 'Modules\SmTausch.ps1')
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
foreach ($f in 'Modules\SmDns.ps1', 'Modules\SmDnsUi.ps1', 'server\SmDnsServer.ps1', 'tests\Test-Dns.ps1', 'DNSParser.ps1') {
    $p = Join-Path $repo $f
    $errs = $null; $tok = $null
    [void][Management.Automation.Language.Parser]::ParseFile($p, [ref]$tok, [ref]$errs)
    $bytes = [IO.File]::ReadAllBytes($p)
    Check "Syntax und Kodierung (ASCII oder UTF-8 mit BOM): $f" ((-not $errs) -and (($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) -or -not ($bytes | Where-Object { $_ -gt 127 } | Select-Object -First 1)))
}
foreach ($f in 'UI\Dns.xaml', 'UI\DnsServer.xaml') { Check "XAML laesst sich lesen: $f" ($(try { [xml](Get-Content -LiteralPath (Join-Path $repo $f) -Raw -Encoding UTF8) | Out-Null; $true } catch { $false })) }

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

# ---------------------------------------------------------------- 6. CSV (Formel-Injection, Checkliste 7)
Check 'CSV: = + - @ Tab CR bekommen Anfuehrungszeichen davor' ((@('=1+1', '+SUM(1)', '-2', '@A1', "`tx", "`rx") | ForEach-Object { [SmCsv]::Escape($_, ';') } | Where-Object { $_ -notmatch "^`"?'" }).Count -eq 0)
Check 'CSV: normaler Text bleibt, Trenner und Anfuehrungszeichen werden gequotet' ([SmCsv]::Escape('abc', ';') -eq 'abc' -and [SmCsv]::Escape('a;b', ';') -eq '"a;b"' -and [SmCsv]::Escape('a"b', ';') -eq '"a""b"' -and [SmCsv]::Escape("a`nb", ';') -eq "`"a`nb`"" -and [SmCsv]::Escape('', ';') -eq '')
$injLog = Join-Path $work 'inj.log'
Write-Log $injLog @(
    (L '22.11.2026' '10:00:00' 'Rcv' '10.0.0.15' 'a3f2' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(4)=cmd(5)local(0)')
    (L '22.11.2026' '10:00:01' 'Rcv' '10.0.0.15' 'a3f3' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(3)a;b(5)local(0)')
    (L '22.11.2026' '10:00:02' 'Rcv' '10.0.0.15' 'a3f4' '' 'Q' '0001' 'D' 'NOERROR' 'A' '(9)-1+cmd|zz(0)'))
$ci = New-SmDnsLog; $ci.ParseFile($injLog, $null)
$csv = Join-Path $work 'out.csv'
$n = $ci.Export('Roh', '', $csv, [char]';')
$text = [IO.File]::ReadAllText($csv, [Text.Encoding]::UTF8)
$csvBytes = [IO.File]::ReadAllBytes($csv)
Check 'CSV-Export Rohdaten: 3 Zeilen, UTF-8 mit BOM, Kopfzeile mit Leerzeichen' ($n -eq 3 -and $csvBytes[0] -eq 0xEF -and $text -match 'Zeit;Richtung;Protokoll;Ip;Art;Opcode;Flags;Flags Hex;Rcode;Typ;Name;Xid')
Check 'CSV-Export: gefaehrliche Namen sind entschaerft, Trenner gequotet' ($text -match ";'=cmd\.local;" -and $text -match ';"a;b\.local";' -and $text -match ";'-1\+cmd\|zz;" -and $text -notmatch ';=cmd' -and $text -notmatch ';-1\+cmd')
Check 'CSV-Export gefilterte Ansicht enthaelt nur Treffer' ($ci.Export('Roh', 'cmd', $csv, [char]';') -eq 2)
$csv2 = Join-Path $work 'out2.csv'
$m = Export-SmCsv -Items @([pscustomobject]@{ Name = '=evil'; Anzahl = 5 }, [pscustomobject]@{ Name = 'ok'; Anzahl = -3 }) -Path $csv2
$t2 = [IO.File]::ReadAllText($csv2, [Text.Encoding]::UTF8)
Check 'Export-SmCsv: Text entschaerft, Zahlen unveraendert (auch negative)' ($m -eq 2 -and $t2 -match "'=evil;5" -and $t2 -match 'ok;-3')

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
    Remove-Item Env:\SM_OLD_LOG -ErrorAction SilentlyContinue
}
else { Write-Host 'INFO git oder Altbestand (3326a3c) nicht verfuegbar, Gegentests gegen den Altbestand uebersprungen' -ForegroundColor Yellow }
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
$script:Diag = [pscustomobject]@{
    EnableLoggingToFile = $false; LogFilePath = 'C:\Windows\System32\dns\dns.log'; MaxMBFileSize = [uint32]500000000
    Queries = $false; Answers = $true; SendPackets = $false; ReceivePackets = $false; UdpPackets = $false; TcpPackets = $true; Notifications = $false; Update = $false
}
$script:SetCalls = New-Object System.Collections.Generic.List[hashtable]
function Test-SmAdmin { $script:IsAdmin }
$script:IsAdmin = $true
function Get-DnsServerDiagnostics { [CmdletBinding()]param() $script:Diag }
function Set-DnsServerDiagnostics {
    [CmdletBinding()]param([bool]$EnableLoggingToFile, [string]$LogFilePath, [uint32]$MaxMBFileSize, [bool]$Queries, [bool]$Answers, [bool]$SendPackets, [bool]$ReceivePackets, [bool]$UdpPackets, [bool]$TcpPackets, [bool]$Notifications, [bool]$Update)
    $h = @{}; foreach ($k in $PSBoundParameters.Keys) { if ($script:Diag.PSObject.Properties[$k]) { $h[$k] = $PSBoundParameters[$k] } }; $script:SetCalls.Add($h)
    foreach ($k in $h.Keys) { $script:Diag.$k = $h[$k] }
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
Check 'Status: Logging aus, Pfad, Pakete (nur die eingeschalteten)' (-not $st.LoggingOn -and $st.Path -eq 'C:\Windows\System32\dns\dns.log' -and ($st.Packets -join ',') -eq 'Answers,TcpPackets' -and -not $st.LogExists)
# Pfad
$good = Join-Path $dnsDir 'dns.log'
Check 'Pfad: gueltiger Pfad (Kurznamen werden aufgeloest)' ((Test-SmDnsLogPath -Path $good) -eq [IO.Path]::GetFullPath($good))
Check 'Pfad: Standard %windir%\System32\dns\dns.log wird aufgeloest' ($(try { $x = Test-SmDnsLogPath -Path $script:SmDnsDefaultPath; $x -match '(?i)\\System32\\dns\\dns\.log$' } catch { $_.Exception.Message -match 'Ordner existiert nicht' }))
Check 'Pfad: UNC, relativ, .., Laufwerk ohne Ordner, falsche Endung, Sonderzeichen abgelehnt' ((Throws { Test-SmDnsLogPath -Path '\\server\share\dns.log' }) -and (Throws { Test-SmDnsLogPath -Path 'dns.log' }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir '..\dns.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'dns.exe') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'a;b.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'a$b.log') }) -and (Throws { Test-SmDnsLogPath -Path (Join-Path $dnsDir 'gibt\es\nicht.log') }) -and (Throws { Test-SmDnsLogPath -Path '%nichtda%\dns.log' }))
$other = Join-Path $dnsDir 'setupapi.log'; [IO.File]::WriteAllText($other, 'fremde Datei', [Text.Encoding]::ASCII)
Check 'Pfad: vorhandene Datei, die kein DNS-Log ist, wird nicht ueberschrieben' (Throws { Test-SmDnsLogPath -Path $other })
$own = Join-Path $dnsDir 'old.log'; [IO.File]::WriteAllText($own, 'DNS Server log file creation at 22.11.2026 14:00:00', [Text.Encoding]::ASCII)
Check 'Pfad: vorhandenes DNS-Log ist erlaubt' ((Test-SmDnsLogPath -Path $own) -eq [IO.Path]::GetFullPath($own))
# Vorpruefung
$plan = Get-SmDnsEnablePlan -Path $good -MaxMB '500'
Check 'Vorpruefung: ok, Pakete Queries, Answers, Send, Receive, UDP, TCP, Notify, Update' ($plan.Ok -and $plan.MaxMB -eq 500 -and ($plan.Packets -join ',') -eq 'Queries,Answers,SendPackets,ReceivePackets,UdpPackets,TcpPackets,Notifications,Update')
Check 'Vorpruefung: Groesse ausserhalb 10-2048, Text, leer' (-not (Get-SmDnsEnablePlan -Path $good -MaxMB '5').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB '99999').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB 'abc').Ok -and -not (Get-SmDnsEnablePlan -Path $good -MaxMB '').Ok)
Check 'Vorpruefung: Platz auf dem Laufwerk (2048 MB passen nicht auf ein volles Laufwerk)' ($(try { $fr = (New-Object IO.DriveInfo ($dnsDir.Substring(0, 1))).AvailableFreeSpace; if ($fr -gt 2300MB) { $true } else { -not (Get-SmDnsEnablePlan -Path $good -MaxMB '2048').Ok } } catch { $true }))
$script:IsAdmin = $false
$noAdmin = Get-SmDnsEnablePlan -Path $good -MaxMB '500'
Check 'Vorpruefung: ohne Administrator abgelehnt, und Einschalten verweigert' (-not $noAdmin.Ok -and ($noAdmin.Errors -join ' ') -match 'Administrator' -and (Throws { Enable-SmDnsLogging -Plan $noAdmin -StateDir $stateDir }) -and $script:SetCalls.Count -eq 0)
$script:IsAdmin = $true
# Einschalten
$logLines = New-Object System.Collections.Generic.List[string]
Enable-SmDnsLogging -Plan $plan -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
$call = $script:SetCalls[0]
Check 'Einschalten: Set-DnsServerDiagnostics mit Pfad, Groesse und allen Paketen' ($call.EnableLoggingToFile -eq $true -and $call.LogFilePath -eq [IO.Path]::GetFullPath($good) -and $call.MaxMBFileSize -eq 500 -and $call.Queries -and $call.Answers -and $call.SendPackets -and $call.ReceivePackets -and $call.UdpPackets -and $call.TcpPackets -and $call.Notifications -and $call.Update)
Check 'Einschalten: Protokollzeile ohne Geheimnisse (Pfad, Groesse, Pakete)' (($logLines -join '|') -match 'DNS-Logging eingeschaltet' -and ($logLines -join '|') -match '500 MB' -and ($logLines -join '|') -notmatch '(?i)passw|kennwort|http|token')
$stateFile = Join-Path $stateDir 'dns-diagnostics-before.json'
$sv = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
Check 'Einschalten: vorheriger Zustand gesichert' ((Test-Path $stateFile) -and $sv.Values.EnableLoggingToFile -eq $false -and $sv.Values.Answers -eq $true -and $sv.Values.Queries -eq $false -and $sv.Values.LogFilePath -eq 'C:\Windows\System32\dns\dns.log')
Check 'Status nach dem Einschalten: an' ((Get-SmDnsStatus).LoggingOn -and (Get-SmDnsStatus).MaxMB -eq 500)
# Ausschalten stellt wieder her
$script:SetCalls.Clear(); $logLines.Clear()
Disable-SmDnsLogging -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
$d = $script:SetCalls[0]
Check 'Ausschalten: EnableLoggingToFile false und der vorherige Zustand zurueck' ($d.EnableLoggingToFile -eq $false -and $d.Queries -eq $false -and $d.Answers -eq $true -and $d.TcpPackets -eq $true -and $d.UdpPackets -eq $false -and $d.LogFilePath -eq 'C:\Windows\System32\dns\dns.log')
Check 'Ausschalten: Diagnose ist wie vorher, gesicherte Datei entfernt, Protokollzeile' ((-not $script:Diag.EnableLoggingToFile) -and $script:Diag.Queries -eq $false -and $script:Diag.Answers -eq $true -and $script:Diag.MaxMBFileSize -eq 500000000 -and -not (Test-Path $stateFile) -and ($logLines -join '|') -match 'wiederhergestellt')
$script:SetCalls.Clear(); $logLines.Clear()
Disable-SmDnsLogging -StateDir $stateDir -Log { param($m) $logLines.Add($m) }
Check 'Ausschalten ohne gesicherten Zustand: nur ausschalten, klare Meldung' ($script:SetCalls[0].Keys.Count -eq 1 -and $script:SetCalls[0].EnableLoggingToFile -eq $false -and ($logLines -join '|') -match 'keinen gesicherten Zustand')
# manipulierte Zustandsdatei
New-Item -ItemType Directory -Force $stateDir | Out-Null
[IO.File]::WriteAllText($stateFile, '{"Version":1,"Values":{"LogFilePath":"C:\\..\\Windows\\x.log","MaxMBFileSize":"abc","Queries":"ja","Answers":true,"Evil":"x"}}', [Text.Encoding]::ASCII)
$rs = Read-SmDnsState -StateDir $stateDir
Check 'Zustandsdatei manipuliert: ungueltige Werte werden verworfen, nur gepruefte uebernommen' ($rs.Keys.Count -eq 1 -and $rs['Answers'] -eq $true)
[IO.File]::WriteAllText($stateFile, 'kein json', [Text.Encoding]::ASCII)
Check 'Zustandsdatei kaputt: ignoriert' ($null -eq (Read-SmDnsState -StateDir $stateDir))
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
