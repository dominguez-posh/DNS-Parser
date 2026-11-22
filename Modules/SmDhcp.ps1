<#
.SYNOPSIS
    DHCP: Daten aus dem Tauschordner lesen und pruefen, Vorher-/Nachher-Vergleich, Seite DHCP des Berater-Tools.
.DESCRIPTION
    Wird per Dot-Source geladen (Berater-Tool und Server-Fenster; die Seite braucht Modules\SmShell.ps1 und SmTausch.ps1).
    Daten aus dem Tauschordner gelten als feindlich (Checkliste 7): Dateinamen nur nach Whitelist, Groessenlimits fuer ZIP, Eintrag und JSON,
    JSON nur als Daten (Tiefe begrenzt, danach Feld fuer Feld in eine neue Struktur uebernommen, alles Unbekannte verworfen),
    XML nur ohne DTD und ohne Resolver. Keine Objekt-Deserialisierung (kein Clixml).
    Die Zusammenfassung ("dhcp-summary.json", Format SmDhcpSummary 1) erzeugt server\SmDhcpServer.ps1.
    Der Export des Vergleichs geht ueber Export-SmTable (Modules\SmExport.ps1), sobald diese Datei da ist.
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmDhcpMaxZipBytes = 512MB        # Export-ZIP (mit Leases) aus dem Tauschordner
$script:SmDhcpMaxJsonBytes = 64MB        # Zusammenfassung (Datei oder ZIP-Eintrag)
$script:SmDhcpMaxXmlBytes = 1GB          # entpackte Export-XML
$script:SmDhcpMaxDepth = 24              # Verschachtelung im JSON
$script:SmDhcpMaxItems = 1000000         # Eintraege insgesamt (Optionen, Reservierungen, Ausschluesse ...)
$script:SmDhcpMaxScopes = 4096
$script:SmDhcpSummaryEntry = 'dhcp-summary.json'
$script:SmDhcpXmlEntry = 'dhcp-export.xml'

function Get-SmDhcpFileKind {
    <# 'Export' (ZIP vom alten Server), 'Nachher' (JSON vom neuen Server) oder $null. Nur diese Namen werden angefasst. #>
    param([string]$Name)
    if ($Name -match '^DHCP-Export-[A-Za-z0-9\-]{1,30}-\d{8}-\d{6}\.zip$') { return 'Export' }
    if ($Name -match '^DHCP-Nachher-[A-Za-z0-9\-]{1,30}-\d{8}-\d{6}\.json$') { return 'Nachher' }
    $null
}

function ConvertTo-SmDhcpText {
    <# Text aus fremden Daten: Steuerzeichen raus, Laenge begrenzt. #>
    param($Value, [int]$Max = 256)
    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { $Value = ($Value | ForEach-Object { [string]$_ }) -join ',' }
    $s = [regex]::Replace([string]$Value, '[\x00-\x1F\x7F]', ' ')
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    $s.Trim()
}

function Test-SmDhcpIp {
    <# $true, wenn Text eine gueltige IPv4- ('v4') bzw. IPv6-Adresse ('v6') ist. #>
    param([string]$Text, [ValidateSet('v4', 'v6')][string]$Family)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Text, [ref]$ip)) { return $false }
    if ($Family -eq 'v4') { return ($ip.AddressFamily -eq 'InterNetwork' -and $Text -match '^\d{1,3}(\.\d{1,3}){3}$') }
    $ip.AddressFamily -eq 'InterNetworkV6'
}

function Test-SmDhcpJsonDepth {
    <# Verschachtelungstiefe des JSON-Textes (Klammern ausserhalb von Zeichenketten), bevor er geparst wird. #>
    param([Parameter(Mandatory)][string]$Text, [int]$Max = $script:SmDhcpMaxDepth)
    $d = 0; $inStr = $false; $esc = $false
    foreach ($c in $Text.ToCharArray()) {
        if ($inStr) {
            if ($esc) { $esc = $false } elseif ($c -eq '\') { $esc = $true } elseif ($c -eq '"') { $inStr = $false }
            continue
        }
        if ($c -eq '"') { $inStr = $true }
        elseif ($c -eq '{' -or $c -eq '[') { $d++; if ($d -gt $Max) { return $false } }
        elseif ($c -eq '}' -or $c -eq ']') { $d-- }
    }
    $true
}

function Get-SmDhcpProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj -or $Obj -is [string] -or $Obj -is [array]) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function ConvertTo-SmDhcpList {
    param($Value, [string]$What, [int]$Max = 100000)
    if ($null -eq $Value) { return @() }
    $a = @($Value)
    if ($a.Count -gt $Max) { throw "Zusammenfassung ungueltig: zu viele Eintraege ($What)." }
    $script:SmDhcpItemCount += $a.Count
    if ($script:SmDhcpItemCount -gt $script:SmDhcpMaxItems) { throw 'Zusammenfassung ungueltig: zu viele Eintraege insgesamt.' }
    , $a
}

function ConvertTo-SmDhcpOptions {
    param($List, [string]$What)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in (ConvertTo-SmDhcpList $List $What)) {
        $id = 0
        if (-not [int]::TryParse([string](Get-SmDhcpProp $o 'Id'), [ref]$id) -or $id -lt 0 -or $id -gt 65535) { throw "Zusammenfassung ungueltig: Optionsnummer ($What)." }
        $out.Add([ordered]@{ Id = $id; Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $o 'Name') 100); Value = (ConvertTo-SmDhcpText (Get-SmDhcpProp $o 'Value') 1024) })
    }
    , $out.ToArray()
}

function ConvertTo-SmDhcpRanges {
    param($List, [string]$What, [string]$Family)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (ConvertTo-SmDhcpList $List $What)) {
        $s = ConvertTo-SmDhcpText (Get-SmDhcpProp $r 'Start') 64; $e = ConvertTo-SmDhcpText (Get-SmDhcpProp $r 'End') 64
        if (-not (Test-SmDhcpIp $s $Family) -or -not (Test-SmDhcpIp $e $Family)) { throw "Zusammenfassung ungueltig: Adresse ($What)." }
        $out.Add([ordered]@{ Start = $s; End = $e })
    }
    , $out.ToArray()
}

function ConvertTo-SmDhcpReservations {
    param($List, [string]$What, [string]$Family)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (ConvertTo-SmDhcpList $List $What)) {
        $ip = ConvertTo-SmDhcpText (Get-SmDhcpProp $r 'Ip') 64
        if (-not (Test-SmDhcpIp $ip $Family)) { throw "Zusammenfassung ungueltig: Reservierungsadresse ($What)." }
        $out.Add([ordered]@{ Ip = $ip; ClientId = (ConvertTo-SmDhcpText (Get-SmDhcpProp $r 'ClientId') 128); Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $r 'Name') 256) })
    }
    , $out.ToArray()
}

function ConvertTo-SmDhcpInt {
    param($Value, [string]$What)
    $n = 0L
    if ($null -eq $Value) { return 0L }
    if (-not [long]::TryParse([string]$Value, [ref]$n) -or $n -lt 0) { throw "Zusammenfassung ungueltig: Zahl ($What)." }
    $n
}

function ConvertTo-SmDhcpSummary {
    <#
    .SYNOPSIS
        Prueft ein aus JSON gelesenes Objekt und baut daraus Feld fuer Feld eine neue, saubere Struktur (Format SmDhcpSummary, Version 1).
        Wirft bei falschem Format, ungueltigen Adressen oder zu vielen Eintraegen. Unbekannte Felder werden verworfen.
    #>
    param([Parameter(Mandatory)]$Obj)
    $script:SmDhcpItemCount = 0
    if ($null -eq $Obj -or $Obj -is [string] -or $Obj -is [array]) { throw 'Zusammenfassung ungueltig: kein Objekt.' }
    if ((Get-SmDhcpProp $Obj 'Format') -ne 'SmDhcpSummary' -or [string](Get-SmDhcpProp $Obj 'Version') -ne '1') { throw 'Das ist keine DHCP-Zusammenfassung (Format SmDhcpSummary, Version 1).' }
    $server = ConvertTo-SmDhcpText (Get-SmDhcpProp $Obj 'Server') 255
    $s4 = New-Object System.Collections.Generic.List[object]
    foreach ($s in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Scopes4') 'Bereiche v4' $script:SmDhcpMaxScopes)) {
        $id = ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'ScopeId') 64
        if (-not (Test-SmDhcpIp $id 'v4')) { throw 'Zusammenfassung ungueltig: Bereichs-ID (v4).' }
        $mask = ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'Mask') 64
        if ($mask -and -not (Test-SmDhcpIp $mask 'v4')) { throw 'Zusammenfassung ungueltig: Subnetzmaske.' }
        $start = ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'Start') 64; $end = ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'End') 64
        if (($start -and -not (Test-SmDhcpIp $start 'v4')) -or ($end -and -not (Test-SmDhcpIp $end 'v4'))) { throw 'Zusammenfassung ungueltig: Adressbereich.' }
        $s4.Add([ordered]@{
                ScopeId = $id; Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'Name') 256); Mask = $mask; Start = $start; End = $end
                State = (ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'State') 32); LeaseDuration = (ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'LeaseDuration') 64)
                Leases = (ConvertTo-SmDhcpInt (Get-SmDhcpProp $s 'Leases') 'Leases')
                Options = (ConvertTo-SmDhcpOptions (Get-SmDhcpProp $s 'Options') 'Bereichsoptionen')
                Reservations = (ConvertTo-SmDhcpReservations (Get-SmDhcpProp $s 'Reservations') 'Reservierungen' 'v4')
                Exclusions = (ConvertTo-SmDhcpRanges (Get-SmDhcpProp $s 'Exclusions') 'Ausschluesse' 'v4')
                Policies = @(ConvertTo-SmDhcpList (Get-SmDhcpProp $s 'Policies') 'Richtlinien' | ForEach-Object { ConvertTo-SmDhcpText $_ 256 })
            })
    }
    $s6 = New-Object System.Collections.Generic.List[object]
    foreach ($s in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Scopes6') 'Bereiche v6' $script:SmDhcpMaxScopes)) {
        $px = ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'Prefix') 64
        if (-not (Test-SmDhcpIp $px 'v6')) { throw 'Zusammenfassung ungueltig: Praefix (v6).' }
        $s6.Add([ordered]@{
                Prefix = $px; Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'Name') 256); State = (ConvertTo-SmDhcpText (Get-SmDhcpProp $s 'State') 32)
                Leases = (ConvertTo-SmDhcpInt (Get-SmDhcpProp $s 'Leases') 'Leases')
                Options = (ConvertTo-SmDhcpOptions (Get-SmDhcpProp $s 'Options') 'Bereichsoptionen v6')
                Reservations = (ConvertTo-SmDhcpReservations (Get-SmDhcpProp $s 'Reservations') 'Reservierungen v6' 'v6')
                Exclusions = (ConvertTo-SmDhcpRanges (Get-SmDhcpProp $s 'Exclusions') 'Ausschluesse v6' 'v6')
            })
    }
    $fo = New-Object System.Collections.Generic.List[object]
    foreach ($f in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Failover') 'Failover' 1000)) {
        $sc = @(ConvertTo-SmDhcpList (Get-SmDhcpProp $f 'Scopes') 'Failover-Bereiche' $script:SmDhcpMaxScopes | ForEach-Object { ConvertTo-SmDhcpText $_ 64 })
        foreach ($x in $sc) { if (-not (Test-SmDhcpIp $x 'v4')) { throw 'Zusammenfassung ungueltig: Failover-Bereich.' } }
        $fo.Add([ordered]@{ Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $f 'Name') 256); Partner = (ConvertTo-SmDhcpText (Get-SmDhcpProp $f 'Partner') 255); Mode = (ConvertTo-SmDhcpText (Get-SmDhcpProp $f 'Mode') 64); State = (ConvertTo-SmDhcpText (Get-SmDhcpProp $f 'State') 64); Scopes = $sc })
    }
    $po = New-Object System.Collections.Generic.List[object]
    foreach ($p in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Policies') 'Richtlinien')) {
        $po.Add([ordered]@{ Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $p 'Name') 256); Scope = (ConvertTo-SmDhcpText (Get-SmDhcpProp $p 'Scope') 64); Enabled = [bool](Get-SmDhcpProp $p 'Enabled') })
    }
    $fe = New-Object System.Collections.Generic.List[object]
    $filters = Get-SmDhcpProp $Obj 'Filters'
    foreach ($e in (ConvertTo-SmDhcpList (Get-SmDhcpProp $filters 'Entries') 'Filter')) {
        $fe.Add([ordered]@{ List = (ConvertTo-SmDhcpText (Get-SmDhcpProp $e 'List') 16); Mac = (ConvertTo-SmDhcpText (Get-SmDhcpProp $e 'Mac') 64); Description = (ConvertTo-SmDhcpText (Get-SmDhcpProp $e 'Description') 256) })
    }
    $dn = New-Object System.Collections.Generic.List[object]
    foreach ($d in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'DnsUpdate') 'DNS-Update' 1000)) {
        $dn.Add([ordered]@{ Scope = (ConvertTo-SmDhcpText (Get-SmDhcpProp $d 'Scope') 64); Name = (ConvertTo-SmDhcpText (Get-SmDhcpProp $d 'Name') 100); Value = (ConvertTo-SmDhcpText (Get-SmDhcpProp $d 'Value') 256) })
    }
    $bi = New-Object System.Collections.Generic.List[object]
    foreach ($b in (ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Bindings') 'Bindungen' 1000)) {
        $bi.Add([ordered]@{ Interface = (ConvertTo-SmDhcpText (Get-SmDhcpProp $b 'Interface') 256); Ip = (ConvertTo-SmDhcpText (Get-SmDhcpProp $b 'Ip') 64); State = (ConvertTo-SmDhcpText (Get-SmDhcpProp $b 'State') 32) })
    }
    [ordered]@{
        Format = 'SmDhcpSummary'; Version = 1; Server = $server; Created = (ConvertTo-SmDhcpText (Get-SmDhcpProp $Obj 'Created') 40)
        Authorized = [bool](Get-SmDhcpProp $Obj 'Authorized')
        Scopes4 = $s4.ToArray(); Scopes6 = $s6.ToArray()
        ServerOptions4 = (ConvertTo-SmDhcpOptions (Get-SmDhcpProp $Obj 'ServerOptions4') 'Serveroptionen v4')
        ServerOptions6 = (ConvertTo-SmDhcpOptions (Get-SmDhcpProp $Obj 'ServerOptions6') 'Serveroptionen v6')
        Failover = $fo.ToArray(); Policies = $po.ToArray()
        Filters = [ordered]@{ AllowEnabled = [bool](Get-SmDhcpProp $filters 'AllowEnabled'); DenyEnabled = [bool](Get-SmDhcpProp $filters 'DenyEnabled'); Entries = $fe.ToArray() }
        DnsUpdate = $dn.ToArray(); Bindings = $bi.ToArray()
        Errors = @(ConvertTo-SmDhcpList (Get-SmDhcpProp $Obj 'Errors') 'Fehler' 1000 | ForEach-Object { ConvertTo-SmDhcpText $_ 256 })
    }
}

function Read-SmBoundedStream {
    <# Liest einen Strom bis hoechstens Max Bytes; mehr ist ein Fehler (eine falsche Groessenangabe im ZIP schuetzt nicht). #>
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Max)
    $ms = New-Object IO.MemoryStream
    try {
        $buf = New-Object byte[] (1MB)
        while (($n = $Stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $ms.Write($buf, 0, $n)
            if ($ms.Length -gt $Max) { throw 'Die Datei ist groesser als erlaubt.' }
        }
        , $ms.ToArray()
    }
    finally { $ms.Dispose() }
}

function Read-SmDhcpSummaryFile {
    <# Liest eine Zusammenfassung aus einem Export-ZIP (Eintrag dhcp-summary.json) oder einer .json-Datei und prueft sie. #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Datei nicht gefunden.' }
    $bytes = $null
    if ($Path -match '\.zip$') {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        if ((Get-Item -LiteralPath $Path).Length -gt $script:SmDhcpMaxZipBytes) { throw 'Das ZIP ist groesser als erlaubt.' }
        $zip = [IO.Compression.ZipFile]::OpenRead($Path)
        try {
            if ($zip.Entries.Count -gt 10) { throw 'Das ZIP enthaelt zu viele Eintraege.' }
            $e = @($zip.Entries | Where-Object { $_.FullName -ceq $script:SmDhcpSummaryEntry })
            if ($e.Count -ne 1) { throw "Im ZIP fehlt $($script:SmDhcpSummaryEntry)." }
            if ($e[0].Length -gt $script:SmDhcpMaxJsonBytes) { throw 'Die Zusammenfassung im ZIP ist groesser als erlaubt.' }
            $st = $e[0].Open()
            try { $bytes = Read-SmBoundedStream -Stream $st -Max $script:SmDhcpMaxJsonBytes } finally { $st.Dispose() }
        }
        finally { $zip.Dispose() }
    }
    else {
        if ((Get-Item -LiteralPath $Path).Length -gt $script:SmDhcpMaxJsonBytes) { throw 'Die Datei ist groesser als erlaubt.' }
        $bytes = [IO.File]::ReadAllBytes($Path)
    }
    $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes).TrimStart([char]0xFEFF)
    if (-not (Test-SmDhcpJsonDepth $text)) { throw 'Zusammenfassung ungueltig: zu tief verschachtelt.' }
    $obj = try { ConvertFrom-Json -InputObject $text } catch { throw 'Zusammenfassung ungueltig: kein JSON.' }
    ConvertTo-SmDhcpSummary $obj
}

function Test-SmDhcpXmlSafe {
    <#
    .SYNOPSIS
        Prueft die Export-XML, bevor Import-DhcpServer sie liest: wohlgeformt, ohne DTD (DtdProcessing=Prohibit), ohne Resolver (XmlResolver=$null),
        Groesse begrenzt. Liest als Strom, baut keinen Baum. Liefert den Namen des Wurzelelements.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if ((Get-Item -LiteralPath $Path).Length -gt $script:SmDhcpMaxXmlBytes) { throw 'Die Export-XML ist groesser als erlaubt.' }
    $set = New-Object Xml.XmlReaderSettings
    $set.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $set.XmlResolver = $null
    $set.MaxCharactersFromEntities = 1024
    $set.CloseInput = $true
    $fs = [IO.File]::OpenRead($Path)
    $r = [Xml.XmlReader]::Create($fs, $set)
    try {
        $root = $null
        while ($r.Read()) { if (-not $root -and $r.NodeType -eq 'Element') { $root = $r.LocalName } }
        if (-not $root) { throw 'Die Export-XML ist leer.' }
        $root
    }
    catch [Xml.XmlException] { throw ('Die Export-XML ist ungueltig oder enthaelt eine DTD: ' + $_.Exception.Message) }
    finally { $r.Dispose(); $fs.Dispose() }
}

# ---------------------------------------------------------------- Vergleich

function ConvertTo-SmDhcpMap {
    <# Liste -> Hashtable Schluessel -> @{ Value; Label }. Schluessel sind Text, Gross-/Kleinschreibung egal. #>
    param($Items, [scriptblock]$Key, [scriptblock]$Value, [scriptblock]$Label)
    $m = @{}
    foreach ($i in @($Items)) {
        $k = [string](& $Key $i)
        $m[$k.ToLowerInvariant()] = @{ Value = (& $Value $i); Label = [string]$(if ($Label) { & $Label $i } else { $k }) }
    }
    $m
}

function Compare-SmDhcpMap {
    param($Rows, [string]$Area, [string]$Category, [hashtable]$Before, [hashtable]$After, [string]$Hint = '', [switch]$IncludeEqual)
    foreach ($k in (@($Before.Keys) + @($After.Keys) | Sort-Object -Unique)) {
        $b = $Before[$k]; $a = $After[$k]
        $label = if ($b) { $b.Label } else { $a.Label }
        if ($b -and -not $a) { $res = 'fehlt nachher'; $bv = [string]$b.Value; $av = '' }
        elseif ($a -and -not $b) { $res = 'neu nachher'; $bv = ''; $av = [string]$a.Value }
        elseif ([string]$a.Value -cne [string]$b.Value) { $res = 'anders'; $bv = [string]$b.Value; $av = [string]$a.Value }
        else { if (-not $IncludeEqual) { continue }; $res = 'gleich'; $bv = [string]$b.Value; $av = [string]$a.Value }
        $Rows.Add([pscustomobject]@{ Bereich = $Area; Kategorie = $Category; Element = $label; Vorher = $bv; Nachher = $av; Ergebnis = $res; Hinweis = $(if ($res -eq 'gleich') { '' } else { $Hint }) })
    }
}

function Get-SmDhcpOptionMap {
    param($Options)
    ConvertTo-SmDhcpMap $Options { param($o) 'Option ' + $o.Id } { param($o) $o.Value } { param($o) ('Option {0} {1}' -f $o.Id, $o.Name).Trim() }
}

function Compare-SmDhcpSummary {
    <#
    .SYNOPSIS
        Vergleicht zwei geprueften Zusammenfassungen (Vorher = alter Server, Nachher = neuer Server) je Bereich, Option, Reservierung, Ausschluss,
        Lease-Anzahl, Failover, Richtlinie, Filter, DNS-Update und Bindung. Liefert Zeilen mit Ergebnis gleich, anders, fehlt nachher, neu nachher.
        Ohne -IncludeEqual nur die Unterschiede.
    #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After, [switch]$IncludeEqual)
    $rows = New-Object System.Collections.Generic.List[object]
    $inc = [bool]$IncludeEqual
    # IPv4-Bereiche
    $bs = ConvertTo-SmDhcpMap $Before.Scopes4 { param($s) $s.ScopeId } { param($s) $s }
    $as = ConvertTo-SmDhcpMap $After.Scopes4 { param($s) $s.ScopeId } { param($s) $s }
    foreach ($k in (@($bs.Keys) + @($as.Keys) | Sort-Object { try { [version]$_ } catch { [version]'0.0' } } -Unique)) {
        $b = $bs[$k]; $a = $as[$k]
        $label = 'Bereich ' + $(if ($b) { $b.Label } else { $a.Label })
        if ($b -and -not $a) { $rows.Add([pscustomobject]@{ Bereich = $label; Kategorie = 'Bereich'; Element = $b.Value.Name; Vorher = 'vorhanden'; Nachher = ''; Ergebnis = 'fehlt nachher'; Hinweis = '' }); continue }
        if ($a -and -not $b) { $rows.Add([pscustomobject]@{ Bereich = $label; Kategorie = 'Bereich'; Element = $a.Value.Name; Vorher = ''; Nachher = 'vorhanden'; Ergebnis = 'neu nachher'; Hinweis = '' }); continue }
        $x = $b.Value; $y = $a.Value
        $pb = @{}; $pa = @{}
        foreach ($n in 'Name', 'Mask', 'Start', 'End', 'State', 'LeaseDuration') { $pb[$n.ToLowerInvariant()] = @{ Value = [string]$x[$n]; Label = $n }; $pa[$n.ToLowerInvariant()] = @{ Value = [string]$y[$n]; Label = $n } }
        Compare-SmDhcpMap $rows $label 'Bereich' $pb $pa -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Option' (Get-SmDhcpOptionMap $x.Options) (Get-SmDhcpOptionMap $y.Options) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Reservierung' (ConvertTo-SmDhcpMap $x.Reservations { param($r) $r.Ip } { param($r) ('{0} {1}' -f $r.ClientId, $r.Name).Trim() }) (ConvertTo-SmDhcpMap $y.Reservations { param($r) $r.Ip } { param($r) ('{0} {1}' -f $r.ClientId, $r.Name).Trim() }) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Ausschluss' (ConvertTo-SmDhcpMap $x.Exclusions { param($r) $r.Start + '-' + $r.End } { param($r) 'vorhanden' }) (ConvertTo-SmDhcpMap $y.Exclusions { param($r) $r.Start + '-' + $r.End } { param($r) 'vorhanden' }) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Richtlinie' (ConvertTo-SmDhcpMap $x.Policies { param($p) $p } { param($p) 'vorhanden' }) (ConvertTo-SmDhcpMap $y.Policies { param($p) $p } { param($p) 'vorhanden' }) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Leases' @{ anzahl = @{ Value = [string]$x.Leases; Label = 'Anzahl' } } @{ anzahl = @{ Value = [string]$y.Leases; Label = 'Anzahl' } } 'Leases aendern sich laufend, eine kleine Abweichung kann normal sein.' -IncludeEqual:$inc
    }
    # IPv6-Bereiche
    $b6 = ConvertTo-SmDhcpMap $Before.Scopes6 { param($s) $s.Prefix } { param($s) $s }
    $a6 = ConvertTo-SmDhcpMap $After.Scopes6 { param($s) $s.Prefix } { param($s) $s }
    foreach ($k in (@($b6.Keys) + @($a6.Keys) | Sort-Object -Unique)) {
        $b = $b6[$k]; $a = $a6[$k]
        $label = 'Bereich ' + $(if ($b) { $b.Label } else { $a.Label })
        if ($b -and -not $a) { $rows.Add([pscustomobject]@{ Bereich = $label; Kategorie = 'Bereich'; Element = $b.Value.Name; Vorher = 'vorhanden'; Nachher = ''; Ergebnis = 'fehlt nachher'; Hinweis = '' }); continue }
        if ($a -and -not $b) { $rows.Add([pscustomobject]@{ Bereich = $label; Kategorie = 'Bereich'; Element = $a.Value.Name; Vorher = ''; Nachher = 'vorhanden'; Ergebnis = 'neu nachher'; Hinweis = '' }); continue }
        $x = $b.Value; $y = $a.Value
        $pb = @{}; $pa = @{}
        foreach ($n in 'Name', 'State') { $pb[$n.ToLowerInvariant()] = @{ Value = [string]$x[$n]; Label = $n }; $pa[$n.ToLowerInvariant()] = @{ Value = [string]$y[$n]; Label = $n } }
        Compare-SmDhcpMap $rows $label 'Bereich' $pb $pa -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Option' (Get-SmDhcpOptionMap $x.Options) (Get-SmDhcpOptionMap $y.Options) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Reservierung' (ConvertTo-SmDhcpMap $x.Reservations { param($r) $r.Ip } { param($r) ('{0} {1}' -f $r.ClientId, $r.Name).Trim() }) (ConvertTo-SmDhcpMap $y.Reservations { param($r) $r.Ip } { param($r) ('{0} {1}' -f $r.ClientId, $r.Name).Trim() }) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Ausschluss' (ConvertTo-SmDhcpMap $x.Exclusions { param($r) $r.Start + '-' + $r.End } { param($r) 'vorhanden' }) (ConvertTo-SmDhcpMap $y.Exclusions { param($r) $r.Start + '-' + $r.End } { param($r) 'vorhanden' }) -IncludeEqual:$inc
        Compare-SmDhcpMap $rows $label 'Leases' @{ anzahl = @{ Value = [string]$x.Leases; Label = 'Anzahl' } } @{ anzahl = @{ Value = [string]$y.Leases; Label = 'Anzahl' } } 'Leases aendern sich laufend, eine kleine Abweichung kann normal sein.' -IncludeEqual:$inc
    }
    # Serverebene
    Compare-SmDhcpMap $rows 'Server' 'Option' (Get-SmDhcpOptionMap $Before.ServerOptions4) (Get-SmDhcpOptionMap $After.ServerOptions4) -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server (v6)' 'Option' (Get-SmDhcpOptionMap $Before.ServerOptions6) (Get-SmDhcpOptionMap $After.ServerOptions6) -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'Failover' (ConvertTo-SmDhcpMap $Before.Failover { param($f) $f.Name } { param($f) ('Partner {0}, {1}, Bereiche {2}' -f $f.Partner, $f.Mode, ($f.Scopes -join ' ')) }) (ConvertTo-SmDhcpMap $After.Failover { param($f) $f.Name } { param($f) ('Partner {0}, {1}, Bereiche {2}' -f $f.Partner, $f.Mode, ($f.Scopes -join ' ')) }) 'Import-DhcpServer uebernimmt keine Failover-Beziehungen: manuell neu anlegen (Add-DhcpServerv4Failover).' -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'Richtlinie' (ConvertTo-SmDhcpMap ($Before.Policies | Where-Object { -not $_.Scope }) { param($p) $p.Name } { param($p) $(if ($p.Enabled) { 'aktiv' } else { 'inaktiv' }) }) (ConvertTo-SmDhcpMap ($After.Policies | Where-Object { -not $_.Scope }) { param($p) $p.Name } { param($p) $(if ($p.Enabled) { 'aktiv' } else { 'inaktiv' }) }) -IncludeEqual:$inc
    $fb = @{ erlauben = @{ Value = [string]$Before.Filters.AllowEnabled; Label = 'Erlauben-Liste aktiv' }; ablehnen = @{ Value = [string]$Before.Filters.DenyEnabled; Label = 'Ablehnen-Liste aktiv' } }
    $fa = @{ erlauben = @{ Value = [string]$After.Filters.AllowEnabled; Label = 'Erlauben-Liste aktiv' }; ablehnen = @{ Value = [string]$After.Filters.DenyEnabled; Label = 'Ablehnen-Liste aktiv' } }
    Compare-SmDhcpMap $rows 'Server' 'Filter' $fb $fa -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'Filter' (ConvertTo-SmDhcpMap $Before.Filters.Entries { param($e) $e.List + ' ' + $e.Mac } { param($e) $e.Description }) (ConvertTo-SmDhcpMap $After.Filters.Entries { param($e) $e.List + ' ' + $e.Mac } { param($e) $e.Description }) -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'DNS-Update' (ConvertTo-SmDhcpMap $Before.DnsUpdate { param($d) ($d.Scope + ' ' + $d.Name).Trim() } { param($d) $d.Value }) (ConvertTo-SmDhcpMap $After.DnsUpdate { param($d) ($d.Scope + ' ' + $d.Name).Trim() } { param($d) $d.Value }) -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'Bindung' (ConvertTo-SmDhcpMap $Before.Bindings { param($d) $d.Interface } { param($d) $d.State }) (ConvertTo-SmDhcpMap $After.Bindings { param($d) $d.Interface } { param($d) $d.State }) 'Bindungen gehoeren zum Server (Netzwerkkarten) und koennen abweichen.' -IncludeEqual:$inc
    Compare-SmDhcpMap $rows 'Server' 'Autorisierung' @{ ad = @{ Value = [string]$Before.Authorized; Label = 'In AD autorisiert' } } @{ ad = @{ Value = [string]$After.Authorized; Label = 'In AD autorisiert' } } 'Der neue Server wird erst nach dem Import autorisiert.' -IncludeEqual:$inc
    , $rows.ToArray()
}

function Get-SmDhcpDiffText {
    param([Parameter(Mandatory)][object[]]$Rows)
    $d = @($Rows | Where-Object Ergebnis -ne 'gleich')
    '{0} Unterschiede: {1} fehlen nachher, {2} neu nachher, {3} anders' -f $d.Count, @($d | Where-Object Ergebnis -eq 'fehlt nachher').Count, @($d | Where-Object Ergebnis -eq 'neu nachher').Count, @($d | Where-Object Ergebnis -eq 'anders').Count
}

# ---------------------------------------------------------------- Seite DHCP im Berater-Tool

function Register-SmDhcpPage {
    <# Haengt die Knoepfe der Seite DHCP (UI\Dhcp.xaml) ein. Jobs laden SmTausch.ps1 und SmDhcp.ps1 (JobModules). #>
    param(
        [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string[]]$JobModules,
        [Parameter(Mandatory)][scriptblock]$GetShare, [Parameter(Mandatory)][scriptblock]$AddLog
    )
    $script:SmDhcpAdv = @{ Ui = $Ui; Modules = $JobModules; GetShare = $GetShare; AddLog = $AddLog; Files = @{}; Rows = @(); Busy = $false }
    $Ui.GrdDhcp.Add_AutoGeneratingColumn({ param($s, $e) $e.Column.Header = [string]$e.PropertyName })
    $Ui.BtnDhcpExport.IsEnabled = $false
    $Ui.BtnDhcpFind.Add_Click({
            $c = $script:SmDhcpAdv; $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'DHCP: Zuerst auf der Seite Tauschordner verbinden.'; return }
            if ($c.Busy) { return }
            $c.Busy = $true; $c.Ui.BtnDhcpFind.IsEnabled = $false; $c.Ui.TxtDhcpState.Text = 'Suche ...'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share } -Script {
                    param($State, $P)
                    @(Get-SmShareFiles -Share $P.Share | Where-Object { Get-SmDhcpFileKind $_.Name } | Sort-Object Modified -Descending)
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpAdv; $u = $c2.Ui; $c2.Busy = $false; $u.BtnDhcpFind.IsEnabled = $true
                    if ($err) { $u.TxtDhcpState.Text = 'Fehler'; & $c2.AddLog ('DHCP: ' + $err); return }
                    $files = @($result | Where-Object { $_ -and $_.Name })
                    $c2.Files = @{}; $u.CmbDhcpBefore.Items.Clear(); $u.CmbDhcpAfter.Items.Clear()
                    foreach ($f in $files) {
                        $label = '{0}  ({1})' -f $f.Name, (Format-SmSize $f.Length); $c2.Files[$label] = $f
                        if ((Get-SmDhcpFileKind $f.Name) -eq 'Export') { [void]$u.CmbDhcpBefore.Items.Add($label) } else { [void]$u.CmbDhcpAfter.Items.Add($label) }
                    }
                    if ($u.CmbDhcpBefore.Items.Count) { $u.CmbDhcpBefore.SelectedIndex = 0 }
                    if ($u.CmbDhcpAfter.Items.Count) { $u.CmbDhcpAfter.SelectedIndex = 0 }
                    $u.BtnDhcpCompare.IsEnabled = ($u.CmbDhcpBefore.Items.Count -gt 0 -and $u.CmbDhcpAfter.Items.Count -gt 0)
                    $u.TxtDhcpState.Text = '{0} Export(e) vom alten Server, {1} Zusammenfassung(en) vom neuen Server' -f $u.CmbDhcpBefore.Items.Count, $u.CmbDhcpAfter.Items.Count
                    & $c2.AddLog ('DHCP: {0} Datei(en) im Tauschordner' -f $files.Count)
                })
        })
    $Ui.BtnDhcpCompare.Add_Click({ Start-SmDhcpCompare })
    $Ui.ChkDhcpEqual.Add_Click({ if ($script:SmDhcpAdv.Summaries) { Show-SmDhcpRows } })
    $Ui.BtnDhcpExport.Add_Click({
            $c = $script:SmDhcpAdv; $u = $c.Ui
            if (-not (Get-Command Export-SmTable -ErrorAction SilentlyContinue)) { & $c.AddLog 'DHCP: Export-SmTable fehlt (Modules\SmExport.ps1).'; return }
            $rows = @($c.Shown)
            if (-not $rows.Count) { return }
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Title = 'Unterschiede speichern'; $dlg.Filter = 'Excel (*.xlsx)|*.xlsx|CSV (*.csv)|*.csv'; $dlg.FileName = ('dhcp-vergleich-{0:yyyyMMdd}.xlsx' -f (Get-Date))
            if (-not $dlg.ShowDialog()) { return }
            try { Export-SmTable -Rows $rows -Path $dlg.FileName; & $c.AddLog ('DHCP: {0} Zeilen exportiert' -f $rows.Count); Show-SmToast 'Exportiert.' }
            catch { & $c.AddLog ('DHCP: Export fehlgeschlagen: ' + $_.Exception.Message) }
        })
}

function Start-SmDhcpCompare {
    $c = $script:SmDhcpAdv; $u = $c.Ui; $share = & $c.GetShare
    $b = $c.Files[[string]$u.CmbDhcpBefore.SelectedItem]; $a = $c.Files[[string]$u.CmbDhcpAfter.SelectedItem]
    if (-not $share -or -not $b -or -not $a -or $c.Busy) { return }
    $c.Busy = $true; $u.BtnDhcpCompare.IsEnabled = $false; $u.TxtDhcpState.Text = 'Lade und vergleiche ...'
    [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; Before = $b; After = $a } -Script {
            param($State, $P)
            $tmp = Join-Path $env:TEMP ('ServerMigration-dhcp-' + [guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $tmp)
            try {
                $res = @{}
                foreach ($k in 'Before', 'After') {
                    $f = $P[$k]
                    if (-not (Get-SmDhcpFileKind $f.Name)) { throw 'Unerlaubter Dateiname im Tauschordner.' }
                    $limit = if ($f.Name -match '\.zip$') { $script:SmDhcpMaxZipBytes } else { $script:SmDhcpMaxJsonBytes }
                    if ($f.Length -gt $limit) { throw ('Datei zu gross: ' + $f.Name) }
                    $local = Join-Path $tmp ($k + [IO.Path]::GetExtension($f.Name))
                    Receive-SmShareFile -Share $P.Share -Name $f.Name -OutFile $local
                    $res[$k] = Read-SmDhcpSummaryFile -Path $local
                }
                [pscustomobject]@{ Before = $res.Before; After = $res.After }
            }
            finally {
                $full = [IO.Path]::GetFullPath($tmp)
                if ($full.StartsWith([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\ServerMigration-dhcp-', [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
            }
        } -OnDone {
            param($result, $err)
            $c2 = $script:SmDhcpAdv; $u2 = $c2.Ui; $c2.Busy = $false; $u2.BtnDhcpCompare.IsEnabled = $true
            if ($err) { $u2.TxtDhcpState.Text = 'Fehler'; & $c2.AddLog ('DHCP: ' + $err); return }
            $r = $result[-1]
            $c2.Summaries = $r
            $u2.TxtDhcpState.Text = 'Vorher: {0}, nachher: {1}' -f $r.Before.Server, $r.After.Server
            Show-SmDhcpRows
        })
}

function Show-SmDhcpRows {
    $c = $script:SmDhcpAdv; $u = $c.Ui; $r = $c.Summaries
    $rows = @(Compare-SmDhcpSummary -Before $r.Before -After $r.After -IncludeEqual:([bool]$u.ChkDhcpEqual.IsChecked))
    $c.Shown = $rows
    $u.GrdDhcp.ItemsSource = $rows
    $all = @(Compare-SmDhcpSummary -Before $r.Before -After $r.After)
    $u.TxtDhcpCount.Text = (Get-SmDhcpDiffText $all)
    $u.BtnDhcpExport.IsEnabled = ($rows.Count -gt 0 -and [bool](Get-Command Export-SmTable -ErrorAction SilentlyContinue))
    & $c.AddLog ('DHCP-Vergleich: ' + $u.TxtDhcpCount.Text)
}
