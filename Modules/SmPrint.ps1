<#
.SYNOPSIS
    Phase 5 (Print): gemeinsame Funktionen fuer Server-Fenster und Berater-Tool.
    Inventur lesen und vergleichen, Ereignis 307 parsen, Zugriffe auswerten (auch ungenutzte Drucker).
.DESCRIPTION
    Wird per Dot-Source geladen. Reine Funktionen ohne Zugriff auf Drucker oder Netz, damit sie mit Beispieldaten testbar sind.
    Alle Dateien aus dem Tauschordner gelten als feindlich (Sicherheits-Checkliste Punkt 7): Groessenlimit, JSON ueber
    JavaScriptSerializer (Clixml wird nie gelesen), XML nur mit DtdProcessing=Prohibit, Texte werden als Daten behandelt,
    gekuerzt und von Steuerzeichen befreit. Benutzernamen sind personenbezogene Daten (Punkt 12).
    Windows PowerShell 5.1.
#>

$script:SmPrintLog = 'Microsoft-Windows-PrintService/Operational'
$script:SmPrintMaxJsonBytes = 64MB
$script:SmPrintMaxEvents = 200000
$script:SmPrintMaxItems = 20000
$script:SmPrintMaxText = 256
$script:SmPrintSchema = 1

# ---------------------------------------------------------------- Hilfen

if (-not (Get-Command Format-SmSize -ErrorAction SilentlyContinue)) {
    function Format-SmSize {
        param([long]$Bytes)
        if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
        if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
        ('{0:N0} KB' -f [math]::Ceiling($Bytes / 1KB))
    }
}

function Get-SmPrintFileHash {
    <# SHA256 einer Datei, grossgeschrieben (wie Get-FileHash). #>
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $fs = [IO.File]::OpenRead($Path)
        try { $h = $sha.ComputeHash($fs) } finally { $fs.Dispose() }
    }
    finally { $sha.Dispose() }
    -join ($h | ForEach-Object { $_.ToString('X2') })
}

function Format-SmPrintText {
    <# Text aus fremden Daten: Steuerzeichen raus, gekuerzt. Bleibt reiner Text. #>
    param($Value, [int]$Max = $script:SmPrintMaxText)
    if ($null -eq $Value) { return '' }
    $t = [regex]::Replace([string]$Value, '[\x00-\x1F\x7F]', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) }
    $t
}

function Format-SmPrintName {
    <# Rechner- und Druckernamen vergleichbar machen: ohne fuehrende Backslashes bzw. \\server\ , Gross/Klein egal. #>
    param($Value)
    $t = Format-SmPrintText $Value
    $t = $t -replace '^\\\\[^\\]+\\', ''
    $t.TrimStart('\')
}

function ConvertTo-SmPrintTime {
    <# ISO-Text in UTC-Zeit, sonst $null. #>
    param($Value)
    $d = [datetime]::MinValue
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    $null
}

function Get-SmPrintBool($Value) {
    if ($Value -is [bool]) { return $Value }
    [bool]([string]$Value -match '^(?i:true|1|yes|ja)$')
}

function Get-SmPrintLong($Value) {
    $n = 0L
    if ([long]::TryParse([string]$Value, [ref]$n) -and $n -ge 0) { return $n }
    0L
}

function Read-SmPrintJson {
    <#
    .SYNOPSIS
        Liest eine JSON-Datei aus dem Tauschordner (feindlich): Groessenlimit, JavaScriptSerializer mit Rekursionsgrenze.
        Liefert Dictionary/Liste, nie Objekte mit Code.
    #>
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = $script:SmPrintMaxJsonBytes)
    $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($fi.Length -gt $MaxBytes) { throw ('Datei zu gross ({0} MB, erlaubt {1} MB): {2}' -f [math]::Ceiling($fi.Length / 1MB), [math]::Floor($MaxBytes / 1MB), $fi.Name) }
    Add-Type -AssemblyName System.Web.Extensions
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int][math]::Min([int]::MaxValue, $MaxBytes * 2)
    $ser.RecursionLimit = 16
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $obj = $null
    try { $obj = $ser.DeserializeObject($text) } catch { throw ('Keine gueltige JSON-Datei: ' + $fi.Name) }
    ConvertTo-SmPlainJson $obj
}

function ConvertTo-SmPlainJson {
    <# Dictionary in Hashtable (fehlender Schluessel liefert $null, kein Fehler), Listen in Arrays. #>
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $Value.Keys) { $h[[string]$k] = ConvertTo-SmPlainJson $Value[$k] }
        return $h
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $Value) { [void]$list.Add((ConvertTo-SmPlainJson $i)) }
        return , $list.ToArray()
    }
    $Value
}

function Get-SmPrintList($Dict, [string]$Key) {
    if ($Dict -is [System.Collections.IDictionary] -and ([System.Collections.IDictionary]$Dict).Contains($Key) -and $null -ne $Dict[$Key]) {
        $v = $Dict[$Key]
        if ($v -is [System.Collections.IDictionary]) { return @($v) }   # ein einzelnes Objekt statt Liste
        if ($v -is [string]) { return @() }
        return @(@($v) | Where-Object { $_ -is [System.Collections.IDictionary] })   # nur Objekte, nie Texte oder Zahlen
    }
    @()
}

function Get-SmPrintVal($Dict, [string]$Key) {
    if ($Dict -is [System.Collections.IDictionary] -and ([System.Collections.IDictionary]$Dict).Contains($Key)) { return $Dict[$Key] }
    $null
}

# ---------------------------------------------------------------- Inventur

function New-SmPrintInventory {
    <# Baut das Inventurobjekt (so wird es als JSON geschrieben). Eingaben sind die Rohdaten von Get-Printer usw. #>
    param([string]$Computer, [string]$Role = '', [object[]]$Printers = @(), [object[]]$Drivers = @(), [object[]]$Ports = @())
    [ordered]@{
        Schema   = $script:SmPrintSchema; Kind = 'PrintInventory'; Computer = (Format-SmPrintText $Computer 64)
        Created  = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); Role = $Role
        Printers = @($Printers); Drivers = @($Drivers); Ports = @($Ports)
    }
}

function ConvertTo-SmDriverVersion {
    <# DriverVersion von Get-PrinterDriver ist eine 64-Bit-Zahl: vier Teile a.b.c.d. #>
    param($Value)
    $n = [uint64]0
    if ($null -eq $Value -or -not [uint64]::TryParse([string]$Value, [ref]$n)) { return Format-SmPrintText $Value 40 }
    '{0}.{1}.{2}.{3}' -f (($n -shr 48) -band 0xFFFF), (($n -shr 32) -band 0xFFFF), (($n -shr 16) -band 0xFFFF), ($n -band 0xFFFF)
}

function Get-SmDriverArch {
    param([string]$Environment)
    if ($Environment -match '(?i)x64|amd64') { return 'x64' }
    if ($Environment -match '(?i)x86|NT x86') { return 'x86' }
    if ($Environment -match '(?i)arm') { return 'arm64' }
    Format-SmPrintText $Environment 30
}

function Read-SmPrintInventory {
    <# Liest und normalisiert eine Inventur (Tauschordner, feindlich). #>
    param([Parameter(Mandatory)][string]$Path)
    $d = Read-SmPrintJson -Path $Path
    if ($d -isnot [System.Collections.IDictionary] -or (Get-SmPrintVal $d 'Kind') -ne 'PrintInventory') { throw 'Das ist keine Druckserver-Inventur.' }
    if ((Get-SmPrintLong (Get-SmPrintVal $d 'Schema')) -ne $script:SmPrintSchema) { throw 'Unbekannte Schemaversion der Inventur.' }
    $lim = $script:SmPrintMaxItems
    $printers = @(Get-SmPrintList $d 'Printers' | Select-Object -First $lim | ForEach-Object {
            [pscustomobject]@{
                Name = Format-SmPrintText $_['Name']; DriverName = Format-SmPrintText $_['DriverName']; PortName = Format-SmPrintText $_['PortName']
                ShareName = Format-SmPrintText $_['ShareName']; Shared = (Get-SmPrintBool $_['Shared']); Published = (Get-SmPrintBool $_['Published'])
                Location = Format-SmPrintText $_['Location']; Comment = Format-SmPrintText $_['Comment']; Type = Format-SmPrintText $_['Type'] 30
            } } | Where-Object { $_.Name })
    $drivers = @(Get-SmPrintList $d 'Drivers' | Select-Object -First $lim | ForEach-Object {
            [pscustomobject]@{
                Name = Format-SmPrintText $_['Name']; Version = Format-SmPrintText $_['Version'] 40; Architecture = Format-SmPrintText $_['Architecture'] 30
                DriverType = [int](Get-SmPrintLong $_['DriverType']); Manufacturer = Format-SmPrintText $_['Manufacturer']
            } } | Where-Object { $_.Name })
    $ports = @(Get-SmPrintList $d 'Ports' | Select-Object -First $lim | ForEach-Object {
            [pscustomobject]@{ Name = Format-SmPrintText $_['Name']; Description = Format-SmPrintText $_['Description']; Address = Format-SmPrintText $_['Address']; PortNumber = [int](Get-SmPrintLong $_['PortNumber']) }
        } | Where-Object { $_.Name })
    [pscustomobject]@{
        Computer = Format-SmPrintText (Get-SmPrintVal $d 'Computer') 64; Created = (ConvertTo-SmPrintTime (Get-SmPrintVal $d 'Created'))
        Role = Format-SmPrintText (Get-SmPrintVal $d 'Role') 10; Printers = $printers; Drivers = $drivers; Ports = $ports
    }
}

function Compare-SmPrintInventory {
    <#
    .SYNOPSIS
        Vergleicht alte und neue Inventur: Drucker, Treiber, Ports, Freigaben.
        Liefert Zeilen (Area, Name, Status, Detail). Status: gleich, nur alt, nur neu, abweichend.
    #>
    param([Parameter(Mandatory)]$Old, [Parameter(Mandatory)]$New)
    $rows = New-Object System.Collections.ArrayList
    function Add-Row($area, $name, $status, $detail) { [void]$rows.Add([pscustomobject]@{ Area = $area; Name = $name; Status = $status; Detail = $detail }) }
    function Compare-Set($area, $oldItems, $newItems, [scriptblock]$Key, [string[]]$Fields) {
        $o = @{}; foreach ($i in @($oldItems)) { if ($null -eq $i) { continue }; $o[(& $Key $i).ToLowerInvariant()] = $i }
        $n = @{}; foreach ($i in @($newItems)) { if ($null -eq $i) { continue }; $n[(& $Key $i).ToLowerInvariant()] = $i }
        foreach ($k in ($o.Keys | Sort-Object)) {
            if (-not $n.ContainsKey($k)) { Add-Row $area (& $Key $o[$k]) 'nur alt' 'fehlt auf dem neuen Server'; continue }
            $diff = @(foreach ($f in $Fields) {
                    $a = [string]$o[$k].$f; $b = [string]$n[$k].$f
                    if ($a -ne $b) { '{0}: "{1}" -> "{2}"' -f $f, $a, $b }
                })
            if ($diff.Count) { Add-Row $area (& $Key $o[$k]) 'abweichend' ($diff -join '; ') } else { Add-Row $area (& $Key $o[$k]) 'gleich' '' }
        }
        foreach ($k in ($n.Keys | Sort-Object)) { if (-not $o.ContainsKey($k)) { Add-Row $area (& $Key $n[$k]) 'nur neu' 'nicht auf dem alten Server' } }
    }
    Compare-Set 'Drucker' $Old.Printers $New.Printers { param($i) $i.Name } @('DriverName', 'PortName', 'ShareName', 'Shared', 'Published', 'Location', 'Comment')
    Compare-Set 'Treiber' $Old.Drivers $New.Drivers { param($i) ('{0} ({1})' -f $i.Name, $i.Architecture) } @('Version', 'DriverType')
    Compare-Set 'Ports' $Old.Ports $New.Ports { param($i) $i.Name } @('Address', 'PortNumber')
    $os = @($Old.Printers | Where-Object { $_.Shared -and $_.ShareName }) | ForEach-Object { [pscustomobject]@{ Name = $_.ShareName; Printer = $_.Name } }
    $ns = @($New.Printers | Where-Object { $_.Shared -and $_.ShareName }) | ForEach-Object { [pscustomobject]@{ Name = $_.ShareName; Printer = $_.Name } }
    Compare-Set 'Freigaben' $os $ns { param($i) $i.Name } @('Printer')
    $rows.ToArray()
}

function Get-SmPrintCompareSummary {
    param([Parameter(Mandatory)][object[]]$Rows)
    $parts = foreach ($area in 'Drucker', 'Treiber', 'Ports', 'Freigaben') {
        $r = @($Rows | Where-Object Area -eq $area)
        '{0}: {1} gleich, {2} abweichend, {3} nur alt, {4} nur neu' -f $area, @($r | Where-Object Status -eq 'gleich').Count, @($r | Where-Object Status -eq 'abweichend').Count, @($r | Where-Object Status -eq 'nur alt').Count, @($r | Where-Object Status -eq 'nur neu').Count
    }
    $parts -join "`r`n"
}

# ---------------------------------------------------------------- Ereignis 307

function ConvertFrom-SmPrintEventXml {
    <#
    .SYNOPSIS
        Liest ein Ereignis 307 (Dokument gedruckt) aus seinem XML. Ohne DTD (Prohibit), ohne Resolver, Groessenlimit.
        Liefert Time (UTC), User, Client, Printer, Port, Pages, Bytes, RecordId; sonst $null. Der Dokumentname wird absichtlich nicht uebernommen.
        Param3 Benutzer, Param4 Rechner (\\CLIENT), Param5 Drucker, Param6 Port, Param7 Groesse in Bytes, Param8 Seiten.
    #>
    param([Parameter(Mandatory)][string]$Xml)
    if ($Xml.Length -gt 64KB) { return $null }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 64KB
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $sr = New-Object System.IO.StringReader $Xml
    try {
        $xr = [System.Xml.XmlReader]::Create($sr, $settings)
        try { $doc.Load($xr) } finally { $xr.Dispose() }
    }
    catch { return $null }
    finally { $sr.Dispose() }
    $id = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventID']")
    if (-not $id -or $id.InnerText.Trim() -ne '307') { return $null }
    $tc = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='TimeCreated']/@SystemTime")
    $time = if ($tc) { ConvertTo-SmPrintTime $tc.Value } else { $null }
    if (-not $time) { return $null }
    $rec = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventRecordID']")
    $p = @{}
    foreach ($n in 1..8) {
        $node = $doc.SelectSingleNode("//*[local-name()='DocumentPrinted']/*[local-name()='Param$n']")
        $p[$n] = if ($node) { $node.InnerText } else { '' }
    }
    $printer = Format-SmPrintName $p[5]
    if (-not $printer) { return $null }
    [pscustomobject]@{
        Time = $time; User = (Format-SmPrintText $p[3]); Client = (Format-SmPrintName $p[4]); Printer = $printer
        Port = (Format-SmPrintText $p[6]); Pages = [int](Get-SmPrintLong $p[8]); Bytes = (Get-SmPrintLong $p[7])
        RecordId = $(if ($rec) { Get-SmPrintLong $rec.InnerText } else { 0L })
    }
}

function New-SmPrintAccessFile {
    <# Objekt fuer die Zugriffsdatei (wird als JSON geschrieben). #>
    param([string]$Computer, [object[]]$Events = @(), $Snapshot, [datetime]$RequestedFrom, [bool]$Truncated = $false, [switch]$Pseudonymized, [switch]$ClientsPseudonymized)
    $ev = @($Events | Sort-Object Time)
    [ordered]@{
        Schema = $script:SmPrintSchema; Kind = 'PrintAccess'; Computer = (Format-SmPrintText $Computer 64)
        Created = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        RequestedFrom = $RequestedFrom.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        From = $(if ($ev.Count) { $ev[0].Time.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null })
        To = $(if ($ev.Count) { $ev[-1].Time.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null })
        Count = $ev.Count; Truncated = $Truncated; Pseudonymized = [bool]$Pseudonymized; ClientsPseudonymized = [bool]$ClientsPseudonymized
        Events = @($ev | ForEach-Object { [ordered]@{ Time = $_.Time.ToString('yyyy-MM-ddTHH:mm:ssZ'); User = $_.User; Client = $_.Client; Printer = $_.Printer; Port = $_.Port; Pages = $_.Pages; Bytes = $_.Bytes; RecordId = $_.RecordId } })
        Snapshot = $Snapshot
    }
}

function Read-SmPrintAccess {
    <# Liest eine Zugriffsdatei (feindlich). Liefert Computer, From, To, Events (normalisiert), Snapshot, Truncated. #>
    param([Parameter(Mandatory)][string]$Path)
    $d = Read-SmPrintJson -Path $Path
    if ($d -isnot [System.Collections.IDictionary] -or (Get-SmPrintVal $d 'Kind') -ne 'PrintAccess') { throw 'Das ist keine Datei mit Druckzugriffen.' }
    if ((Get-SmPrintLong (Get-SmPrintVal $d 'Schema')) -ne $script:SmPrintSchema) { throw 'Unbekannte Schemaversion der Zugriffsdatei.' }
    $events = @(Get-SmPrintList $d 'Events' | Select-Object -First $script:SmPrintMaxEvents | ForEach-Object {
            $t = ConvertTo-SmPrintTime $_['Time']
            if ($t -and $_['Printer']) {
                [pscustomobject]@{
                    Time = $t; User = (Format-SmPrintText $_['User']); Client = (Format-SmPrintName $_['Client']); Printer = (Format-SmPrintName $_['Printer'])
                    Port = (Format-SmPrintText $_['Port']); Pages = [int](Get-SmPrintLong $_['Pages']); Bytes = (Get-SmPrintLong $_['Bytes']); RecordId = (Get-SmPrintLong $_['RecordId'])
                }
            } })
    $snap = Get-SmPrintVal $d 'Snapshot'
    $sessions = @(); $files = @()
    if ($snap -is [System.Collections.IDictionary]) {
        $sessions = @(Get-SmPrintList $snap 'SmbSessions' | Select-Object -First 5000 | ForEach-Object { [pscustomobject]@{ Client = (Format-SmPrintName $_['Client']); User = (Format-SmPrintText $_['User']); Opens = [int](Get-SmPrintLong $_['Opens']); PrintOpen = (Get-SmPrintBool $_['PrintOpen']) } })
        $files = @(Get-SmPrintList $snap 'OpenFiles' | Select-Object -First 5000 | ForEach-Object { [pscustomobject]@{ Client = (Format-SmPrintName $_['Client']); User = (Format-SmPrintText $_['User']); Path = (Format-SmPrintText $_['Path'] 260) } })
    }
    [pscustomobject]@{
        Computer = Format-SmPrintText (Get-SmPrintVal $d 'Computer') 64; Events = $events; Truncated = (Get-SmPrintBool (Get-SmPrintVal $d 'Truncated')); Pseudonymized = (Get-SmPrintBool (Get-SmPrintVal $d 'Pseudonymized')); ClientsPseudonymized = (Get-SmPrintBool (Get-SmPrintVal $d 'ClientsPseudonymized'))
        Sessions = $sessions; OpenFiles = $files; Taken = (ConvertTo-SmPrintTime (Get-SmPrintVal $d 'Created'))
    }
}

function Merge-SmPrintEvents {
    <# Fuegt Ereignisse mehrerer Dateien zusammen und entfernt Doppelte (Zeit, Benutzer, Client, Drucker, Port, Seiten, Bytes, RecordId). #>
    param([object[]]$Events = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $out = New-Object System.Collections.ArrayList
    foreach ($e in $Events) {
        $key = '{0:o}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f $e.Time, $e.User, $e.Client, $e.Printer, $e.Port, $e.Pages, $e.Bytes, $e.RecordId
        if ($seen.Add($key)) { [void]$out.Add($e) }
    }
    , @($out)
}

# ---------------------------------------------------------------- Auswertung

function New-SmPseudonymKey {
    <# Zufaelliger Schluessel fuer Pseudonyme: 32 Byte aus dem kryptografischen Zufallsgenerator, als 64 Hexzeichen. Er wird angezeigt und kopiert, nie in eine Datei oder den Tauschordner geschrieben. #>
    $b = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    -join ($b | ForEach-Object { $_.ToString('X2') })
}

function Get-SmPseudonym {
    <# Kuerzel fuer einen Namen (personenbezogene Daten): Praefix und 12 Hexzeichen aus HMAC-SHA256 mit geheimem Schluessel (Name klein geschrieben). Gleicher Name und Schluessel, gleiches Kuerzel; ohne Schluessel nicht zurueckrechenbar. #>
    param([string]$Value, [Parameter(Mandatory)][Alias('Salt')][string]$Key, [string]$Prefix = 'Benutzer', [ValidateRange(4, 32)][int]$HexLength = 12)
    if (-not $Value) { return '' }
    $mac = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($Key))
    try { $h = $mac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.Trim().ToLowerInvariant())) } finally { $mac.Dispose() }
    '{0}-{1}' -f $Prefix, ((-join ($h | ForEach-Object { $_.ToString('X2') })).Substring(0, $HexLength))
}

function Get-SmPrintUsage {
    <#
    .SYNOPSIS
        Wertet Ereignisse aus. Liefert Period, ByUser, ByClient, ByPrinter, Unused und LastUse.
        Unused: Drucker der Inventur ohne Ereignis im Zeitraum (nur mit -Inventory).
        -MaskUsers ersetzt Benutzernamen durch Kuerzel (-Salt Pflicht).
    #>
    param([object[]]$Events = @(), $Inventory, [switch]$MaskUsers, [string]$Salt = '')
    $ev = @($Events | ForEach-Object {
            $e = $_.PSObject.Copy(); $e.Printer = Format-SmPrintName $e.Printer; $e.Client = Format-SmPrintName $e.Client
            if ($MaskUsers) { $e.User = Get-SmPseudonym -Value $e.User -Salt $Salt }
            $e
        })
    $ev = @($ev | Sort-Object Time)
    $fmt = 'yyyy-MM-dd HH:mm'
    $period = [pscustomobject]@{
        From = $(if ($ev.Count) { $ev[0].Time } else { $null }); To = $(if ($ev.Count) { $ev[-1].Time } else { $null }); Count = $ev.Count
        Days = $(if ($ev.Count) { [math]::Max(1, [int][math]::Ceiling(($ev[-1].Time - $ev[0].Time).TotalDays)) } else { 0 })
    }
    function Group-Usage([string]$Prop, [string]$Other, [string]$OtherLabel) {
        $ev | Where-Object { $_.$Prop } | Group-Object { $_.$Prop.ToLowerInvariant() } | ForEach-Object {
            $g = @($_.Group); $last = ($g | Sort-Object Time)[-1]
            $names = @($g | ForEach-Object { $_.$Other } | Sort-Object -Unique)
            [pscustomobject]@{
                Name = $g[0].$Prop; Printers = $names.Count; PrinterList = ($names -join ', '); Jobs = $g.Count
                Pages = [int](($g | Measure-Object Pages -Sum).Sum); LastUse = $last.Time.ToString($fmt)
            }
        } | Sort-Object @{ Expression = 'Jobs'; Descending = $true }, Name
    }
    $byPrinter = @($ev | Group-Object { $_.Printer.ToLowerInvariant() } | ForEach-Object {
            $g = @($_.Group); $s = @($g | Sort-Object Time)
            [pscustomobject]@{
                Printer = $g[0].Printer; Jobs = $g.Count; Pages = [int](($g | Measure-Object Pages -Sum).Sum)
                Users = @($g | ForEach-Object User | Where-Object { $_ } | Sort-Object -Unique).Count
                Clients = @($g | ForEach-Object Client | Where-Object { $_ } | Sort-Object -Unique).Count
                FirstUse = $s[0].Time.ToString($fmt); LastUse = $s[-1].Time.ToString($fmt)
            }
        } | Sort-Object @{ Expression = 'Jobs'; Descending = $true }, Printer)
    $unused = @()
    if ($Inventory) {
        $used = @{}; foreach ($e in $ev) { $used[$e.Printer.ToLowerInvariant()] = $true }
        $unused = @($Inventory.Printers | Where-Object { -not $used.ContainsKey((Format-SmPrintName $_.Name).ToLowerInvariant()) } | ForEach-Object {
                [pscustomobject]@{ Printer = $_.Name; Share = $_.ShareName; Port = $_.PortName; Driver = $_.DriverName; Location = $_.Location; LastUse = '(kein Ereignis im Zeitraum)' }
            } | Sort-Object Printer)
    }
    [pscustomobject]@{
        Period = $period
        ByUser = @(Group-Usage 'User' 'Printer' 'Drucker')
        ByClient = @(Group-Usage 'Client' 'Printer' 'Drucker')
        ByPrinter = $byPrinter
        Unused = $unused
    }
}

function Get-SmPrintPeriodText {
    param([Parameter(Mandatory)]$Period)
    if (-not $Period.Count) { return 'Keine Ereignisse geladen.' }
    $t = 'Zeitraum der Daten: {0:yyyy-MM-dd} bis {1:yyyy-MM-dd} (UTC, {2} Tage, {3} Druckauftraege).' -f $Period.From, $Period.To, $Period.Days, $Period.Count
    if ($Period.Days -lt 28) { $t += ' Achtung: kuerzer als ein Monat, selten genutzte Drucker erscheinen als ungenutzt.' }
    $t
}

function ConvertTo-SmDataTable {
    <# Objekte in eine DataTable (alle Spalten Text), damit die DataGrid sie sicher anzeigt. -Columns: Name=Ueberschrift. #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][string[]]$Properties, [string[]]$Headers)
    if (-not $Headers) { $Headers = $Properties }
    $dt = New-Object System.Data.DataTable
    foreach ($h in $Headers) { [void]$dt.Columns.Add($h, [string]) }
    foreach ($r in $Rows) {
        $row = $dt.NewRow()
        for ($i = 0; $i -lt $Properties.Count; $i++) { $row[$Headers[$i]] = [string]$r.($Properties[$i]) }
        [void]$dt.Rows.Add($row)
    }
    , $dt
}

function Invoke-SmPrintExportTable {
    <# Export ueber Export-SmTable (Modules\SmExport.ps1, Phase 3). Die Endung .csv oder .xlsx entscheidet. #>
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string]$Path)
    if (-not (Get-Command Export-SmTable -ErrorAction SilentlyContinue)) { throw 'Der Tabellenexport (Modules\SmExport.ps1) ist in dieser Fassung nicht vorhanden.' }
    Export-SmTable -Rows $Rows -Path $Path
}

# ---------------------------------------------------------------- Ansichten fuer die Seite Print (Berater-Tool)

function Get-SmPrintView {
    <#
    .SYNOPSIS
        Tabelle fuer eine Ansicht: Headers, Properties, Rows. Ansichten: Benutzer, Rechner, Drucker, Ungenutzt, Sofortbild, Vergleich.
        Die Zeilen tragen die deutschen Ueberschriften als Eigenschaften (so gehen sie in Export-SmTable).
    #>
    param([Parameter(Mandatory)][ValidateSet('Benutzer', 'Rechner', 'Drucker', 'Ungenutzt', 'Sofortbild', 'Vergleich')][string]$View, $Usage, [object[]]$Sessions = @(), [object[]]$Compare = @(), [switch]$MaskUsers, [string]$Salt = '')
    $map = switch ($View) {
        'Benutzer' { [ordered]@{ 'Benutzer' = 'Name'; 'Drucker (Anzahl)' = 'Printers'; 'Drucker' = 'PrinterList'; 'Auftraege' = 'Jobs'; 'Seiten' = 'Pages'; 'Letzte Nutzung' = 'LastUse' } }
        'Rechner' { [ordered]@{ 'Rechner' = 'Name'; 'Drucker (Anzahl)' = 'Printers'; 'Drucker' = 'PrinterList'; 'Auftraege' = 'Jobs'; 'Seiten' = 'Pages'; 'Letzte Nutzung' = 'LastUse' } }
        'Drucker' { [ordered]@{ 'Drucker' = 'Printer'; 'Auftraege' = 'Jobs'; 'Seiten' = 'Pages'; 'Benutzer' = 'Users'; 'Rechner' = 'Clients'; 'Erste Nutzung' = 'FirstUse'; 'Letzte Nutzung' = 'LastUse' } }
        'Ungenutzt' { [ordered]@{ 'Drucker' = 'Printer'; 'Freigabe' = 'Share'; 'Port' = 'Port'; 'Treiber' = 'Driver'; 'Standort' = 'Location'; 'Letzte Nutzung' = 'LastUse' } }
        'Sofortbild' { [ordered]@{ 'Rechner' = 'Client'; 'Benutzer' = 'User'; 'Offene Dateien' = 'Opens'; 'Druckdateien offen' = 'PrintOpen' } }
        'Vergleich' { [ordered]@{ 'Bereich' = 'Area'; 'Name' = 'Name'; 'Status' = 'Status'; 'Abweichung' = 'Detail' } }
    }
    $src = switch ($View) {
        'Benutzer' { @($Usage.ByUser) }
        'Rechner' { @($Usage.ByClient) }
        'Drucker' { @($Usage.ByPrinter) }
        'Ungenutzt' { @($Usage.Unused) }
        'Sofortbild' { @($Sessions | ForEach-Object { $s = $_; if ($MaskUsers) { $s = $s.PSObject.Copy(); $s.User = Get-SmPseudonym -Value $s.User -Salt $Salt }; $s }) }
        'Vergleich' { @($Compare) }
    }
    $rows = @($src | ForEach-Object {
            $o = [ordered]@{}; $r = $_
            foreach ($h in $map.Keys) { $o[$h] = $r.($map[$h]) }
            [pscustomobject]$o
        })
    [pscustomobject]@{ Headers = @($map.Keys); Properties = @($map.Values); Rows = $rows }
}

function Get-SmPrintPageXaml {
    param([Parameter(Mandatory)][string]$Root)
    [IO.File]::ReadAllText((Join-Path $Root 'UI\Print.xaml'))
}

function Get-SmPrintPageUiNames {
    @('LstPbShare', 'BtnPbRefresh', 'BtnPbOld', 'BtnPbNew', 'BtnPbEvents', 'BtnPbClear', 'TxtPbLoaded',
        'BtnPbCompare', 'TxtPbCompareSummary', 'GrdPbCompare', 'BtnPbCompareExport',
        'CmbPbView', 'ChkPbMask', 'BtnPbUsage', 'TxtPbPeriod', 'GrdPbUsage', 'BtnPbUsageExport')
}

function Initialize-SmPrintPage {
    <# Verdrahtet die Seite Print des Berater-Tools (UI\Print.xaml). GetShare liefert den Tauschordner oder $null. #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$AddLog, [Parameter(Mandatory)][scriptblock]$GetShare)
    $script:SmPB = @{ Ui = $Ui; Modules = $JobModules; Log = $AddLog; GetShare = $GetShare; Old = $null; New = $null; Events = @(); EventFiles = @(); Snapshot = $null; LastCompare = $null; Salt = (New-SmPseudonymKey); Busy = $false }
    foreach ($v in 'Je Benutzer', 'Je Rechner', 'Je Drucker', 'Ungenutzte Drucker', 'Sofortbild (SMB-Sitzungen)') { [void]$Ui.CmbPbView.Items.Add($v) }
    $Ui.CmbPbView.SelectedIndex = 0
    $Ui.BtnPbRefresh.Add_Click({ Update-SmPbShareList })
    $Ui.BtnPbOld.Add_Click({ Start-SmPbLoad -Kind 'Old' })
    $Ui.BtnPbNew.Add_Click({ Start-SmPbLoad -Kind 'New' })
    $Ui.BtnPbEvents.Add_Click({ Start-SmPbLoad -Kind 'Events' })
    $Ui.BtnPbClear.Add_Click({ Clear-SmPbData })
    $Ui.BtnPbCompare.Add_Click({ Show-SmPbCompare })
    $Ui.BtnPbCompareExport.Add_Click({ Export-SmPbView -Which 'Compare' })
    $Ui.BtnPbUsage.Add_Click({ Show-SmPbUsage })
    $Ui.BtnPbUsageExport.Add_Click({ Export-SmPbView -Which 'Usage' })
    Update-SmPbLoadedText
}

function Clear-SmPbData {
    $s = $script:SmPB
    $s.Old = $null; $s.New = $null; $s.Events = @(); $s.EventFiles = @(); $s.Snapshot = $null; $s.LastCompare = $null
    $s.Ui.GrdPbCompare.ItemsSource = $null; $s.Ui.GrdPbUsage.ItemsSource = $null; $s.Ui.TxtPbCompareSummary.Text = ''; $s.Ui.TxtPbPeriod.Text = ''
    Update-SmPbLoadedText
}

function Update-SmPbLoadedText {
    $s = $script:SmPB
    $parts = @()
    $parts += $(if ($s.Old) { 'Alte Inventur: {0} ({1} Drucker)' -f $s.Old.Computer, @($s.Old.Printers).Count } else { 'Alte Inventur: keine' })
    $parts += $(if ($s.New) { 'Neue Inventur: {0} ({1} Drucker)' -f $s.New.Computer, @($s.New.Printers).Count } else { 'Neue Inventur: keine' })
    $parts += ('Zugriffe: {0} Ereignisse aus {1} Datei(en)' -f @($s.Events).Count, @($s.EventFiles).Count)
    $s.Ui.TxtPbLoaded.Text = $parts -join "`r`n"
}

function Update-SmPbShareList {
    $s = $script:SmPB
    $share = & $s.GetShare
    if (-not $share) { $s.Ui.TxtPbLoaded.Text = 'Kein Tauschordner verbunden (Seite Tauschordner).'; return }
    try {
        $s.Ui.LstPbShare.Items.Clear()
        foreach ($f in @(Get-SmShareFiles -Share $share | Where-Object { $_.Name -match '^Print-(Inventur|Zugriffe)-[\w.\-]+\.json$' })) { [void]$s.Ui.LstPbShare.Items.Add($f.Name) }
        & $s.Log ('Print-Dateien im Tauschordner: {0}' -f $s.Ui.LstPbShare.Items.Count)
    }
    catch { $s.Ui.TxtPbLoaded.Text = 'Fehler: ' + $_.Exception.Message }
}

function Start-SmPbLoad {
    <# Laedt eine Inventur oder Zugriffsdatei: gewaehlte Datei aus dem Tauschordner, sonst per Dateidialog. #>
    param([Parameter(Mandatory)][ValidateSet('Old', 'New', 'Events')][string]$Kind)
    $s = $script:SmPB
    if ($s.Busy) { return }
    $name = [string]$s.Ui.LstPbShare.SelectedItem; $path = $null; $share = $null
    if ($name) {
        $share = & $s.GetShare
        if (-not $share) { $s.Ui.TxtPbLoaded.Text = 'Kein Tauschordner verbunden.'; return }
    }
    else {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title = 'Datei wählen'; $dlg.Filter = 'JSON (*.json)|*.json'
        if (-not $dlg.ShowDialog()) { return }
        $path = $dlg.FileName
    }
    $s.Busy = $true
    [void](Start-SmJob -Modules $s.Modules -Params @{ Share = $share; Name = $name; Path = $path; Kind = $Kind } -Script {
            param($State, $P)
            $file = $P.Path; $temp = $null
            if ($P.Share) {
                if ($P.Name -notmatch '^Print-(Inventur|Zugriffe)-[\w.\-]+\.json$') { throw 'Ungueltiger Dateiname.' }
                $remote = @(Get-SmShareFiles -Share $P.Share | Where-Object Name -eq $P.Name)
                if (-not $remote) { throw 'Die Datei ist nicht mehr im Tauschordner.' }
                if ($remote[0].Length -gt $script:SmPrintMaxJsonBytes) { throw 'Datei zu gross.' }
                $dir = Join-Path $env:TEMP ('ServerMigration-Print-' + [guid]::NewGuid().ToString('N'))
                [void](New-Item -ItemType Directory $dir)
                $temp = $dir; $file = Join-Path $dir $P.Name
                Receive-SmShareFile -Share $P.Share -Name $P.Name -OutFile $file -MaxBytes $script:SmPrintMaxJsonBytes
            }
            try {
                if ($P.Kind -eq 'Events') { [pscustomobject]@{ Kind = 'Events'; Data = (Read-SmPrintAccess -Path $file); Name = (Split-Path -Leaf $file) } }
                else { [pscustomobject]@{ Kind = $P.Kind; Data = (Read-SmPrintInventory -Path $file); Name = (Split-Path -Leaf $file) } }
            }
            finally { if ($temp) { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue } }
        } -OnDone {
            param($result, $err)
            $s = $script:SmPB; $s.Busy = $false
            if ($err) { $s.Ui.TxtPbLoaded.Text = 'Fehler: ' + $err; & $s.Log ('Print: Datei nicht geladen: ' + $err); return }
            $r = $result[-1]
            switch ($r.Kind) {
                'Old' { $s.Old = $r.Data }
                'New' { $s.New = $r.Data }
                'Events' {
                    $s.EventFiles = @($s.EventFiles) + $r.Name
                    $s.Events = Merge-SmPrintEvents -Events (@($s.Events) + @($r.Data.Events))
                    if ($r.Data.Pseudonymized) { & $s.Log ('Hinweis: Die Benutzernamen in dieser Zugriffsdatei sind pseudonymisiert' + $(if ($r.Data.ClientsPseudonymized) { ', die Rechnernamen auch.' } else { '.' })) }
                    if ($r.Data.Truncated) { & $s.Log 'Hinweis: Diese Zugriffsdatei wurde beim Sammeln gekuerzt (nur die neuesten Ereignisse).' }
                    $s.Snapshot = $r.Data
                }
            }
            & $s.Log ('Print: geladen ' + $r.Name)
            Update-SmPbLoadedText
        })
}

function Set-SmPbGrid($Grid, $View) {
    $dt = ConvertTo-SmDataTable -Rows $View.Rows -Properties $View.Headers -Headers $View.Headers
    $Grid.ItemsSource = $dt.DefaultView
}

function Show-SmPbCompare {
    $s = $script:SmPB
    if (-not $s.Old -or -not $s.New) { $s.Ui.TxtPbCompareSummary.Text = 'Bitte alte und neue Inventur laden.'; return }
    $rows = Compare-SmPrintInventory -Old $s.Old -New $s.New
    $s.LastCompare = $rows
    Set-SmPbGrid $s.Ui.GrdPbCompare (Get-SmPrintView -View Vergleich -Compare $rows)
    $s.Ui.TxtPbCompareSummary.Text = Get-SmPrintCompareSummary -Rows $rows
}

function Get-SmPbUsageView {
    $s = $script:SmPB
    $mask = [bool]$s.Ui.ChkPbMask.IsChecked
    $usage = Get-SmPrintUsage -Events @($s.Events) -Inventory $(if ($s.New) { $s.New } else { $s.Old }) -MaskUsers:$mask -Salt $s.Salt
    $view = switch ($s.Ui.CmbPbView.SelectedIndex) { 0 { 'Benutzer' } 1 { 'Rechner' } 2 { 'Drucker' } 3 { 'Ungenutzt' } default { 'Sofortbild' } }
    $sessions = if ($s.Snapshot) { @($s.Snapshot.Sessions) } else { @() }
    @{ Usage = $usage; View = (Get-SmPrintView -View $view -Usage $usage -Sessions $sessions -MaskUsers:$mask -Salt $s.Salt) }
}

function Show-SmPbUsage {
    $s = $script:SmPB
    if (-not @($s.Events).Count -and $s.Ui.CmbPbView.SelectedIndex -ne 4) { $s.Ui.TxtPbPeriod.Text = 'Bitte Zugriffsdateien laden.'; return }
    $r = Get-SmPbUsageView
    Set-SmPbGrid $s.Ui.GrdPbUsage $r.View
    $t = Get-SmPrintPeriodText $r.Usage.Period
    if ($s.Ui.CmbPbView.SelectedIndex -eq 3 -and -not ($s.Old -or $s.New)) { $t += ' Für ungenutzte Drucker bitte eine Inventur laden.' }
    $s.Ui.TxtPbPeriod.Text = $t
}

function Export-SmPbView {
    param([ValidateSet('Compare', 'Usage')][string]$Which)
    $s = $script:SmPB
    try {
        $v = if ($Which -eq 'Compare') { if (-not $s.LastCompare) { throw 'Bitte zuerst vergleichen.' }; Get-SmPrintView -View Vergleich -Compare $s.LastCompare } else { (Get-SmPbUsageView).View }
        if (-not @($v.Rows).Count) { throw 'Keine Zeilen zum Exportieren.' }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'Excel (*.xlsx)|*.xlsx|CSV (*.csv)|*.csv'; $dlg.FileName = if ($Which -eq 'Compare') { 'Print-Vergleich' } else { 'Print-Auswertung' }
        if (-not $dlg.ShowDialog()) { return }
        Invoke-SmPrintExportTable -Rows @($v.Rows) -Path $dlg.FileName
        & $s.Log ('Print: Export {0} Zeilen nach {1}' -f @($v.Rows).Count, (Split-Path -Leaf $dlg.FileName))
        Show-SmToast 'Export gespeichert.'
    }
    catch { $s.Ui.TxtPbLoaded.Text = 'Export nicht möglich: ' + $_.Exception.Message }
}
