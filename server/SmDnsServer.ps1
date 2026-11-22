<#
.SYNOPSIS
    Server-Fenster, Bereich DNS: Logging-Status, Logging ein- und ausschalten, Logs mit Metadaten als ZIP in den Tauschordner legen.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht Modules\SmTausch.ps1 und, fuer die Oberflaeche, Modules\SmShell.ps1).
    Aendernde Aktionen (Logging ein und aus) haben eine Vorpruefung, eine Bestaetigung im Fenster und eine Protokollzeile ohne Geheimnisse.
    Der Zustand von Get-DnsServerDiagnostics wird vor dem Einschalten gesichert und beim Ausschalten wiederhergestellt.
    Die Logdatei wird auch gelesen, wenn der DNS-Dienst sie offen haelt (FileShare ReadWrite), und direkt in das ZIP geschrieben.
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmDnsDefaultPath = '%windir%\System32\dns\dns.log'
$script:SmDnsDefaultMaxMB = 500
# Pakete, die fuer die Auswertung gebraucht werden (Queries, Answers, Send, Receive, UDP, TCP) plus Notify und Update fuer die Ansicht "Updates und Notify".
# Schluessel = Eigenschaft von Get-DnsServerDiagnostics, Wert = Parameter von Set-DnsServerDiagnostics (laut Microsoft-Doku heisst nur Update dort Updates).
$script:SmDnsPacketMap = [ordered]@{
    Queries = 'Queries'; Answers = 'Answers'; SendPackets = 'SendPackets'; ReceivePackets = 'ReceivePackets'
    UdpPackets = 'UdpPackets'; TcpPackets = 'TcpPackets'; Notifications = 'Notifications'; Update = 'Updates'
}
# Set-DnsServerDiagnostics verlangt je mindestens einen Parameter aus jeder Gruppe, deshalb gehen immer alle acht Pakete mit.
$script:SmDnsStateProps = @('EnableLoggingToFile', 'LogFilePath', 'MaxMBFileSize') + @($script:SmDnsPacketMap.Keys)
# MaxMBFileSize heisst nur so: Die Einheit ist Byte (Beispiel der Doku: 500000000). Die Oberflaeche rechnet in MB.
$script:SmDnsMaxBytesLimit = [uint32]::MaxValue
$script:SmDnsAdminText = 'Fuer das Setzen der Logdatei braucht Set-DnsServerDiagnostics lokale Administratorrechte. Bitte das Server-Fenster als Administrator starten.'

function Test-SmAdmin {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false }
}

function Get-SmDnsStateDir {
    Join-Path $env:ProgramData 'ServerMigration'
}

function Get-SmDnsAllowedDir {
    <# Seit dem Cumulative Update 2026-11 fuer Windows Server 2025 ignoriert der DNS-Server Log-Pfade ausserhalb von %windir%\System32\dns (Event 506). #>
    if ($script:SmDnsAllowedDirOverride) { return $script:SmDnsAllowedDirOverride }   # nur fuer Tests
    Join-Path $env:windir 'System32\dns'
}

function Get-SmDnsStateSids {
    if ($script:SmDnsStateSidsOverride) { return @($script:SmDnsStateSidsOverride) }   # nur fuer Tests
    @('S-1-5-32-544', 'S-1-5-18')   # Administratoren und SYSTEM
}

function Test-SmDnsStateDirAcl {
    <# Prueft Besitzer und Zugriffsliste des Sicherungsordners. Liefert die Liste der Probleme (leer = in Ordnung). #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$AllowedSids = (Get-SmDnsStateSids))
    $problems = New-Object System.Collections.Generic.List[string]
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $problems.Add('Der Ordner ist eine Verknuepfung (Junction oder Symlink).') }
    $acl = Get-Acl -LiteralPath $Path
    try { $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $owner = '' }
    if ($owner -notin $AllowedSids) { $problems.Add("Der Besitzer des Ordners ist nicht erlaubt ($owner).") }
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin $AllowedSids) { $problems.Add("Die Zugriffsliste enthaelt einen nicht erlaubten Eintrag ($($r.IdentityReference.Value)).") }
    }
    @($problems)
}

function Protect-SmDnsStateDir {
    <# Legt den Sicherungsordner an (falls noetig), setzt Besitzer und Zugriffsliste (nur Administratoren und SYSTEM) und prueft das Ergebnis. Bricht bei jedem Problem ab. #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$AllowedSids = (Get-SmDnsStateSids))
    if (-not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Path $Path -Force) }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Sicherungsordner ist kein Ordner: $Path" }
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Sicherungsordner ist eine Verknuepfung, abgebrochen: $Path" }
    try {
        $own = Get-Acl -LiteralPath $Path
        $own.SetOwner((New-Object Security.Principal.SecurityIdentifier $AllowedSids[0]))
        Set-Acl -LiteralPath $Path -AclObject $own
    }
    catch { }   # ohne Recht, den Besitzer zu setzen, entscheidet die Pruefung unten
    try {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in $AllowedSids) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        }
        # .NET statt Set-Acl: Set-Acl scheitert beim zweiten Aufruf auf einen schon gehaerteten Ordner an SeSecurityPrivilege, SetAccessControl nicht
        [IO.Directory]::SetAccessControl($Path, $acl)
    }
    catch { throw "Die Zugriffsrechte des Sicherungsordners konnten nicht gesetzt werden: $($_.Exception.Message)" }
    $bad = @(Test-SmDnsStateDirAcl -Path $Path -AllowedSids $AllowedSids)
    if ($bad.Count) { throw ('Der Sicherungsordner ist nicht sicher, abgebrochen: ' + ($bad -join ' ')) }
}

function Remove-SmWorkOrphans {
    <#
    Loescht verwaiste Arbeitsordner (Name passt auf NamePattern, aelter als MinAge, Besitzer nur Administratoren oder SYSTEM, keine Verknuepfung).
    Gedacht fuer den Start des Server-Fensters: Ordner, die ein frueherer Lauf nicht aufgeraeumt hat (Absturz, Fenster waehrend eines Jobs geschlossen).
    Fremde Ordner (anderer Besitzer, anderer Name) bleiben unberuehrt. Liefert die Zahl der geloeschten Ordner.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$NamePattern, [timespan]$MinAge = [timespan]::FromHours(24), [string[]]$AllowedSids = (Get-SmDnsStateSids))
    $n = 0
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return $n }
    if ((Get-Item -LiteralPath $Root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $n }
    foreach ($d in @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue)) {
        try {
            if ($d.Name -notmatch $NamePattern) { continue }
            if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if (((Get-Date) - $d.LastWriteTime) -lt $MinAge) { continue }
            try { $owner = (Get-Acl -LiteralPath $d.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($owner -notin $AllowedSids) { continue }
            Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction Stop
            $n++
        }
        catch { }   # in Benutzung oder keine Rechte: bleibt stehen, der naechste Start versucht es wieder
    }
    $n
}

function Clear-SmDnsOrphans {
    <# Start des Server-Fensters: verwaiste ServerMigration-dns-<GUID>-Ordner unter %TEMP% (Reste eines geschlossenen Fensters mitten im Upload), aelter als 24 h. Der Upload selbst raeumt in finally auf. #>
    param([string]$TempRoot = $env:TEMP)
    Remove-SmWorkOrphans -Root $TempRoot -NamePattern '^ServerMigration-dns-[0-9a-f]{32}$'
}

function ConvertTo-SmDnsMaxBytes {
    <# MB (Oberflaeche) -> Byte (MaxMBFileSize). Wirft, wenn der Wert nicht in uint32 passt (unter 4 GB). #>
    param([Parameter(Mandatory)][long]$MB)
    if ($MB -lt 1) { throw 'Die Groesse muss mindestens 1 MB sein.' }
    $b = [long]$MB * 1MB
    if ($b -ge $script:SmDnsMaxBytesLimit) { throw 'Die Groesse muss unter 4096 MB liegen (MaxMBFileSize ist ein 32-Bit-Wert in Byte).' }
    [uint32]$b
}

function ConvertFrom-SmDnsMaxBytes {
    <# Byte (MaxMBFileSize) -> MB fuer die Anzeige. #>
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    [math]::Round([double]$Bytes / 1MB, 1)
}

function Get-SmDnsDiagnostics {
    <# Liest die DNS-Diagnoseeinstellungen (nur die Werte, die wir brauchen oder wiederherstellen). #>
    if (-not (Get-Command Get-DnsServerDiagnostics -ErrorAction SilentlyContinue)) {
        throw 'Auf diesem Server gibt es keine DNS-Verwaltung (Get-DnsServerDiagnostics fehlt). Ist die DNS-Rolle installiert?'
    }
    $d = Get-DnsServerDiagnostics -ErrorAction Stop
    $h = [ordered]@{}
    foreach ($n in $script:SmDnsStateProps) { $p = $d.PSObject.Properties[$n]; if ($p) { $h[$n] = $p.Value } }
    $h
}

function Get-SmDnsStatus {
    <# Status des Loggings: an oder aus, Pfad, Groesse, welche Pakete, ob eine Logdatei da ist. #>
    $h = Get-SmDnsDiagnostics
    $path = [string]$h['LogFilePath']
    $exp = if ($path) { [Environment]::ExpandEnvironmentVariables($path) } else { '' }
    $exists = $false; $bytes = 0L
    if ($exp) { try { if (Test-Path -LiteralPath $exp -PathType Leaf) { $exists = $true; $bytes = (Get-Item -LiteralPath $exp -Force).Length } } catch { } }
    $pk = @($script:SmDnsPacketMap.Keys | Where-Object { $h.Contains($_) -and $h[$_] -eq $true } | ForEach-Object { $script:SmDnsPacketMap[$_] })
    [pscustomobject]@{
        LoggingOn   = [bool]$h['EnableLoggingToFile']
        Path        = $path
        FullPath    = $exp
        MaxMB       = ConvertFrom-SmDnsMaxBytes $h['MaxMBFileSize']
        Packets     = $pk
        LogExists   = $exists
        LogBytes    = $bytes
    }
}

function Test-SmDnsLogPath {
    <# Prueft den Pfad der Logdatei. Liefert den vollen Pfad oder wirft einen Fehler. Der DNS-Dienst (SYSTEM) schreibt dorthin, deshalb streng. #>
    param([Parameter(Mandatory)][string]$Path)
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim())
    if ($p -match '%') { throw 'Der Pfad enthaelt eine unbekannte Umgebungsvariable.' }
    if ($p -notmatch '^[A-Za-z]:\\[\w ~.\-\\()]+$' -or $p -match '\.\.' -or $p -match '\\\\') {
        throw 'Der Pfad ist unzulaessig. Erlaubt: Laufwerk, Ordner und Dateiname mit Buchstaben, Ziffern, Leerzeichen, Punkt, Bindestrich, Unterstrich.'
    }
    $full = [IO.Path]::GetFullPath($p)
    if ([IO.Path]::GetExtension($full) -notin '.log', '.txt') { throw 'Die Logdatei muss auf .log oder .txt enden.' }
    $dir = Split-Path -Parent $full
    $allowed = [IO.Path]::GetFullPath((Get-SmDnsAllowedDir)).TrimEnd('\')
    if ($dir.TrimEnd('\') -ine $allowed) { throw "Seit dem Cumulative Update 2026-11 fuer Windows Server 2025 ignoriert der DNS-Server Log-Pfade ausserhalb von $allowed (Event 506). Erlaubt ist nur dieser Ordner, z. B. $allowed\dns.log." }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Der Ordner existiert nicht: $dir" }
    try { $dt = (New-Object IO.DriveInfo ($full.Substring(0, 1))).DriveType } catch { $dt = 'Unknown' }
    if ($dt -ne 'Fixed') { throw 'Die Logdatei muss auf einem lokalen Laufwerk liegen.' }
    if (Test-Path -LiteralPath $full -PathType Container) { throw 'Der Pfad ist ein Ordner.' }
    if ((Test-Path -LiteralPath $full -PathType Leaf) -and (Get-Item -LiteralPath $full -Force).Length -gt 0) {
        # eine vorhandene Datei darf nur ein DNS-Log sein, sonst wuerde der Dienst eine fremde Datei ueberschreiben
        $fs = [IO.File]::Open($full, 'Open', 'Read', 'ReadWrite, Delete')
        try { $b = New-Object byte[] 40; $n = $fs.Read($b, 0, 40) } finally { $fs.Dispose() }
        if ([Text.Encoding]::ASCII.GetString($b, 0, $n) -notmatch '^DNS Server log file creation') { throw 'Unter diesem Pfad liegt eine Datei, die kein DNS-Log ist. Bitte einen anderen Pfad waehlen.' }
    }
    $full
}

function Get-SmDnsEnablePlan {
    <# Vorpruefung fuer "Logging einschalten": Rechte, Cmdlets, Pfad, Groesse, freier Platz. Aendert nichts. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$MaxMB)
    $err = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $full = $null; $mb = 0
    if (-not (Test-SmAdmin)) { $err.Add('Das Fenster laeuft nicht als Administrator. ' + $script:SmDnsAdminText) }
    if (-not (Get-Command Set-DnsServerDiagnostics -ErrorAction SilentlyContinue)) { $err.Add('Set-DnsServerDiagnostics fehlt: Ist die DNS-Rolle installiert?') }
    try { $full = Test-SmDnsLogPath -Path $Path } catch { $err.Add($_.Exception.Message) }
    if ($MaxMB -notmatch '^\d{2,4}$' -or [int]$MaxMB -lt 10 -or [int]$MaxMB -gt 2048) { $err.Add('Die maximale Groesse muss zwischen 10 und 2048 MB liegen.') }
    else { try { [void](ConvertTo-SmDnsMaxBytes -MB ([long]$MaxMB)); $mb = [int]$MaxMB } catch { $err.Add($_.Exception.Message) } }
    if ($full -and $mb) {
        try {
            $free = (New-Object IO.DriveInfo ($full.Substring(0, 1))).AvailableFreeSpace
            if ($free -lt ($mb * 1MB * 1.1)) { $err.Add(('Auf dem Laufwerk sind nur {0:N0} MB frei, gebraucht werden etwa {1:N0} MB.' -f ($free / 1MB), ($mb * 1.1))) }
        }
        catch { $warn.Add('Der freie Platz konnte nicht geprueft werden.') }
    }
    $setCmd = Get-Command Set-DnsServerDiagnostics -ErrorAction SilentlyContinue
    $pk = @($script:SmDnsPacketMap.Values | Where-Object { $setCmd -and $setCmd.Parameters.ContainsKey($_) })
    [pscustomobject]@{ Ok = ($err.Count -eq 0); Errors = @($err); Warnings = @($warn); Path = $full; MaxMB = $mb; Packets = $pk }
}

function Save-SmDnsState {
    param([Parameter(Mandatory)]$Before, [string]$StateDir = (Get-SmDnsStateDir))
    Protect-SmDnsStateDir -Path $StateDir   # immer haerten und pruefen, auch wenn der Ordner schon da ist
    $values = [ordered]@{}
    foreach ($k in $Before.Keys) { $values[$k] = $Before[$k] }
    $obj = [ordered]@{ Version = 1; Saved = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Server = [string]$env:COMPUTERNAME; Values = $values }
    [IO.File]::WriteAllText((Join-Path $StateDir 'dns-diagnostics-before.json'), ($obj | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
}

function Read-SmDnsState {
    <# Gesicherter Zustand, streng geprueft (Datei gilt als Daten). $null, wenn keiner da oder ungueltig. #>
    param([string]$StateDir = (Get-SmDnsStateDir))
    $f = Join-Path $StateDir 'dns-diagnostics-before.json'
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return $null }
    if (@(Test-SmDnsStateDirAcl -Path $StateDir).Count) { return $null }   # Ordner nicht gesichert: Datei koennte von jedem stammen
    if ((Get-Item -LiteralPath $f).Length -gt 64KB) { return $null }
    try { $o = [IO.File]::ReadAllText($f) | ConvertFrom-Json } catch { return $null }
    if (-not $o -or $o.Version -ne 1 -or -not $o.Values) { return $null }
    $res = [ordered]@{}
    foreach ($n in $script:SmDnsStateProps) {
        $p = $o.Values.PSObject.Properties[$n]
        if (-not $p) { continue }
        $v = $p.Value
        if ($n -eq 'LogFilePath') {
            if ($v -is [string] -and $v.Length -le 260) { try { $res[$n] = Test-SmDnsLogPath -Path $v } catch { } }   # dieselbe Pruefung wie beim Einschalten
        }
        elseif ($n -eq 'MaxMBFileSize') {
            if ($v -is [int] -or $v -is [long]) { if ($v -ge 0 -and $v -le 4294967295) { $res[$n] = [uint32]$v } }   # Byte
        }
        elseif ($v -is [bool]) { $res[$n] = $v }
    }
    $res
}

function Enable-SmDnsLogging {
    <# Schaltet das Logging ein (nach Vorpruefung und Bestaetigung im Fenster). Sichert vorher den Zustand. #>
    param([Parameter(Mandatory)]$Plan, [scriptblock]$Log = { param($m) }, [string]$StateDir = (Get-SmDnsStateDir))
    if (-not $Plan.Ok) { throw ('Vorpruefung nicht bestanden: ' + ($Plan.Errors -join ' ')) }
    if (-not (Test-SmAdmin)) { throw $script:SmDnsAdminText }
    $path = Test-SmDnsLogPath -Path ([string]$Plan.Path)   # der Plan koennte veraltet oder veraendert sein
    $bytes = ConvertTo-SmDnsMaxBytes -MB ([long]$Plan.MaxMB)
    $before = Get-SmDnsDiagnostics
    Save-SmDnsState -Before $before -StateDir $StateDir
    & $Log 'Vorheriger Zustand der DNS-Diagnose gesichert.'
    $p = @{ EnableLoggingToFile = $true; LogFilePath = $path; MaxMBFileSize = $bytes }
    foreach ($n in $Plan.Packets) { $p[$n] = $true }   # Set-Namen (Updates, nicht Update)
    Set-DnsServerDiagnostics @p -ErrorAction Stop
    $after = Get-SmDnsDiagnostics
    if ($after['EnableLoggingToFile'] -ne $true) { throw 'Das Logging ist nach dem Einschalten nicht aktiv.' }
    & $Log ('DNS-Logging eingeschaltet: {0}, max. {1} MB, Pakete: {2}' -f $Plan.Path, $Plan.MaxMB, ($Plan.Packets -join ', '))
}

function Disable-SmDnsLogging {
    <# Schaltet das Logging aus und stellt, wenn gesichert, den vorherigen Zustand wieder her. #>
    param([scriptblock]$Log = { param($m) }, [string]$StateDir = (Get-SmDnsStateDir))
    if (-not (Test-SmAdmin)) { throw 'Das Fenster laeuft nicht als Administrator.' }
    if (-not (Get-Command Set-DnsServerDiagnostics -ErrorAction SilentlyContinue)) { throw 'Set-DnsServerDiagnostics fehlt: Ist die DNS-Rolle installiert?' }
    $state = Read-SmDnsState -StateDir $StateDir
    $cur = Get-SmDnsDiagnostics
    $cmd = Get-Command Set-DnsServerDiagnostics
    $p = @{ EnableLoggingToFile = $false }
    # Der Parametersatz verlangt je einen Parameter aus jeder Paketgruppe: aktuelle Werte durchreichen, der gesicherte Zustand ueberschreibt sie.
    foreach ($g in $script:SmDnsPacketMap.Keys) {
        $sn = $script:SmDnsPacketMap[$g]
        if ($cur.Contains($g) -and $cur[$g] -is [bool] -and $cmd.Parameters.ContainsKey($sn)) { $p[$sn] = $cur[$g] }
    }
    $restored = @()
    if ($state) {
        foreach ($k in $state.Keys) {
            if ($k -eq 'EnableLoggingToFile') { continue }
            $sn = if ($script:SmDnsPacketMap.Contains($k)) { $script:SmDnsPacketMap[$k] } else { $k }
            if (-not $cmd.Parameters.ContainsKey($sn)) { continue }
            $p[$sn] = $state[$k]; $restored += $k
        }
    }
    Set-DnsServerDiagnostics @p -ErrorAction Stop
    $after = Get-SmDnsDiagnostics
    if ($after['EnableLoggingToFile'] -ne $false) { throw 'Das Logging ist nach dem Ausschalten noch aktiv.' }
    if ($state) {
        Remove-Item -LiteralPath (Join-Path $StateDir 'dns-diagnostics-before.json') -Force -ErrorAction SilentlyContinue
        & $Log ('DNS-Logging ausgeschaltet, vorheriger Zustand wiederhergestellt ({0} Einstellungen).' -f $restored.Count)
    }
    else { & $Log 'DNS-Logging ausgeschaltet. Es gab keinen gesicherten Zustand, die uebrigen Einstellungen blieben unveraendert.' }
}

function Get-SmDnsMeta {
    <# Metadaten fuer die Auswertung. Keine Geheimnisse. Jede Quelle einzeln abgesichert, Fehler landen in Warnings. #>
    $warn = New-Object System.Collections.Generic.List[string]
    $meta = [ordered]@{ Version = 1; Server = [string]$env:COMPUTERNAME; Created = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    try { $tz = [TimeZoneInfo]::Local; $meta.TimeZone = $tz.Id; $meta.UtcOffset = $tz.BaseUtcOffset.ToString() } catch { $warn.Add('Zeitzone nicht lesbar') }
    try {
        $cur = Get-Culture; $meta.Culture = $cur.Name
        $sys = $null
        if (Get-Command Get-WinSystemLocale -ErrorAction SilentlyContinue) { try { $sys = (Get-WinSystemLocale).Name } catch { } }
        $meta.SystemLocale = if ($sys) { $sys } else { $cur.Name }
        # der DNS-Dienst laeuft als SYSTEM und schreibt Datum und Uhrzeit im Format des Systemgebietsschemas
        $fmt = try { [Globalization.CultureInfo]::GetCultureInfo($meta.SystemLocale).DateTimeFormat } catch { $cur.DateTimeFormat }
        $meta.DateFormat = $fmt.ShortDatePattern
        $meta.TimeFormat = $fmt.LongTimePattern
        $meta.AmPm = ('{0}/{1}' -f $fmt.AMDesignator, $fmt.PMDesignator)
    }
    catch { $warn.Add('Kultur nicht lesbar') }
    try {
        $meta.OwnIps = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
                ForEach-Object { $_.GetIPProperties().UnicastAddresses } | ForEach-Object { $_.Address } |
                Where-Object { -not $_.IsIPv6LinkLocal -and $_.ToString() -notmatch '^169\.254\.' } | ForEach-Object { $_.ToString() })
    }
    catch { $warn.Add('Eigene IPs nicht lesbar'); $meta.OwnIps = @() }
    $meta.Forwarders = @(); $meta.UseRootHint = $null
    try {
        if (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue) {
            $f = Get-DnsServerForwarder -ErrorAction Stop
            $meta.Forwarders = @($f.IPAddress | ForEach-Object { $_.ToString() })
            $meta.UseRootHint = [bool]$f.UseRootHint
        }
        else { $warn.Add('Get-DnsServerForwarder fehlt') }
    }
    catch { $warn.Add('Forwarder nicht lesbar') }
    $meta.Zones = @(); $meta.ConditionalForwarders = @(); $meta.SecondaryServers = @()
    try {
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $zones = @(Get-DnsServerZone -ErrorAction Stop)
            $meta.Zones = @($zones | ForEach-Object { [ordered]@{ Name = [string]$_.ZoneName; Type = [string]$_.ZoneType; DsIntegrated = [bool]$_.IsDsIntegrated; Reverse = [bool]$_.IsReverseLookupZone } })
            $meta.ConditionalForwarders = @($zones | Where-Object { [string]$_.ZoneType -eq 'Forwarder' } | ForEach-Object { [ordered]@{ Zone = [string]$_.ZoneName; Servers = @($_.MasterServers | ForEach-Object { $_.ToString() }) } })
            $meta.SecondaryServers = @($zones | Where-Object { $_.PSObject.Properties['SecondaryServers'] -and $_.SecondaryServers } | ForEach-Object {
                    [ordered]@{ Zone = [string]$_.ZoneName; Servers = @(@($_.SecondaryServers) + @($(if ($_.PSObject.Properties['NotifyServers']) { $_.NotifyServers })) | Where-Object { $_ } | ForEach-Object { $_.ToString() } | Select-Object -Unique) }
                })
        }
        else { $warn.Add('Get-DnsServerZone fehlt') }
    }
    catch { $warn.Add('Zonen nicht lesbar') }
    $meta.DomainControllers = @()
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $meta.DomainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ Name = [string]$_.HostName; Site = [string]$_.Site; Ips = @(@($_.IPv4Address, $_.IPv6Address) | Where-Object { $_ } | ForEach-Object { $_.ToString() }) }
                })
        }
        catch { $warn.Add('Domaenencontroller nicht lesbar') }
    }
    else { $warn.Add('AD-Modul nicht vorhanden: keine Domaenencontroller in den Metadaten') }
    $meta.Warnings = @($warn)
    $meta
}

function Add-SmZipEntryShared {
    <# Schreibt eine Datei in ein ZIP, auch wenn ein anderer Prozess (der DNS-Dienst) sie offen haelt. #>
    param([Parameter(Mandatory)]$Zip, [Parameter(Mandatory)][string]$EntryName, [Parameter(Mandatory)][string]$Path, [scriptblock]$Progress)
    $entry = $Zip.CreateEntry($EntryName, [IO.Compression.CompressionLevel]::Fastest)
    $src = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $dst = $entry.Open()
        try {
            $buf = New-Object byte[] (1MB); $done = 0L; $total = $src.Length
            while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
                $dst.Write($buf, 0, $n); $done += $n
                if ($Progress) { & $Progress $done $total }
            }
        }
        finally { $dst.Dispose() }
    }
    finally { $src.Dispose() }
}

function New-SmDnsLogZip {
    <# Packt Log und Metadaten (meta.json) in ein ZIP. Liefert den Pfad. Der Dateiname enthaelt nur geprueften Text. #>
    param([Parameter(Mandatory)][string]$LogPath, [Parameter(Mandatory)][string]$OutDir, [Parameter(Mandatory)]$Meta, [scriptblock]$Progress)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $srv = ([string]$Meta.Server) -replace '[^\w\-]', ''
    if ($srv.Length -gt 30) { $srv = $srv.Substring(0, 30) }
    if (-not $srv) { $srv = 'server' }
    $name = 'SM-DNS-{0}-{1}.zip' -f $srv, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $target = Join-Path $OutDir $name
    $zip = [IO.Compression.ZipFile]::Open($target, 'Create')
    try {
        Add-SmZipEntryShared -Zip $zip -EntryName 'dns.log' -Path $LogPath -Progress $Progress
        $e = $zip.CreateEntry('meta.json', [IO.Compression.CompressionLevel]::Optimal)
        $s = $e.Open()
        try { $b = (New-Object Text.UTF8Encoding $false).GetBytes(($Meta | ConvertTo-Json -Depth 6)); $s.Write($b, 0, $b.Length) } finally { $s.Dispose() }
    }
    finally { $zip.Dispose() }
    $target
}

function Publish-SmDnsLogs {
    <#
    .SYNOPSIS
        Packt die DNS-Logdatei mit Metadaten als ZIP und legt sie per Upload in Teilen im Tauschordner ab.
    .DESCRIPTION
        Arbeitet in einem neuen Zufallsordner unter %TEMP% und raeumt ihn danach auf (nur dieser Ordner, Pfad per GetFullPath geprueft).
        Progress bekommt (gesendete Bytes, Gesamtbytes) fuer den Upload, Log eine Textzeile.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$LogPath, [scriptblock]$Progress, [scriptblock]$Log = { param($m) }, [string]$TempRoot = $env:TEMP)
    $full = Test-SmDnsLogPath -Path $LogPath   # Pfad, Endung und Kopfzeile "DNS Server log file creation" wie beim Einschalten
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Keine Logdatei gefunden: $full" }
    $size = (Get-Item -LiteralPath $full -Force).Length
    if ($size -eq 0) { throw 'Die Logdatei ist leer.' }
    $tempFull = [IO.Path]::GetFullPath($TempRoot)
    $free = (New-Object IO.DriveInfo ($tempFull.Substring(0, 1))).AvailableFreeSpace
    if ($free -lt ([math]::Min($size, 2GB) / 2 + 50MB)) { throw 'Im Temp-Ordner ist zu wenig Platz fuer das ZIP.' }
    $work = Join-Path $tempFull ('ServerMigration-dns-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $work)
    try {
        & $Log ('Lese Log ({0:N1} MB) und Metadaten' -f ($size / 1MB))
        $meta = Get-SmDnsMeta
        $zipPath = New-SmDnsLogZip -LogPath $full -OutDir $work -Meta $meta
        & $Log ('ZIP gepackt: {0:N1} MB' -f ((Get-Item -LiteralPath $zipPath).Length / 1MB))
        $remote = Send-SmShareFile -Share $Share -Path $zipPath -Progress $Progress
        & $Log ('Im Tauschordner: {0} ({1:N1} MB)' -f $remote.Name, ($remote.Length / 1MB))
        $remote
    }
    finally {
        $wf = [IO.Path]::GetFullPath($work)
        if ($wf.StartsWith($tempFull.TrimEnd('\') + '\ServerMigration-dns-', [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $wf -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Register-SmDnsServerPage {
    <#
    .SYNOPSIS
        Haengt die Knoepfe des DNS-Bereichs ein. Die Logik steckt in den Funktionen oben, hier nur Oberflaeche und Bestaetigungen.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string[]]$JobModules,
        [Parameter(Mandatory)][scriptblock]$GetShare, [Parameter(Mandatory)][scriptblock]$AddLog
    )
    $script:SmDnsSrv = @{ Ui = $Ui; Modules = $JobModules; GetShare = $GetShare; AddLog = $AddLog; Status = $null }
    $Ui.TxtDnsPath.Text = $script:SmDnsDefaultPath
    $Ui.TxtDnsMax.Text = [string]$script:SmDnsDefaultMaxMB

    $Ui.BtnDnsRefresh.Add_Click({ Update-SmDnsServerPage })
    $Ui.BtnDnsEnable.Add_Click({
            $c = $script:SmDnsSrv; $u = $c.Ui
            $plan = Get-SmDnsEnablePlan -Path $u.TxtDnsPath.Text -MaxMB $u.TxtDnsMax.Text
            if (-not $plan.Ok) { foreach ($e in $plan.Errors) { & $c.AddLog ('DNS-Logging: ' + $e) }; return }
            $msg = "Das DNS-Logging wird eingeschaltet.`n`nLogdatei: $($plan.Path)`nMaximale Groesse: $($plan.MaxMB) MB`nPakete: $($plan.Packets -join ', ')`n`nDer jetzige Zustand wird gesichert und kann mit 'Logging ausschalten' wiederhergestellt werden. Fortfahren?"
            if ([System.Windows.MessageBox]::Show($msg, 'DNS-Logging einschalten', 'YesNo', 'Question') -ne 'Yes') { & $c.AddLog 'DNS-Logging einschalten abgebrochen.'; return }
            $u.BtnDnsEnable.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Params @{ Plan = $plan } -Script {
                    param($State, $P)
                    Enable-SmDnsLogging -Plan $P.Plan -Log { param($m) $State.Log.Enqueue($m) }
                } -OnTick { param($s) Write-SmDnsJobLog $s } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDnsSrv; $c2.Ui.BtnDnsEnable.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DNS-Logging: Fehler: ' + $err) }
                    Update-SmDnsServerPage
                })
        })
    $Ui.BtnDnsDisable.Add_Click({
            $c = $script:SmDnsSrv; $u = $c.Ui
            $msg = "Das DNS-Logging wird ausgeschaltet und der gesicherte vorherige Zustand wiederhergestellt. Die vorhandene Logdatei bleibt erhalten.`n`nFortfahren?"
            if ([System.Windows.MessageBox]::Show($msg, 'DNS-Logging ausschalten', 'YesNo', 'Question') -ne 'Yes') { & $c.AddLog 'DNS-Logging ausschalten abgebrochen.'; return }
            $u.BtnDnsDisable.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Script {
                    param($State, $P)
                    Disable-SmDnsLogging -Log { param($m) $State.Log.Enqueue($m) }
                } -OnTick { param($s) Write-SmDnsJobLog $s } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDnsSrv; $c2.Ui.BtnDnsDisable.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DNS-Logging: Fehler: ' + $err) }
                    Update-SmDnsServerPage
                })
        })
    $Ui.BtnDnsUpload.Add_Click({
            $c = $script:SmDnsSrv; $u = $c.Ui
            $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'Kein Tauschordner verbunden (Seite "Dieser Server", "Ordner prüfen").'; return }
            if (-not $c.Status -or -not $c.Status.LogExists) { & $c.AddLog 'Keine Logdatei vorhanden.'; return }
            $u.BtnDnsUpload.IsEnabled = $false; $u.PrgDns.Value = 0; $u.PrgDns.Visibility = 'Visible'; $u.TxtDnsProgress.Text = 'Packe und lade hoch …'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; Path = $c.Status.FullPath } -Script {
                    param($State, $P)
                    Publish-SmDnsLogs -Share $P.Share -LogPath $P.Path -Progress { param($sent, $total) $State.Sent = $sent; $State.Total = $total } -Log { param($m) $State.Log.Enqueue($m) }
                } -OnTick { param($s) Write-SmDnsJobLog $s; if ($s.Total -gt 0) { $script:SmDnsSrv.Ui.PrgDns.Value = [math]::Min(100, 100 * $s.Sent / $s.Total) } } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDnsSrv; $c2.Ui.BtnDnsUpload.IsEnabled = $true
                    if ($err) { $c2.Ui.TxtDnsProgress.Text = 'Fehlgeschlagen'; & $c2.AddLog ('DNS-Logs: Fehler: ' + $err); return }
                    $c2.Ui.TxtDnsProgress.Text = 'Fertig'
                })
        })
    Update-SmDnsServerPage
}

function Write-SmDnsJobLog {
    param($State)
    $line = $null
    while ($State.Log.TryDequeue([ref]$line)) { & $script:SmDnsSrv.AddLog $line }
}

function Update-SmDnsServerPage {
    <# Liest den Status im Hintergrund und zeigt je nach Zustand "Logs sammeln", "Logging ausschalten" und "Logs hochladen". #>
    $c = $script:SmDnsSrv; $u = $c.Ui
    $u.BtnDnsRefresh.IsEnabled = $false; $u.TxtDnsState.Text = 'Lese Status …'
    [void](Start-SmJob -Modules $c.Modules -Script { param($State, $P) Get-SmDnsStatus } -OnDone {
            param($result, $err)
            $c2 = $script:SmDnsSrv; $u2 = $c2.Ui
            $u2.BtnDnsRefresh.IsEnabled = $true
            if ($err) {
                $c2.Status = $null; $u2.TxtDnsState.Text = 'Nicht verfügbar'
                $u2.BoxDnsEnable.Visibility = 'Collapsed'; $u2.BoxDnsOn.Visibility = 'Collapsed'; $u2.BoxDnsLogs.Visibility = 'Collapsed'
                & $c2.AddLog ('DNS: ' + $err); return
            }
            $s = $result[-1]; $c2.Status = $s
            $u2.TxtDnsState.Text = if ($s.LoggingOn) { 'Logging ist EIN' } else { 'Logging ist AUS' }
            $u2.TxtDnsDetail.Text = 'Datei: {0}, max. {1} MB{2}' -f $s.Path, $s.MaxMB, $(if ($s.Packets.Count) { ', Pakete: ' + ($s.Packets -join ', ') } else { '' })
            $u2.BoxDnsEnable.Visibility = if ($s.LoggingOn) { 'Collapsed' } else { 'Visible' }
            $u2.BoxDnsOn.Visibility = if ($s.LoggingOn) { 'Visible' } else { 'Collapsed' }
            $u2.BoxDnsLogs.Visibility = if ($s.LogExists) { 'Visible' } else { 'Collapsed' }
            $u2.TxtDnsLogInfo.Text = if ($s.LogExists) { 'Logdatei vorhanden: {0} ({1})' -f $s.FullPath, (Format-SmSize $s.LogBytes) } else { '' }
        })
}
