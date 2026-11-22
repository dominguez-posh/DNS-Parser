<#
.SYNOPSIS
    Server-Fenster, Startseite "Dieser Server": gefuehrter Ablauf (Assistent). Pruefungen nacheinander, Ergebnisse vormerken, am Ende alles hochladen.
.DESCRIPTION
    Wird per Dot-Source geladen (nach server\SmDnsServer.ps1, Modules\SmDhcp.ps1, server\SmDhcpServer.ps1, Modules\SmPrint.ps1, server\SmPrintServer.ps1,
    Modules\SmAd.ps1, server\SmAdServer.ps1, Modules\SmTausch.ps1; fuer die Oberflaeche Modules\SmShell.ps1 und Modules\SmUi.ps1).
    Schritte: Server pruefen, DNS, DHCP, Print, AD, Ergebnisse hochladen. Rollen werden erkannt (DNS, DHCP, Druckserver, DC); die anderen Schritte
    stehen als "nicht installiert" da und werden uebersprungen. Jeder Schritt hat einen Zustand: offen, laeuft, erledigt, uebersprungen, Fehler.
    Sammeln und Hochladen sind getrennt: Die Schritte erzeugen Dateien und merken sie vor (Name, Groesse, SHA256), hochgeladen wird erst im letzten
    Schritt, auf einen Klick, alle ausgewaehlten Dateien nacheinander (grosse in Teilen). Aendernde Aktionen (Import, FSMO, Autorisierung ...) gehoeren
    nicht in den Assistenten, sie bleiben auf den Seiten DNS, DHCP, Print und AD. Einzige Ausnahme: das DNS-Logging einschalten (mit Bestaetigung).
    Sicherheit (docs\security-checklist.md): Vorgemerkte Dateien liegen nur in gehaerteten Ordnern (Sammlung-<GUID> unter ProgramData\ServerMigration\Assistent,
    Print, AD). Vor dem Hochladen wird die Datei mit FileShare.Read gehalten und ihr SHA256 mit dem vorgemerkten verglichen. Dateinamen nur per Whitelist.
    Windows PowerShell 5.1.
#>

$script:SmAsDataRoot = $null          # nur fuer Tests: Wurzel statt ProgramData\ServerMigration
$script:SmAsStepKeys = @('Check', 'Dns', 'Dhcp', 'Print', 'Ad', 'Upload')
$script:SmAsTitles = @{ Check = 'Server prüfen'; Dns = 'DNS'; Dhcp = 'DHCP'; Print = 'Druckserver'; Ad = 'Active Directory'; Upload = 'Ergebnisse hochladen' }
$script:SmAsRoleOfStep = @{ Dns = 'Dns'; Dhcp = 'Dhcp'; Print = 'Print'; Ad = 'Ad' }
$script:SmAsStagePattern = '^Sammlung-[0-9a-f]{32}$'
$script:SmAsMinFreeBytes = 2GB

# ---------------------------------------------------------------- Zustaende und Navigation (reine Logik)

function Get-SmAsStateText {
    <# Anzeigetext eines Zustands. #>
    param([Parameter(Mandatory)][string]$State)
    switch ($State) {
        'Open' { 'offen' } 'Running' { 'läuft' } 'Done' { 'erledigt' } 'Skipped' { 'übersprungen' } 'Error' { 'Fehler' } 'NotInstalled' { 'nicht installiert' }
        default { throw "Unbekannter Zustand: $State" }
    }
}

function Get-SmAsServiceNames {
    <# Namen der vorhandenen Dienste, an denen die Rollen hängen (DNS, DHCPServer, NTDS = Domänencontroller, Spooler). #>
    @('DNS', 'DHCPServer', 'NTDS', 'Spooler') | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
}

function Get-SmAsRoles {
    <# Erkennt die installierten Rollen: DNS, DHCP, Druckserver, Domänencontroller. Ein Fehler bei einer Rolle zählt als "nicht installiert". #>
    $svc = @()
    try { $svc = @(Get-SmAsServiceNames) } catch { }
    $print = $false
    try { $print = [bool](Get-SmPrintRoleInstalled) } catch { }
    [pscustomobject]@{ Dns = ($svc -contains 'DNS'); Dhcp = ($svc -contains 'DHCPServer'); Print = $print; Ad = ($svc -contains 'NTDS') }
}

function New-SmAsState {
    <# Zustand des Assistenten: Schritte (Reihenfolge fest), aktueller Schritt, vorgemerkte Dateien, Sammelordner dieser Sitzung. #>
    $steps = [ordered]@{}
    foreach ($k in $script:SmAsStepKeys) { $steps[$k] = [pscustomobject]@{ Key = $k; Title = $script:SmAsTitles[$k]; State = 'Open'; Detail = '' } }
    [pscustomobject]@{ Roles = $null; Steps = $steps; Current = 'Check'; Staged = (New-Object System.Collections.ArrayList); StageDir = $null; Results = @() }
}

function Set-SmAsRoles {
    <# Setzt die erkannten Rollen: Schritte der nicht installierten Rollen werden "nicht installiert", die der installierten wieder "offen". #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Roles)
    $State.Roles = $Roles
    foreach ($k in $script:SmAsRoleOfStep.Keys) {
        $s = $State.Steps[$k]
        $has = [bool]$Roles.($script:SmAsRoleOfStep[$k])
        if (-not $has) { $s.State = 'NotInstalled'; $s.Detail = 'Die Rolle ist auf diesem Server nicht installiert.' }
        elseif ($s.State -eq 'NotInstalled') { $s.State = 'Open'; $s.Detail = '' }
    }
}

function Set-SmAsStepState {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateSet('Open', 'Running', 'Done', 'Skipped', 'Error', 'NotInstalled')][string]$Value, [string]$Detail)
    if (-not $State.Steps.Contains($Key)) { throw "Unbekannter Schritt: $Key" }
    $State.Steps[$Key].State = $Value
    if ($PSBoundParameters.ContainsKey('Detail')) { $State.Steps[$Key].Detail = $Detail }
}

function Get-SmAsNavTarget {
    <# Nächster oder vorheriger Schritt von $From aus; Schritte "nicht installiert" werden übersprungen. $null, wenn es keinen gibt. #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][ValidateSet('Next', 'Back')][string]$Direction, [string]$From = $State.Current)
    $keys = @($State.Steps.Keys)
    $i = [array]::IndexOf($keys, $From)
    if ($i -lt 0) { return $null }
    $step = if ($Direction -eq 'Next') { 1 } else { -1 }
    for ($j = $i + $step; $j -ge 0 -and $j -lt $keys.Count; $j += $step) {
        if ($State.Steps[$keys[$j]].State -ne 'NotInstalled') { return $keys[$j] }
    }
    $null
}

function Skip-SmAsStep {
    <# Überspringt den aktuellen Schritt (ein erledigter bleibt erledigt) und liefert den nächsten Schlüssel oder $null. Der Upload-Schritt lässt sich nicht überspringen. #>
    param([Parameter(Mandatory)]$State)
    $cur = $State.Current
    if ($cur -eq 'Upload') { return $null }
    $s = $State.Steps[$cur]
    if ($s.State -eq 'Running') { throw 'Der Schritt läuft noch.' }
    if ($s.State -in 'Open', 'Error') { $s.State = 'Skipped' }
    Get-SmAsNavTarget -State $State -Direction Next
}

# ---------------------------------------------------------------- Schritt 1: Server prüfen

function Get-SmAsCheck {
    <# Prüft: Administrator, Rollen, Tauschordner verbunden, freier Platz (Systemlaufwerk). Ändert nichts. Items: Name, Ok, Text. #>
    param([bool]$ShareConnected, $Roles = (Get-SmAsRoles), [long]$FreeBytes = -1)
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($n, $ok, $t) $items.Add([pscustomobject]@{ Name = $n; Ok = [bool]$ok; Text = $t }) }
    $adm = Test-SmAdmin
    & $add 'Administrator' $adm $(if ($adm) { 'Das Fenster läuft als Administrator.' } else { 'Das Fenster läuft nicht als Administrator. Sammeln und Einschalten brauchen Administratorrechte: PowerShell mit "Als Administrator ausführen" öffnen und den Einzeiler erneut einfügen.' })
    $names = @()
    if ($Roles.Dns) { $names += 'DNS' }; if ($Roles.Dhcp) { $names += 'DHCP' }; if ($Roles.Print) { $names += 'Druckserver' }; if ($Roles.Ad) { $names += 'Domänencontroller (AD)' }
    & $add 'Rollen' ($names.Count -gt 0) $(if ($names.Count) { 'Erkannt: ' + ($names -join ', ') + '. Die anderen Schritte entfallen.' } else { 'Keine der Rollen DNS, DHCP, Druckserver oder Domänencontroller gefunden.' })
    & $add 'Tauschordner' $ShareConnected $(if ($ShareConnected) { 'Der Tauschordner ist verbunden.' } else { 'Der Tauschordner ist nicht verbunden. Sammeln geht, Hochladen erst nach "Ordner prüfen".' })
    $free = $FreeBytes
    if ($free -lt 0) { try { $free = (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath((Get-SmAsRoot))))).AvailableFreeSpace } catch { $free = -1 } }
    if ($free -lt 0) { & $add 'Freier Platz' $false 'Der freie Platz konnte nicht gelesen werden.' }
    else { & $add 'Freier Platz' ($free -ge $script:SmAsMinFreeBytes) ('Auf dem Systemlaufwerk sind {0} frei{1}.' -f (Format-SmSize $free), $(if ($free -lt $script:SmAsMinFreeBytes) { ' (empfohlen: mindestens ' + (Format-SmSize $script:SmAsMinFreeBytes) + ' für ZIP und Export)' } else { '' })) }
    [pscustomobject]@{ Roles = $Roles; Items = $items.ToArray(); Ok = (-not (@($items | Where-Object { -not $_.Ok }).Count)) }
}

# ---------------------------------------------------------------- Sammelordner und vorgemerkte Dateien

function Get-SmAsRoot {
    if ($script:SmAsDataRoot) { return $script:SmAsDataRoot }
    Get-SmDnsStateDir
}

function New-SmAsStageDir {
    <# Neuer, gehärteter Sammelordner dieser Sitzung: ProgramData\ServerMigration\Assistent\Sammlung-<GUID> (nie unter %TEMP%). #>
    $root = Get-SmAsRoot
    Protect-SmDnsStateDir -Path $root
    $a = Join-Path $root 'Assistent'
    Protect-SmDnsStateDir -Path $a
    $d = Join-Path ([IO.Path]::GetFullPath($a)) ('Sammlung-' + [guid]::NewGuid().ToString('N'))
    Protect-SmDnsStateDir -Path $d
    Assert-SmDhcpNoReparse -Path $d
    $d
}

function Remove-SmAsStageDir {
    <# Löscht nur einen Ordner Sammlung-<GUID> direkt unter ...\Assistent (Pfad per GetFullPath geprüft, keine Verknüpfung). #>
    param([string]$Dir)
    if (-not $Dir) { return }
    $full = [IO.Path]::GetFullPath($Dir).TrimEnd('\')
    $base = [IO.Path]::GetFullPath((Join-Path (Get-SmAsRoot) 'Assistent')).TrimEnd('\')
    if ((Split-Path -Leaf $full) -notmatch $script:SmAsStagePattern) { return }
    if ((Split-Path -Parent $full) -ine $base) { return }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return }
    if ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
}

function Clear-SmAsOrphans {
    <# Start des Server-Fensters: verwaiste Sammelordner früherer Läufe (älter als 24 h, Besitzer Administratoren oder SYSTEM) löschen. #>
    Remove-SmWorkOrphans -Root (Join-Path (Get-SmAsRoot) 'Assistent') -NamePattern $script:SmAsStagePattern
}

function Get-SmAsAllowedRoots {
    <# Ordner, aus denen Dateien vorgemerkt und hochgeladen werden dürfen: Sammelordner dieser Sitzung, Print und AD (jeweils gehärtet). #>
    param([string]$StageDir)
    $adRoot = if ($script:SmAdDataRoot) { $script:SmAdDataRoot } else { Join-Path $env:ProgramData 'ServerMigration' }
    $r = @((Get-SmPrintFolder), (Join-Path $adRoot 'AD'))
    if ($StageDir) { $r += $StageDir }
    @($r | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
}

function Test-SmAsStagePath {
    <# Prüft eine Datei: Name per Whitelist, direkt in einem erlaubten Ordner, kein ReparsePoint, nicht leer. Liefert den vollen Pfad oder wirft. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Roots)
    $full = [IO.Path]::GetFullPath($Path)
    $leaf = Split-Path -Leaf $full
    if ($leaf -notmatch '^[\w.\-]+$' -or $leaf.Length -gt 200) { throw "Der Dateiname ist nicht erlaubt: $leaf" }
    $dir = (Split-Path -Parent $full).TrimEnd('\')
    if (-not (@($Roots | Where-Object { $_ -ieq $dir }).Count)) { throw 'Die Datei liegt nicht in einem erlaubten Ordner des Assistenten.' }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Die Datei fehlt: $leaf" }
    foreach ($p in $dir, $full) { if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Verknüpfung (ReparsePoint) statt Datei oder Ordner, abgebrochen: $leaf" } }
    if ((Get-Item -LiteralPath $full -Force).Length -eq 0) { throw "Die Datei ist leer: $leaf" }
    $full
}

function Add-SmAsStaged {
    <# Merkt eine Datei für den Upload vor: Name, Größe, SHA256. Eine vorgemerkte Datei gleichen Namens wird ersetzt. Liefert den Eintrag. #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Path)
    $full = Test-SmAsStagePath -Path $Path -Roots (Get-SmAsAllowedRoots -StageDir $State.StageDir)
    $name = Split-Path -Leaf $full
    foreach ($old in @($State.Staged | Where-Object { $_.Name -ieq $name })) { $State.Staged.Remove($old) }
    $item = [pscustomobject]@{
        Id = [guid]::NewGuid().ToString('N'); Source = $Source; Kind = $Kind; Name = $name; Path = $full
        Length = (Get-Item -LiteralPath $full -Force).Length; Sha256 = (Get-SmSha256Local -Path $full); Selected = $true
    }
    [void]$State.Staged.Add($item)
    $item
}

function Clear-SmAsStaged {
    <# Entfernt die vorgemerkten Dateien eines Schritts (vor einem erneuten Sammeln). Dateien im Sammelordner werden gelöscht, die in Print und AD bleiben. #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Source)
    foreach ($it in @($State.Staged | Where-Object { $_.Source -eq $Source })) {
        $State.Staged.Remove($it)
        try {
            if ($State.StageDir -and (Split-Path -Parent $it.Path).TrimEnd('\') -ieq ([IO.Path]::GetFullPath($State.StageDir).TrimEnd('\')) -and (Test-Path -LiteralPath $it.Path -PathType Leaf)) { Remove-Item -LiteralPath $it.Path -Force -ErrorAction SilentlyContinue }
        }
        catch { }
    }
}

# ---------------------------------------------------------------- Sammeln (ohne Hochladen), laufen im Job

function Invoke-SmAsDnsCollect {
    <# DNS: Logdatei plus Metadaten als ZIP in den Sammelordner. Leerer Pfad = Windows-Standard. #>
    param([Parameter(Mandatory)][string]$StageDir, [AllowEmptyString()][string]$LogPath, [scriptblock]$Log = { param($m) }, [scriptblock]$Progress)
    New-SmDnsLogPackage -LogPath $LogPath -OutDir $StageDir -Log $Log -Progress $Progress
}

function Invoke-SmAsDhcpCollect {
    <# DHCP: Export-DhcpServer (mit oder ohne Leases) samt Zusammenfassung als ZIP in den Sammelordner; die Zwischendateien (XML, JSON) werden gelöscht. #>
    param([Parameter(Mandatory)][string]$StageDir, [switch]$NoLeases, [scriptblock]$Log = { param($m) })
    $pre = Test-SmDhcpPrecheck -Mode Export
    if (-not $pre.Ok) { throw ('Vorprüfung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    Assert-SmDhcpNoReparse -Path $StageDir
    $exp = New-SmDhcpExport -WorkDir $StageDir -Log $Log -NoLeases:$NoLeases
    foreach ($f in $script:SmDhcpXmlEntry, $script:SmDhcpSummaryEntry) { Remove-Item -LiteralPath (Join-Path $StageDir $f) -Force -ErrorAction SilentlyContinue }
    [void](Write-SmDhcpAudit -Action 'Export (Assistent, vorgemerkt)' -Text ('{0}, {1} Bereiche v4, {2} v6, {3}' -f $exp.Name, @($exp.Summary.Scopes4).Count, @($exp.Summary.Scopes6).Count, $(if ($NoLeases) { 'ohne Leases' } else { 'mit Leases' })) -Log $Log)
    [pscustomobject]@{ Path = $exp.Path; Name = $exp.Name; Length = $exp.Length }
}

function Invoke-SmAsAdCollect {
    <# AD: Übersichtsbericht (nur lesend) als JSON im gehärteten AD-Ordner. #>
    param([scriptblock]$Log = { param($m) })
    & $Log 'AD: lese Gesamtstruktur, Domänencontroller, FSMO, Replikation und dcdiag ...'
    $o = Get-SmAdOverview
    $path = New-SmAdReport -Overview $o
    [pscustomobject]@{ Path = $path; Name = (Split-Path -Leaf $path); Length = (Get-Item -LiteralPath $path).Length }
}

# ---------------------------------------------------------------- Hochladen

function Publish-SmAsItems {
    <#
    .SYNOPSIS
        Lädt die vorgemerkten Dateien nacheinander in den Tauschordner (große in Teilen). Eine fehlgeschlagene Datei bricht die anderen nicht ab.
    .DESCRIPTION
        Vor dem Hochladen wird jede Datei neu geprüft (erlaubter Ordner, Name, kein ReparsePoint) und mit FileShare.Read gehalten; ihr SHA256 muss dem
        vorgemerkten entsprechen, sonst wird sie nicht hochgeladen. Progress bekommt (Index ab 1, Anzahl, Name, gesendete Bytes, Gesamtbytes).
        Liefert je Datei ein Ergebnis: Name, Source, Kind, Length, Sha256, Ok, Error.
    #>
    param(
        [Parameter(Mandatory)]$Share, [Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string[]]$Roots,
        [scriptblock]$Progress, [scriptblock]$Log = { param($m) }, [long]$ChunkSize = $script:SmChunkSize
    )
    $count = @($Items).Count
    if ($count -eq 0) { throw 'Keine Dateien zum Hochladen gewählt.' }
    $i = 0
    foreach ($it in @($Items)) {
        $i++
        $res = [pscustomobject]@{ Name = [string]$it.Name; Source = [string]$it.Source; Kind = [string]$it.Kind; Length = [long]$it.Length; Sha256 = [string]$it.Sha256; Ok = $false; Error = '' }
        $held = $null
        try {
            $full = Test-SmAsStagePath -Path ([string]$it.Path) -Roots $Roots
            $held = Open-SmDhcpHeldFile -Dir (Split-Path -Parent $full) -Path $full
            if ($held.Sha256 -ne [string]$it.Sha256) { throw 'Die Datei hat sich seit dem Vormerken geändert (SHA256 passt nicht). Bitte den Schritt erneut ausführen.' }
            & $Log ('Lade hoch ({0} von {1}): {2}' -f $i, $count, $res.Name)
            $idx = $i; $nm = $res.Name; $pr = $Progress
            $cb = { param($sent, $total) if ($pr) { & $pr $idx $count $nm $sent $total } }.GetNewClosure()
            $remote = Send-SmShareFile -Share $Share -Path $full -ChunkSize $ChunkSize -Progress $cb
            $res.Length = [long]$remote.Length
            $res.Ok = $true
            & $Log ('Im Tauschordner: {0} ({1}), SHA256 {2}' -f $res.Name, (Format-SmSize $res.Length), (Format-SmAsHash $res.Sha256))
        }
        catch {
            $res.Error = [string]$_.Exception.Message
            & $Log ('Fehler bei {0}: {1}' -f $res.Name, $res.Error)
        }
        finally { if ($held) { $held.Handle.Dispose() } }
        $res
    }
}

function Format-SmAsHash {
    <# GekÃ¼rzte SHA256 fÃ¼r die Anzeige: erste 8 und letzte 4 Zeichen (wie der Chip). #>
    param([string]$Sha)
    if ($Sha.Length -le 14) { return $Sha }
    $Sha.Substring(0, 8) + 'â€¦' + $Sha.Substring($Sha.Length - 4)
}

function Format-SmAsChecksums {
    <# Text zum Kopieren: je hochgeladener Datei "Bezeichnung: SHA256". Für Print heißen die Zeilen Export und Inventur (so versteht sie die Seite Print am neuen Server). #>
    param([Parameter(Mandatory)][object[]]$Results)
    $lines = foreach ($r in @($Results | Where-Object { $_.Ok })) {
        $label = switch ([string]$r.Kind) { 'PrintExport' { 'Export' } 'PrintInventory' { 'Inventur' } default { [string]$r.Name } }
        '{0}: {1}' -f $label, $r.Sha256
    }
    @($lines) -join "`r`n"
}

function Format-SmAsSummary {
    <# Zusammenfassung nach dem Hochladen (Text für die Anzeige). #>
    param([Parameter(Mandatory)][object[]]$Results)
    $ok = @($Results | Where-Object { $_.Ok })
    $bad = @($Results | Where-Object { -not $_.Ok })
    $total = [long](($ok | Measure-Object -Property Length -Sum).Sum)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add(('{0} von {1} Dateien hochgeladen ({2}).' -f $ok.Count, @($Results).Count, (Format-SmSize $total)))
    foreach ($r in $ok) { $l.Add(('  {0}  ({1})  SHA256 {2}' -f $r.Name, (Format-SmSize $r.Length), (Format-SmAsHash $r.Sha256))) }
    foreach ($r in $bad) { $l.Add(('  FEHLER {0}: {1}' -f $r.Name, $r.Error)) }
    $l -join "`r`n"
}

# ---------------------------------------------------------------- Oberfläche

function Get-SmAssistantUiNames {
    $n = @('TxtServer', 'BoxAdmin', 'BtnRefresh', 'TxtShareState', 'TxtFiles', 'BtnUpload', 'TxtProgress', 'PrgUpload',
        'BtnAsBack', 'BtnAsSkip', 'BtnAsNext', 'BtnAsCheck', 'TxtAsCheckState', 'PnlAsCheckRows',
        'BtnAsDnsRead', 'TxtAsDnsState', 'TxtAsDnsDetail', 'BoxAsDnsOff', 'TxtAsDnsPath', 'TxtAsDnsMax', 'BtnAsDnsEnable', 'BoxAsDnsOn', 'TxtAsDnsLogInfo', 'BtnAsDnsCollect', 'PrgAsDns', 'TxtAsDnsResult',
        'ChkAsDhcpNoLeases', 'BtnAsDhcp', 'TxtAsDhcpResult',
        'TxtAsPrintLog', 'BtnAsPrintStatus', 'BtnAsPrintExport', 'TxtAsPrintDays', 'BtnAsPrintCollect', 'TxtAsPrintResult',
        'BtnAsAd', 'TxtAsAdResult',
        'PnlAsFiles', 'TxtAsFilesEmpty', 'BtnAsUpload', 'TxtAsUploadState', 'BoxAsSummary', 'TxtAsSummary', 'BtnAsCopySha')
    foreach ($k in $script:SmAsStepKeys) { $n += @("BdgAs$k", "TxtAsNum$k", "TxtAsState$k", "BtnAsGo$k", "PnlAs$k") }
    $n
}

function Get-SmAssistantPageXaml {
    <# Seite "Dieser Server": UI\ServerStart.xaml mit den Schrittzeilen (je Schritt Nummer, Titel, Zustand) und der Protokollkarte. #>
    param([Parameter(Mandatory)][string]$Root)
    $xaml = [IO.File]::ReadAllText((Join-Path $Root 'UI\ServerStart.xaml'), [Text.Encoding]::UTF8)
    $rows = New-Object System.Text.StringBuilder
    $no = 0
    foreach ($k in $script:SmAsStepKeys) {
        $no++
        [void]$rows.AppendLine(('<Grid Margin="0,0,0,8"><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>' +
                '<Border x:Name="BdgAs{0}" Style="{{DynamicResource StepBadge}}"><TextBlock x:Name="TxtAsNum{0}" Text="{1}" Style="{{DynamicResource StepNumber}}"/></Border>' +
                '<Button x:Name="BtnAsGo{0}" Grid.Column="1" Content="{2}" Style="{{DynamicResource LinkButton}}" HorizontalAlignment="Left" AutomationProperties.Name="Zu Schritt {1}: {2}"/>' +
                '<TextBlock x:Name="TxtAsState{0}" Grid.Column="2" Style="{{DynamicResource Hint}}" VerticalAlignment="Center" Text="offen"/></Grid>') -f @($k, $no, $script:SmAsTitles[$k]))
    }
    $xaml = $xaml.Replace('<!--SCHRITTE-->', $rows.ToString())
    $xaml.Replace('<!--PROTOKOLL-->', (Get-SmLogCardXaml))
}

function Set-SmAsStepVisual {
    <# Schrittzeile: Zahl im Kreis in der Farbe des Zustands, Zustandstext, nicht installierte Schritte gedimmt. Nur Text und Farben, keine Symbolschrift. #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$State, [bool]$Current)
    $b = $Ui["BdgAs$Key"]; $n = $Ui["TxtAsNum$Key"]; $t = $Ui["TxtAsState$Key"]; $g = $Ui["BtnAsGo$Key"]
    $bgKey = 'Divider'; $fgKey = 'MutedText'
    switch ($State) {
        'Done' { $bgKey = 'SuccessBg'; $fgKey = 'Success' }
        'Running' { $bgKey = 'AccentSubtle'; $fgKey = 'Primary' }
        'Error' { $bgKey = 'ErrorBg'; $fgKey = 'DangerText' }
    }
    $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, $bgKey)
    $n.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $fgKey)
    $t.Text = Get-SmAsStateText $State
    $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $(if ($State -eq 'Error') { 'DangerText' } elseif ($State -eq 'Done') { 'Success' } else { 'MutedText' }))
    $g.FontWeight = if ($Current) { [System.Windows.FontWeights]::Bold } else { [System.Windows.FontWeights]::Normal }
    $g.IsEnabled = ($State -ne 'NotInstalled')
    $b.Opacity = if ($State -eq 'NotInstalled') { 0.5 } else { 1 }
}

function Confirm-SmAs {
    param([Parameter(Mandatory)][string]$Text, [string]$Title = 'Bitte bestätigen')
    [System.Windows.MessageBox]::Show($Text, $Title, 'YesNo', 'Question') -eq 'Yes'
}

function Initialize-SmAssistantPage {
    <#
    .SYNOPSIS
        Verdrahtet die Startseite. GetShare liefert den verbundenen Tauschordner oder $null, RefreshShare liest die Dateiliste des Ordners neu.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$GetShare,
        [Parameter(Mandatory)][scriptblock]$AddLog, [scriptblock]$RefreshShare = { }
    )
    $st = New-SmAsState
    $script:SmAs = @{ Ui = $Ui; Modules = $JobModules; GetShare = $GetShare; Log = $AddLog; Refresh = $RefreshShare; State = $st; Busy = $false; Rows = @{}; DnsStatus = $null; PrintLogOn = $false; CheckedOnce = $false }
    $Ui.TxtAsDnsPath.Text = $script:SmDnsDefaultPath
    $Ui.TxtAsDnsMax.Text = [string]$script:SmDnsDefaultMaxMB
    $Ui.TxtAsPrintDays.Text = '90'
    $Ui.BtnAsPrintCollect.IsEnabled = $false
    $Ui.BtnAsDnsCollect.IsEnabled = $false
    foreach ($k in $script:SmAsStepKeys) {
        $Ui["BtnAsGo$k"].Add_Click({ param($src, $e) Show-SmAsStep ([string]$src.Name.Substring(7)) })   # Schluessel aus dem Namen BtnAsGo<Schritt>; Tag bleibt dem Symbol vorbehalten
    }
    $Ui.BtnAsBack.Add_Click({ $c = $script:SmAs; $t = Get-SmAsNavTarget -State $c.State -Direction Back; if ($t) { Show-SmAsStep $t } })
    $Ui.BtnAsNext.Add_Click({ $c = $script:SmAs; $t = Get-SmAsNavTarget -State $c.State -Direction Next; if ($t) { Show-SmAsStep $t } })
    $Ui.BtnAsSkip.Add_Click({
            $c = $script:SmAs
            try { $t = Skip-SmAsStep -State $c.State } catch { & $c.Log ('Assistent: ' + $_.Exception.Message); return }
            & $c.Log ('Schritt übersprungen: ' + $script:SmAsTitles[$c.State.Current])
            Update-SmAsView
            if ($t) { Show-SmAsStep $t }
        })
    $Ui.BtnAsCheck.Add_Click({ Start-SmAsCheck })
    $Ui.BtnAsDnsRead.Add_Click({ Update-SmAsDns })
    $Ui.BtnAsDnsEnable.Add_Click({ Start-SmAsDnsEnable })
    $Ui.BtnAsDnsCollect.Add_Click({ Start-SmAsDnsCollect })
    $Ui.BtnAsDhcp.Add_Click({ Start-SmAsDhcp })
    $Ui.BtnAsPrintStatus.Add_Click({ Update-SmAsPrintLog })
    $Ui.BtnAsPrintExport.Add_Click({ Start-SmAsPrintExport })
    $Ui.BtnAsPrintCollect.Add_Click({ Start-SmAsPrintCollect })
    $Ui.BtnAsAd.Add_Click({ Start-SmAsAd })
    $Ui.BtnAsUpload.Add_Click({ Start-SmAsUpload })
    $Ui.BtnAsCopySha.Add_Click({
            $c = $script:SmAs; $txt = Format-SmAsChecksums -Results @($c.State.Results)
            if ($txt) { [System.Windows.Clipboard]::SetText($txt); Show-SmCopied -Button $c.Ui.BtnAsCopySha }
        })
    Update-SmAsView
}

function Close-SmAssistantPage {
    <# Beim Schließen des Fensters: den Sammelordner dieser Sitzung löschen (die Dateien in Print und AD bleiben, siehe Sicherheits-Checkliste 12). #>
    if ($script:SmAs -and $script:SmAs.State.StageDir) { Remove-SmAsStageDir -Dir $script:SmAs.State.StageDir; $script:SmAs.State.StageDir = $null }
}

function Get-SmAsStageDirSafe {
    <# Sammelordner der Sitzung, bei Bedarf neu angelegt. #>
    $st = $script:SmAs.State
    if (-not $st.StageDir -or -not (Test-Path -LiteralPath $st.StageDir -PathType Container)) { $st.StageDir = New-SmAsStageDir }
    $st.StageDir
}

function Update-SmAsView {
    <# Zeigt Schrittzeilen, den aktuellen Schritt und die Knöpfe Zurück, Überspringen, Weiter passend zum Zustand. #>
    $c = $script:SmAs; $u = $c.Ui; $st = $c.State
    foreach ($k in $script:SmAsStepKeys) {
        Set-SmAsStepVisual -Ui $u -Key $k -State $st.Steps[$k].State -Current ($k -eq $st.Current)
        $u["PnlAs$k"].Visibility = if ($k -eq $st.Current) { 'Visible' } else { 'Collapsed' }
    }
    $busy = [bool]$c.Busy
    $u.BtnAsBack.IsEnabled = (-not $busy) -and [bool](Get-SmAsNavTarget -State $st -Direction Back)
    $u.BtnAsNext.IsEnabled = (-not $busy) -and [bool](Get-SmAsNavTarget -State $st -Direction Next)
    $u.BtnAsSkip.IsEnabled = (-not $busy) -and ($st.Current -ne 'Upload')
    $u.BtnAsNext.Visibility = if ($st.Current -eq 'Upload') { 'Collapsed' } else { 'Visible' }
    $u.BtnAsSkip.Visibility = if ($st.Current -eq 'Upload') { 'Collapsed' } else { 'Visible' }
    foreach ($k in $script:SmAsStepKeys) { $u["BtnAsGo$k"].IsEnabled = ($st.Steps[$k].State -ne 'NotInstalled') -and (-not $busy) }
}

function Show-SmAsStep {
    param([Parameter(Mandatory)][string]$Key)
    $c = $script:SmAs
    if ($c.Busy -or -not $c.State.Steps.Contains($Key) -or $c.State.Steps[$Key].State -eq 'NotInstalled') { return }
    $c.State.Current = $Key
    Update-SmAsView
    switch ($Key) {
        'Dns' { if (-not $c.DnsStatus) { Update-SmAsDns } }
        'Print' { Update-SmAsPrintLog }
        'Upload' { Update-SmAsFileList }
    }
}

function Set-SmAsBusy {
    param([bool]$Busy)
    $script:SmAs.Busy = $Busy
    $u = $script:SmAs.Ui
    foreach ($n in 'BtnAsCheck', 'BtnAsDnsRead', 'BtnAsDnsEnable', 'BtnAsDnsCollect', 'BtnAsDhcp', 'BtnAsPrintStatus', 'BtnAsPrintExport', 'BtnAsPrintCollect', 'BtnAsAd', 'BtnAsUpload', 'BtnUpload') { $u[$n].IsEnabled = -not $Busy }
    $u.PrgAsDns.Visibility = 'Collapsed'
    if (-not $Busy) {
        # Knöpfe, die vom Zustand abhängen, wieder passend setzen
        $u.BtnAsDnsCollect.IsEnabled = [bool]($script:SmAs.DnsStatus -and $script:SmAs.DnsStatus.LogExists)
        $u.BtnAsPrintCollect.IsEnabled = [bool]$script:SmAs.PrintLogOn
        $u.BtnUpload.IsEnabled = [bool](& $script:SmAs.GetShare)
        $u.BtnAsUpload.IsEnabled = ($script:SmAs.State.Staged.Count -gt 0)
    }
    Update-SmAsView
}

function Write-SmAsJobLog {
    param($State)
    $line = $null
    while ($State.Log.TryDequeue([ref]$line)) { & $script:SmAs.Log $line }
}

function Start-SmAsJob {
    <#
    Gemeinsamer Ablauf eines Schritts: Zustand "läuft", Oberfläche sperren, Auftrag im eigenen Runspace, danach "erledigt" oder "Fehler".
    OnOk($result) setzt Detail und Ergebnis. $Result ist das letzte Ausgabeobjekt des Auftrags.
    #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Params = @{}, [Parameter(Mandatory)][scriptblock]$OnOk, [string]$ProgressName, [scriptblock]$OnFail, [switch]$KeepState)   # ProgressName: Fortschrittsbalken (Sent/Total des Auftrags)
    $c = $script:SmAs
    if ($c.Busy) { return }
    $c.JobKey = $Key; $c.ProgressName = $ProgressName; $c.OnOk = $OnOk; $c.OnFail = $OnFail; $c.KeepState = [bool]$KeepState
    if (-not $KeepState) { Set-SmAsStepState -State $c.State -Key $Key -Value Running -Detail '' }
    Set-SmAsBusy $true
    if ($ProgressName) { $p = $c.Ui[$ProgressName]; $p.Value = 0; $p.Visibility = 'Visible' }
    [void](Start-SmJob -Modules $c.Modules -Params $Params -Script $Script -OnTick { param($s) Write-SmAsJobLog $s; $cc = $script:SmAs; if ($cc.ProgressName -and $s.Total -gt 0) { $cc.Ui[$cc.ProgressName].Value = [math]::Min(100, 100 * $s.Sent / $s.Total) } } -OnDone {
            param($result, $err)
            $c2 = $script:SmAs
            Set-SmAsBusy $false
            if ($err) {
                if (-not $c2.KeepState) { Set-SmAsStepState -State $c2.State -Key $c2.JobKey -Value Error -Detail $err }
                & $c2.Log ('{0}: Fehler: {1}' -f $script:SmAsTitles[$c2.JobKey], $err)
                if ($c2.OnFail) { & $c2.OnFail $err }
                Update-SmAsView; return
            }
            $r = if (@($result).Count) { @($result)[-1] } else { $null }
            & $c2.OnOk $r
            Update-SmAsView
        })
}

# ---- Schritt 1

function Start-SmAsCheck {
    <# Prüft den Server (Rollen, Admin, Tauschordner, Platz). Mit -Auto nur beim ersten Mal (Start des Fensters). #>
    param([switch]$Auto)
    $c = $script:SmAs
    if ($Auto -and $c.CheckedOnce) { return }
    $c.CheckedOnce = $true
    $c.Ui.TxtAsCheckState.Text = 'Prüfe …'
    Start-SmAsJob -Key 'Check' -Params @{ Share = [bool](& $c.GetShare) } -Script {
        param($State, $P)
        Get-SmAsCheck -ShareConnected $P.Share
    } -OnOk {
        param($r)
        $c2 = $script:SmAs; $u = $c2.Ui
        Set-SmAsRoles -State $c2.State -Roles $r.Roles
        $u.PnlAsCheckRows.Children.Clear()
        foreach ($it in $r.Items) {
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.TextWrapping = 'Wrap'; $tb.Margin = '0,0,0,6'
            $tb.Text = '{0}: {1}' -f $it.Name, $it.Text
            $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $(if ($it.Ok) { 'Text' } else { 'DangerText' }))
            [void]$u.PnlAsCheckRows.Children.Add($tb)
        }
        $u.TxtAsCheckState.Text = if ($r.Ok) { 'Alles in Ordnung.' } else { 'Es gibt Hinweise (siehe unten). Der Ablauf geht trotzdem weiter.' }
        Set-SmAsStepState -State $c2.State -Key 'Check' -Value Done -Detail $u.TxtAsCheckState.Text
        & $c2.Log ('Server geprüft: ' + (($r.Items | ForEach-Object { '{0} {1}' -f $_.Name, $(if ($_.Ok) { 'ok' } else { 'Hinweis' }) }) -join ', '))
    }
}

# ---- Schritt DNS

function Update-SmAsDns {
    $c = $script:SmAs; $u = $c.Ui
    $u.TxtAsDnsState.Text = 'Lese Status …'
    Start-SmAsJob -Key 'Dns' -KeepState -Script { param($State, $P) Get-SmDnsStatus } -OnFail {
        param($e)
        $u2 = $script:SmAs.Ui; $script:SmAs.DnsStatus = $null
        $u2.TxtAsDnsState.Text = 'Nicht verfügbar'; $u2.TxtAsDnsDetail.Text = $e
        $u2.BoxAsDnsOff.Visibility = 'Collapsed'; $u2.BoxAsDnsOn.Visibility = 'Collapsed'
    } -OnOk {
        param($s)
        $c2 = $script:SmAs; $u2 = $c2.Ui; $c2.DnsStatus = $s
        $u2.TxtAsDnsState.Text = if ($s.LoggingOn) { 'Logging ist EIN' } else { 'Logging ist AUS' }
        $u2.TxtAsDnsDetail.Text = 'Datei: {0}{3}, max. {1} MB{2}' -f $s.Path, $s.MaxMB, $(if ($s.Packets.Count) { ', Pakete: ' + ($s.Packets -join ', ') } else { '' }), $(if ($s.PathIsDefault) { ' (Windows-Standard, der Pfad ist nicht gesetzt)' } else { '' })
        $u2.BoxAsDnsOff.Visibility = if ($s.LoggingOn) { 'Collapsed' } else { 'Visible' }
        $u2.BoxAsDnsOn.Visibility = if ($s.LoggingOn) { 'Visible' } else { 'Collapsed' }
        $u2.BtnAsDnsCollect.IsEnabled = [bool]$s.LogExists
        $u2.TxtAsDnsLogInfo.Text = if ($s.LogExists) { 'Logdatei vorhanden: {0} ({1}).' -f $s.FullPath, (Format-SmSize $s.LogBytes) } elseif ($s.LoggingOn) { 'Das Logging ist an, aber unter {0} gibt es noch keine Logdatei. Später noch einmal prüfen.' -f $s.FullPath } else { '' }
    }
}

function Start-SmAsDnsEnable {
    $c = $script:SmAs; $u = $c.Ui
    $plan = Get-SmDnsEnablePlan -Path $u.TxtAsDnsPath.Text -MaxMB $u.TxtAsDnsMax.Text
    if (-not $plan.Ok) { foreach ($e in $plan.Errors) { & $c.Log ('DNS-Logging: ' + $e) }; $u.TxtAsDnsResult.Text = ($plan.Errors -join ' '); return }
    $msg = "Das DNS-Logging wird eingeschaltet.`n`nLogdatei: $($plan.Path)`nMaximale Größe: $($plan.MaxMB) MB`nPakete: $($plan.Packets -join ', ')`n`nDer jetzige Zustand wird gesichert und kann auf der Seite DNS mit 'Logging ausschalten' wiederhergestellt werden. Fortfahren?"
    if (-not (Confirm-SmAs $msg 'DNS-Logging einschalten')) { & $c.Log 'DNS-Logging einschalten abgebrochen.'; return }
    Start-SmAsJob -Key 'Dns' -KeepState -Params @{ Plan = $plan } -Script {
        param($State, $P)
        Enable-SmDnsLogging -Plan $P.Plan -Log { param($m) $State.Log.Enqueue($m) }
        'ok'
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        $d = 'Logging eingeschaltet. Die Logs später sammeln (nach einigen Tagen Betrieb), dann in diesem Schritt "Logs sammeln".'
        $c2.Ui.TxtAsDnsResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Dns' -Value Done -Detail $d
        $c2.DnsStatus = $null
        Update-SmAsDns
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsDnsResult.Text = 'Fehlgeschlagen: ' + $e }
}

function Start-SmAsDnsCollect {
    $c = $script:SmAs; $u = $c.Ui
    $s = $c.DnsStatus
    if (-not $s -or -not $s.LogExists) { $u.TxtAsDnsResult.Text = 'Keine Logdatei vorhanden.'; return }
    if (-not (Confirm-SmAs "Die DNS-Logdatei wird mit Metadaten (Servername, Zeitzone, Forwarder, Zonen, Domänencontroller) in ein ZIP gepackt und für den Upload vorgemerkt. Hochgeladen wird erst im letzten Schritt.`n`nDie Logdatei enthält Client-Adressen und Namen (personenbezogene Daten). Nach dem Projekt im Tauschordner und lokal löschen.`n`nFortfahren?" 'DNS-Logs sammeln')) { & $c.Log 'DNS-Logs sammeln abgebrochen.'; return }
    try { $dir = Get-SmAsStageDirSafe } catch { $u.TxtAsDnsResult.Text = 'Sammelordner nicht möglich: ' + $_.Exception.Message; return }
    Clear-SmAsStaged -State $c.State -Source 'Dns'
    $u.TxtAsDnsResult.Text = 'Packe …'
    Start-SmAsJob -Key 'Dns' -ProgressName 'PrgAsDns' -Params @{ Dir = $dir; Path = $s.Path } -Script {
        param($State, $P)
        Invoke-SmAsDnsCollect -StageDir $P.Dir -LogPath $P.Path -Log { param($m) $State.Log.Enqueue($m) } -Progress { param($sent, $total) $State.Sent = $sent; $State.Total = $total }
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        $it = Add-SmAsStaged -State $c2.State -Source 'Dns' -Kind 'DnsLogs' -Path $r.Path
        $d = 'Vorgemerkt: {0} ({1}). Hochgeladen wird im letzten Schritt.' -f $it.Name, (Format-SmSize $it.Length)
        $c2.Ui.TxtAsDnsResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Dns' -Value Done -Detail $d
        & $c2.Log ('DNS: ' + $d)
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsDnsResult.Text = 'Fehlgeschlagen: ' + $e }
}

# ---- Schritt DHCP

function Start-SmAsDhcp {
    $c = $script:SmAs; $u = $c.Ui
    $noLeases = [bool]$u.ChkAsDhcpNoLeases.IsChecked
    if (-not (Confirm-SmAs (Get-SmDhcpExportText -NoLeases:$noLeases).Replace('und als ZIP in den Tauschordner gelegt', 'und als ZIP für den Upload vorgemerkt (hochgeladen wird im letzten Schritt)') 'DHCP exportieren')) { & $c.Log 'DHCP-Export abgebrochen.'; return }
    try { $dir = Get-SmAsStageDirSafe } catch { $u.TxtAsDhcpResult.Text = 'Sammelordner nicht möglich: ' + $_.Exception.Message; return }
    Clear-SmAsStaged -State $c.State -Source 'Dhcp'
    $u.TxtAsDhcpResult.Text = 'Exportiere …'
    Start-SmAsJob -Key 'Dhcp' -Params @{ Dir = $dir; NoLeases = $noLeases } -Script {
        param($State, $P)
        Invoke-SmAsDhcpCollect -StageDir $P.Dir -NoLeases:$P.NoLeases -Log { param($m) $State.Log.Enqueue($m) }
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        $it = Add-SmAsStaged -State $c2.State -Source 'Dhcp' -Kind 'DhcpExport' -Path $r.Path
        $d = 'Vorgemerkt: {0} ({1}, Export samt Zusammenfassung, {2}).' -f $it.Name, (Format-SmSize $it.Length), $(if ([bool]$c2.Ui.ChkAsDhcpNoLeases.IsChecked) { 'ohne Leases' } else { 'mit Leases' })
        $c2.Ui.TxtAsDhcpResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Dhcp' -Value Done -Detail $d
        & $c2.Log ('DHCP: ' + $d)
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsDhcpResult.Text = 'Fehlgeschlagen: ' + $e }
}

# ---- Schritt Print

function Update-SmAsPrintLog {
    $c = $script:SmAs; $u = $c.Ui
    $u.TxtAsPrintLog.Text = 'Lese Druckprotokoll …'
    Start-SmAsJob -Key 'Print' -KeepState -Script { param($State, $P) Get-SmPrintLogStatus } -OnFail {
        param($e)
        $script:SmAs.PrintLogOn = $false; $script:SmAs.Ui.TxtAsPrintLog.Text = 'Status nicht lesbar: ' + $e
    } -OnOk {
        param($s)
        $c2 = $script:SmAs
        $c2.PrintLogOn = [bool]$s.Enabled
        $c2.Ui.BtnAsPrintCollect.IsEnabled = $c2.PrintLogOn
        $c2.Ui.TxtAsPrintLog.Text = if ($s.Enabled) { 'Druckprotokoll ist eingeschaltet (Größe {0}). Zugriffe lassen sich sammeln.' -f (Format-SmSize $s.MaxSize) } else { 'Druckprotokoll ist ausgeschaltet. Ohne Protokoll gibt es keine Zugriffe zu sammeln; einschalten auf der Seite Print, später sammeln.' }
    }
}

function Start-SmAsPrintExport {
    $c = $script:SmAs; $u = $c.Ui
    $pre = Test-SmPrintPrecheck -Mode Export
    if (-not $pre.Ok) { $u.TxtAsPrintResult.Text = "Vorprüfung nicht bestanden:`r`n" + (Format-SmPrecheck $pre); return }
    if (-not (Confirm-SmAs "Alle Drucker, Treiber, Ports, Warteschlangen und Freigaben mit PrintBrm exportieren und die Inventur erstellen?`n`nDas kann einige Minuten dauern. Die Dateien liegen im gesicherten Ordner unter ProgramData und werden für den Upload vorgemerkt (hochgeladen wird im letzten Schritt). Der Export ändert nichts am Server." 'Druck-Export')) { & $c.Log 'Druck-Export abgebrochen.'; return }
    Clear-SmAsStaged -State $c.State -Source 'PrintExport'
    $u.TxtAsPrintResult.Text = 'Export läuft …'
    Start-SmAsJob -Key 'Print' -Script {
        param($State, $P)
        Invoke-SmPrintExport -Confirmed
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        foreach ($l in @($r.Log)) { & $c2.Log ([string]$l) }
        $a = Add-SmAsStaged -State $c2.State -Source 'PrintExport' -Kind 'PrintExport' -Path $r.Export.Path
        $b = Add-SmAsStaged -State $c2.State -Source 'PrintExport' -Kind 'PrintInventory' -Path $r.Inventory.Path
        $d = 'Vorgemerkt: {0} ({1}) und {2} ({3}).' -f $a.Name, (Format-SmSize $a.Length), $b.Name, (Format-SmSize $b.Length)
        $c2.Ui.TxtAsPrintResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Print' -Value Done -Detail $d
        & $c2.Log ('Druckserver: ' + $d)
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsPrintResult.Text = 'Fehlgeschlagen: ' + $e }
}

function Start-SmAsPrintCollect {
    $c = $script:SmAs; $u = $c.Ui
    $days = 0
    if (-not [int]::TryParse($u.TxtAsPrintDays.Text, [ref]$days) -or $days -lt 1 -or $days -gt 3650) { $u.TxtAsPrintResult.Text = 'Tage: eine ganze Zahl von 1 bis 3650.'; return }
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { $u.TxtAsPrintResult.Text = "Vorprüfung nicht bestanden:`r`n" + (Format-SmPrecheck $pre); return }
    if (-not (Confirm-SmAs ("Druckzugriffe der letzten {0} Tage sammeln?`n`nDatenschutz: Benutzer- und Rechnernamen aus Ereignis 307 sind personenbezogene Daten und stehen hier im Klartext in der Datei (Pseudonyme gibt es auf der Seite Print). Die Datei wird für den Upload vorgemerkt, hochgeladen wird im letzten Schritt. Nach dem Projekt im Tauschordner und lokal löschen." -f $days) 'Zugriffe sammeln')) { & $c.Log 'Zugriffe sammeln abgebrochen.'; return }
    Clear-SmAsStaged -State $c.State -Source 'PrintAccess'
    $u.TxtAsPrintResult.Text = 'Sammle …'
    Start-SmAsJob -Key 'Print' -Params @{ Days = $days } -Script {
        param($State, $P)
        Invoke-SmPrintCollect -Days $P.Days
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        foreach ($l in @($r.Log)) { & $c2.Log ([string]$l) }
        $it = Add-SmAsStaged -State $c2.State -Source 'PrintAccess' -Kind 'PrintAccess' -Path $r.Path
        $d = 'Vorgemerkt: {0} ({1}, {2} Ereignisse).' -f $it.Name, (Format-SmSize $it.Length), $r.Count
        $c2.Ui.TxtAsPrintResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Print' -Value Done -Detail $d
        & $c2.Log ('Druckserver: ' + $d)
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsPrintResult.Text = 'Fehlgeschlagen: ' + $e }
}

# ---- Schritt AD

function Start-SmAsAd {
    $c = $script:SmAs; $u = $c.Ui
    Clear-SmAsStaged -State $c.State -Source 'Ad'
    $u.TxtAsAdResult.Text = 'Erstelle den Bericht (kann einige Minuten dauern) …'
    Start-SmAsJob -Key 'Ad' -Script {
        param($State, $P)
        Invoke-SmAsAdCollect -Log { param($m) $State.Log.Enqueue($m) }
    } -OnOk {
        param($r)
        $c2 = $script:SmAs
        $it = Add-SmAsStaged -State $c2.State -Source 'Ad' -Kind 'AdReport' -Path $r.Path
        $d = 'Vorgemerkt: {0} ({1}).' -f $it.Name, (Format-SmSize $it.Length)
        $c2.Ui.TxtAsAdResult.Text = $d
        Set-SmAsStepState -State $c2.State -Key 'Ad' -Value Done -Detail $d
        & $c2.Log ('AD: ' + $d)
    } -OnFail { param($e) $script:SmAs.Ui.TxtAsAdResult.Text = 'Fehlgeschlagen: ' + $e }
}

# ---- Schritt Hochladen

function Update-SmAsFileList {
    <# Zeigt die vorgemerkten Dateien: Haken, Name, Größe, SHA256 als Chip, Fortschritt je Datei. Haken bleiben beim Neuaufbau erhalten. #>
    $c = $script:SmAs; $u = $c.Ui; $st = $c.State
    $keep = @{}
    foreach ($id in $c.Rows.Keys) { $keep[$id] = [bool]$c.Rows[$id].Chk.IsChecked }
    $u.PnlAsFiles.Children.Clear(); $c.Rows = @{}
    $u.TxtAsFilesEmpty.Visibility = if ($st.Staged.Count) { 'Collapsed' } else { 'Visible' }
    $ns = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'
    $tpl = @"
<Grid $ns Margin="0,0,0,12">
    <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <CheckBox x:Name="Chk" IsChecked="True" VerticalAlignment="Top" Margin="0,2,10,0"/>
    <StackPanel Grid.Column="1" Margin="0,0,12,0">
        <TextBlock x:Name="Nm" FontWeight="SemiBold" TextWrapping="Wrap" Foreground="{DynamicResource Text}"/>
        <TextBlock x:Name="Info" Style="{DynamicResource Hint}"/>
        <ProgressBar x:Name="Prg" Style="{DynamicResource ThinProgress}" Margin="0,6,0,0" Minimum="0" Maximum="100" Value="0" Visibility="Collapsed"/>
    </StackPanel>
    <Border Grid.Column="2" Style="{DynamicResource Chip}" VerticalAlignment="Top" Padding="12,3,12,3">
        <StackPanel Orientation="Horizontal"><TextBlock Text="SHA256" Style="{DynamicResource ChipLabel}"/><TextBlock x:Name="Sha" Style="{DynamicResource ChipValue}" Margin="0"/></StackPanel>
    </Border>
</Grid>
"@
    foreach ($it in @($st.Staged)) {
        $row = [Windows.Markup.XamlReader]::Parse($tpl)
        $chk = $row.FindName('Chk'); $nm = $row.FindName('Nm'); $info = $row.FindName('Info'); $sha = $row.FindName('Sha'); $prg = $row.FindName('Prg')
        $nm.Text = $it.Name
        $info.Text = '{0}, aus Schritt {1}' -f (Format-SmSize $it.Length), $(switch ($it.Source) { 'Dns' { 'DNS' } 'Dhcp' { 'DHCP' } 'Ad' { 'Active Directory' } default { 'Druckserver' } })
        $sha.Text = Format-SmAsHash $it.Sha256
        $sha.ToolTip = 'SHA256 (vollständig): ' + $it.Sha256
        $chk.IsChecked = if ($keep.ContainsKey($it.Id)) { $keep[$it.Id] } else { $true }
        [void]$u.PnlAsFiles.Children.Add($row)
        $c.Rows[$it.Id] = @{ Chk = $chk; Info = $info; Prg = $prg; Item = $it }
    }
    $u.BtnAsUpload.IsEnabled = ($st.Staged.Count -gt 0) -and (-not $c.Busy)
}

function Start-SmAsUpload {
    $c = $script:SmAs; $u = $c.Ui; $st = $c.State
    $share = & $c.GetShare
    if (-not $share) { $u.TxtAsUploadState.Text = 'Kein Tauschordner verbunden. Oben "Ordner prüfen" wählen.'; return }
    $sel = @($c.Rows.Values | Where-Object { $_.Chk.IsChecked } | ForEach-Object { $_.Item })
    if (-not $sel.Count) { $u.TxtAsUploadState.Text = 'Keine Datei gewählt.'; return }
    $c.UploadNames = @{}; foreach ($r in $c.Rows.Values) { $c.UploadNames[$r.Item.Name] = $r }
    foreach ($r in $c.Rows.Values) { $r.Prg.Value = 0; $r.Prg.Visibility = if ($r.Chk.IsChecked) { 'Visible' } else { 'Collapsed' }; $r.Chk.IsEnabled = $false; $r.Info.Text = '{0}, wartet' -f (Format-SmSize $r.Item.Length) }
    $u.BoxAsSummary.Visibility = 'Collapsed'
    $u.TxtAsUploadState.Text = 'Lade hoch …'
    $roots = Get-SmAsAllowedRoots -StageDir $st.StageDir
    $c.JobKey = 'Upload'; $c.KeepState = $false
    Set-SmAsStepState -State $st -Key 'Upload' -Value Running -Detail ''
    Set-SmAsBusy $true
    [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; Items = $sel; Roots = $roots } -Script {
            param($State, $P)
            Publish-SmAsItems -Share $P.Share -Items $P.Items -Roots $P.Roots -Log { param($m) $State.Log.Enqueue($m) } -Progress { param($i, $n, $name, $sent, $total) $State.Index = $i; $State.Name = $name; $State.Sent = $sent; $State.Total = $total }
        } -OnTick {
            param($s)
            Write-SmAsJobLog $s
            $c3 = $script:SmAs
            if ($s.Name -and $c3.UploadNames -and $c3.UploadNames.ContainsKey([string]$s.Name) -and $s.Total -gt 0) {
                $r = $c3.UploadNames[[string]$s.Name]
                $r.Prg.Value = [math]::Min(100, 100 * $s.Sent / $s.Total)
                $r.Info.Text = '{0} von {1}' -f (Format-SmSize $s.Sent), (Format-SmSize $s.Total)
            }
        } -OnDone {
            param($result, $err)
            $c2 = $script:SmAs; $u2 = $c2.Ui; $st2 = $c2.State
            Set-SmAsBusy $false
            foreach ($r in $c2.Rows.Values) { $r.Chk.IsEnabled = $true }
            if ($err) {
                Set-SmAsStepState -State $st2 -Key 'Upload' -Value Error -Detail $err
                $u2.TxtAsUploadState.Text = 'Fehlgeschlagen: ' + $err
                & $c2.Log ('Hochladen: Fehler: ' + $err)
                foreach ($r in $c2.Rows.Values) { $r.Prg.Visibility = 'Collapsed' }
                Update-SmAsView; return
            }
            $res = @($result | Where-Object { $_ -and $_.PSObject.Properties['Ok'] })
            $st2.Results = $res
            foreach ($x in $res) {
                if ($c2.UploadNames.ContainsKey($x.Name)) {
                    $r = $c2.UploadNames[$x.Name]
                    if ($x.Ok) { $r.Prg.Value = 100; $r.Info.Text = '{0}, hochgeladen' -f (Format-SmSize $x.Length) }
                    else { $r.Prg.Visibility = 'Collapsed'; $r.Info.Text = 'Fehler: ' + $x.Error }
                }
            }
            $bad = @($res | Where-Object { -not $_.Ok }).Count
            $u2.TxtAsSummary.Text = Format-SmAsSummary -Results $res
            $u2.BoxAsSummary.Visibility = 'Visible'
            $u2.BtnAsCopySha.IsEnabled = (@($res | Where-Object { $_.Ok }).Count -gt 0)
            $u2.TxtAsUploadState.Text = if ($bad) { '{0} Datei(en) nicht hochgeladen. Haken lassen, erneut hochladen.' -f $bad } else { 'Alles hochgeladen.' }
            Set-SmAsStepState -State $st2 -Key 'Upload' -Value $(if ($bad) { 'Error' } else { 'Done' }) -Detail $u2.TxtAsUploadState.Text
            & $c2.Log ('Hochladen: ' + $u2.TxtAsUploadState.Text)
            try { & $c2.Refresh } catch { }
            Update-SmAsView
        })
}
