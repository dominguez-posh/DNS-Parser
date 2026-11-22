<#
.SYNOPSIS
    Phase 6 (Active Directory): gemeinsame Funktionen fuer Server-Fenster und Berater-Tool.
    Zuordnungen (Schema-Version, Funktionsebenen, Betriebssystem), Pruefung der Funktionsebenen (reine Logik),
    Bericht lesen und anzeigen, Seite "Active Directory" im Berater-Tool.
.DESCRIPTION
    Wird per Dot-Source geladen. Der Bericht kommt aus dem Tauschordner und gilt als feindlich (Sicherheits-Checkliste Punkt 7):
    Groessenlimit, JSON nur ueber JavaScriptSerializer, Texte werden gekuerzt und von Steuerzeichen befreit.
    Der Bericht enthaelt keine Geheimnisse (Namen, Standorte, Betriebssysteme, Rollen, Replikationszustand).
    Windows PowerShell 5.1.
#>

$script:SmAdReportSchema = 1
$script:SmAdMaxReportBytes = 4MB
$script:SmAdMaxText = 300
$script:SmAdReportPattern = '^AD-Bericht-[\w.\-]+\.json$'

# objectVersion im Schema -> Server-Version (Microsoft Learn, "Find the Current Active Directory Schema Version")
$script:SmAdSchemaMap = @{
    91 = 'Windows Server 2025'; 88 = 'Windows Server 2019 / 2022'; 87 = 'Windows Server 2016'; 69 = 'Windows Server 2012 R2'; 56 = 'Windows Server 2012'
    47 = 'Windows Server 2008 R2'; 44 = 'Windows Server 2008'; 31 = 'Windows Server 2003 R2'; 30 = 'Windows Server 2003'
}
# Funktionsebenen (Zahlenwerte laut Set-ADDomainMode / Set-ADForestMode); 7 heisst in der Doku auch WinThreshold
$script:SmAdLevelNames = @{ 0 = '2000'; 1 = '2003 Interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }
$script:SmAdRaiseTargets = @(3, 4, 5, 6, 7, 10)

# ---------------------------------------------------------------- Zuordnungen

function Get-SmAdSchemaName {
    <# Server-Version zu einer Schema-Version (objectVersion). Unbekannte Werte werden benannt, nicht geraten. #>
    param([Parameter(Mandatory)][int]$Version)
    if ($script:SmAdSchemaMap.ContainsKey($Version)) { return $script:SmAdSchemaMap[$Version] }
    $newer = @($script:SmAdSchemaMap.Keys | Where-Object { $_ -gt $Version })
    if (-not $newer.Count) { return 'neuer als die bekannte Tabelle' }
    'unbekannte Version'
}

function ConvertTo-SmAdLevelNumber {
    <# 'Windows2016Domain', 'Windows2016Forest', 'WinThreshold', 'Windows2025Forest' oder eine Zahl -> Zahlenwert der Ebene, sonst $null. #>
    param([AllowNull()]$Mode)
    if ($null -eq $Mode) { return $null }
    $s = [string]$Mode
    if ($s -match '^\d+$') { if ($script:SmAdLevelNames.ContainsKey([int]$s)) { return [int]$s } else { return $null } }
    if ($s -match 'WinThreshold') { return 7 }
    if ($s -match '^Windows2003Interim') { return 1 }
    if ($s -match '^Windows(2000|2003|2008R2|2008|2012R2|2012|2016|2025)') {
        switch ($Matches[1]) { '2000' { 0 } '2003' { 2 } '2008' { 3 } '2008R2' { 4 } '2012' { 5 } '2012R2' { 6 } '2016' { 7 } '2025' { 10 } }
        return
    }
    $null
}

function Get-SmAdLevelName {
    param([AllowNull()]$Number)
    if ($null -eq $Number) { return 'unbekannt' }
    if ($script:SmAdLevelNames.ContainsKey([int]$Number)) { return 'Windows Server ' + $script:SmAdLevelNames[[int]$Number] }
    'unbekannt'
}

function Get-SmAdModeParameter {
    <# Zahl -> Wert fuer -DomainMode bzw. -ForestMode (Namen laut Cmdlet-Doku). #>
    param([Parameter(Mandatory)][ValidateSet('Domain', 'Forest')][string]$Scope, [Parameter(Mandatory)][int]$Level)
    if ($script:SmAdRaiseTargets -notcontains $Level) { throw "Zielebene nicht vorgesehen: $Level" }
    'Windows' + ($script:SmAdLevelNames[$Level] -replace ' ', '') + $Scope
}

function ConvertTo-SmAdOsRank {
    <# Betriebssystem eines DC (Text aus AD) -> hoechste Funktionsebene, die er mittragen kann. 2016, 2019 und 2022 teilen sich Ebene 7. #>
    param([AllowNull()][string]$OperatingSystem)
    if (-not $OperatingSystem) { return $null }
    if ($OperatingSystem -match '2025') { return 10 }
    if ($OperatingSystem -match '2022|2019|2016') { return 7 }
    if ($OperatingSystem -match '2012\s*R2') { return 6 }
    if ($OperatingSystem -match '2012') { return 5 }
    if ($OperatingSystem -match '2008\s*R2') { return 4 }
    if ($OperatingSystem -match '2008') { return 3 }
    if ($OperatingSystem -match '2003') { return 2 }
    if ($OperatingSystem -match '2000') { return 0 }
    $null
}

function Get-SmAdLevelTargets {
    <# Ebenen, die ueber der aktuellen liegen und vorgesehen sind. #>
    param([Parameter(Mandatory)][int]$Current)
    @($script:SmAdRaiseTargets | Where-Object { $_ -gt $Current })
}

function Test-SmAdLevelRaise {
    <#
    .SYNOPSIS
        Vorpruefung fuer das Anheben einer Funktionsebene (reine Logik, keine Zugriffe auf AD).
    .DESCRIPTION
        DomainControllers: Objekte mit HostName, Domain, OperatingSystem. Bei Scope Domain zaehlen nur die DCs der Domain (DomainName),
        bei Forest alle. DomainLevels (nur Forest): Hashtable Domain -> Ebene; keine Domain darf unter der Zielebene liegen.
        Liefert Ok, Checks (Name, Ok, Text) und TooOld (Namen der zu alten DCs).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Domain', 'Forest')][string]$Scope, [Parameter(Mandatory)][int]$Target, [Parameter(Mandatory)][int]$Current,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$DomainControllers, [string]$DomainName, [hashtable]$DomainLevels = @{}, [bool]$ReplicationOk = $false
    )
    $checks = New-Object System.Collections.Generic.List[object]
    function Add([string]$n, [bool]$ok, [string]$t) { $checks.Add([pscustomobject]@{ Name = $n; Ok = $ok; Text = $t }) }
    $targetName = Get-SmAdLevelName $Target
    Add 'Zielebene' ($script:SmAdRaiseTargets -contains $Target) ('Ziel: ' + $targetName)
    Add 'Hoeher als jetzt' ($Target -gt $Current) ('Jetzt: {0}, Ziel: {1}' -f (Get-SmAdLevelName $Current), $targetName)
    $scopeDcs = @($DomainControllers | Where-Object { $Scope -eq 'Forest' -or $_.Domain -ieq $DomainName })
    Add 'Domaenencontroller gefunden' ($scopeDcs.Count -gt 0) ('{0} DC(s) im Geltungsbereich' -f $scopeDcs.Count)
    $tooOld = @(); $unknown = @()
    foreach ($dc in $scopeDcs) {
        $rank = ConvertTo-SmAdOsRank $dc.OperatingSystem
        if ($null -eq $rank) { $unknown += [string]$dc.HostName }
        elseif ($rank -lt $Target) { $tooOld += ('{0} ({1})' -f $dc.HostName, $dc.OperatingSystem) }
    }
    Add 'Alle DCs tragen die Zielebene' (-not $tooOld.Count) $(if ($tooOld.Count) { 'Zu alt: ' + ($tooOld -join '; ') } else { 'Alle DCs haben mindestens Windows Server ' + $script:SmAdLevelNames[$Target] })
    Add 'Betriebssysteme erkennbar' (-not $unknown.Count) $(if ($unknown.Count) { 'Nicht erkennbar: ' + ($unknown -join '; ') } else { 'ok' })
    if ($Scope -eq 'Forest') {
        $low = @($DomainLevels.GetEnumerator() | Where-Object { $null -eq $_.Value -or [int]$_.Value -lt $Target } | ForEach-Object { [string]$_.Key })
        Add 'Alle Domaenen auf Zielebene' ($DomainLevels.Count -gt 0 -and -not $low.Count) $(if ($low.Count -or -not $DomainLevels.Count) { 'Erst die Domaene(n) anheben: ' + ($low -join '; ') } else { 'ok' })
    }
    Add 'Replikation in Ordnung' $ReplicationOk $(if ($ReplicationOk) { 'keine Fehler' } else { 'Replikationsfehler oder nicht pruefbar' })
    [pscustomobject]@{ Ok = (-not ($checks | Where-Object { -not $_.Ok })); Checks = $checks.ToArray(); TooOld = $tooOld }
}

function Get-SmAdAdprepServerName {
    <# Server-Version zur Build-Nummer der adprep.exe auf dem Medium (Anzeige, "vermutlich"). #>
    param([AllowNull()][string]$Version)
    if ($Version -notmatch '^\d+\.\d+\.(\d+)') { return $null }
    switch ([int]$Matches[1]) {
        { $_ -ge 26100 } { return @{ Name = 'Windows Server 2025'; Schema = 91 } }
        { $_ -ge 20348 } { return @{ Name = 'Windows Server 2022'; Schema = 88 } }
        { $_ -ge 17763 } { return @{ Name = 'Windows Server 2019'; Schema = 88 } }
        { $_ -ge 14393 } { return @{ Name = 'Windows Server 2016'; Schema = 87 } }
        { $_ -ge 9600 } { return @{ Name = 'Windows Server 2012 R2'; Schema = 69 } }
        { $_ -ge 9200 } { return @{ Name = 'Windows Server 2012'; Schema = 56 } }
    }
    $null
}

# ---------------------------------------------------------------- Bericht (feindliche Eingabe)

function Clear-SmAdText {
    <# Text aus einer fremden Datei: Steuerzeichen raus, gekuerzt. #>
    param([AllowNull()]$Text, [int]$Max = $script:SmAdMaxText)
    if ($null -eq $Text) { return '' }
    $s = ([string]$Text) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    $s
}

function Read-SmAdReport {
    <# Liest einen AD-Bericht (JSON) aus einer Datei. Wirft bei zu grosser, kaputter oder fremder Datei. Liefert ein bereinigtes Objekt. #>
    param([Parameter(Mandatory)][string]$Path)
    $len = (Get-Item -LiteralPath $Path).Length
    if ($len -gt $script:SmAdMaxReportBytes) { throw 'Der Bericht ist zu gross und wird nicht gelesen.' }
    Add-Type -AssemblyName System.Web.Extensions
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]$script:SmAdMaxReportBytes
    $ser.RecursionLimit = 16
    try { $raw = $ser.DeserializeObject([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)) } catch { throw 'Der Bericht ist kein gueltiges JSON.' }
    if ($raw -isnot [System.Collections.IDictionary] -or [int]$raw['Schema'] -ne $script:SmAdReportSchema -or $raw['Kind'] -ne 'AD-Bericht') { throw 'Das ist kein AD-Bericht dieser Version.' }
    function Txt($v) { Clear-SmAdText $v }
    function Rows($list, [string[]]$props) {
        $out = @()
        foreach ($i in @($list | Select-Object -First 500)) {
            if ($i -isnot [System.Collections.IDictionary]) { continue }
            $o = [ordered]@{}; foreach ($p in $props) { $o[$p] = $i[$p] }
            $out += [pscustomobject]$o
        }
        $out
    }
    $f = $raw['Forest']; $d = $raw['Domain']
    $rep = $raw['Replication']
    [pscustomobject]@{
        Created = Txt $raw['Created']; Computer = Txt $raw['Computer']
        Forest = [pscustomobject]@{ Name = Txt $f['Name']; Mode = Txt $f['Mode']; SchemaVersion = [int]$f['SchemaVersion']; SchemaName = Txt $f['SchemaName'] }
        Domain = [pscustomobject]@{ Name = Txt $d['Name']; Mode = Txt $d['Mode'] }
        DomainControllers = @(Rows $raw['DomainControllers'] @('HostName', 'Domain', 'Site', 'OperatingSystem', 'IsGlobalCatalog', 'IsReadOnly') | ForEach-Object {
                [pscustomobject]@{ HostName = Txt $_.HostName; Domain = Txt $_.Domain; Site = Txt $_.Site; OperatingSystem = Txt $_.OperatingSystem; IsGlobalCatalog = [bool]$_.IsGlobalCatalog; IsReadOnly = [bool]$_.IsReadOnly } })
        Fsmo = @(Rows $raw['Fsmo'] @('Role', 'Holder') | ForEach-Object { [pscustomobject]@{ Role = Txt $_.Role; Holder = Txt $_.Holder } })
        Replication = [pscustomobject]@{ Ok = [bool]$rep['Ok']; Failures = @(@($rep['Failures']) | Select-Object -First 200 | ForEach-Object { Txt $_ }) }
        Dcdiag = @(Rows $raw['Dcdiag'] @('Name', 'Ok', 'Lines') | ForEach-Object { [pscustomobject]@{ Name = Txt $_.Name; Ok = [bool]$_.Ok; Lines = @(@($_.Lines) | Select-Object -First 30 | ForEach-Object { Txt $_ }) } })
        Errors = @(@($raw['Errors']) | Select-Object -First 100 | ForEach-Object { Txt $_ })
    }
}

function Format-SmAdReportText {
    <# Anzeigetext fuer einen gelesenen Bericht (Berater-Tool). #>
    param([Parameter(Mandatory)]$Report)
    $l = New-Object System.Collections.Generic.List[string]
    $r = $Report
    $l.Add(('Bericht von {0}, erstellt {1}' -f $r.Computer, $r.Created))
    $l.Add('')
    $fl = ConvertTo-SmAdLevelNumber $r.Forest.Mode; $dl = ConvertTo-SmAdLevelNumber $r.Domain.Mode
    $l.Add(('Gesamtstruktur {0}: Funktionsebene {1}' -f $r.Forest.Name, (Get-SmAdLevelName $fl)))
    $l.Add(('Domaene {0}: Funktionsebene {1}' -f $r.Domain.Name, (Get-SmAdLevelName $dl)))
    $l.Add(('Schema-Version {0} ({1})' -f $r.Forest.SchemaVersion, (Get-SmAdSchemaName $r.Forest.SchemaVersion)))
    $l.Add(''); $l.Add('Domaenencontroller')
    foreach ($dc in $r.DomainControllers) { $l.Add(('  {0}  |  {1}  |  Standort {2}  |  {3}{4}' -f $dc.HostName, $dc.OperatingSystem, $dc.Site, $(if ($dc.IsGlobalCatalog) { 'GC' } else { 'kein GC' }), $(if ($dc.IsReadOnly) { ', RODC' } else { '' }))) }
    $l.Add(''); $l.Add('FSMO-Rollen')
    foreach ($f in $r.Fsmo) { $l.Add(('  {0}: {1}' -f $f.Role, $f.Holder)) }
    $l.Add(''); $l.Add('Replikation: ' + $(if ($r.Replication.Ok) { 'ohne Fehler' } else { 'FEHLER' }))
    foreach ($x in $r.Replication.Failures) { $l.Add('  ' + $x) }
    $l.Add(''); $l.Add('dcdiag')
    foreach ($t in $r.Dcdiag) { $l.Add(('  {0}: {1}' -f $t.Name, $(if ($t.Ok) { 'bestanden' } else { 'FEHLER' }))); if (-not $t.Ok) { foreach ($x in $t.Lines) { $l.Add('      ' + $x) } } }
    if ($r.Errors.Count) { $l.Add(''); $l.Add('Hinweise beim Erstellen'); foreach ($x in $r.Errors) { $l.Add('  ' + $x) } }
    $l -join "`r`n"
}

function Export-SmAdDcTable {
    <# Tabelle der DCs ueber Export-SmTable (Phase 3, CSV/Excel). Gibt es das Modul noch nicht, kommt eine klare Meldung. #>
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Path)
    if (-not (Get-Command Export-SmTable -ErrorAction SilentlyContinue)) { throw 'Der Tabellenexport (Modules\SmExport.ps1) ist in dieser Version noch nicht enthalten.' }
    $rows = @($Report.DomainControllers | ForEach-Object { [pscustomobject]@{ DC = $_.HostName; Domaene = $_.Domain; Standort = $_.Site; Betriebssystem = $_.OperatingSystem; GC = $_.IsGlobalCatalog; RODC = $_.IsReadOnly } })
    Export-SmTable -Rows $rows -Path $Path
}

function New-SmAdWorkDir {
    <# Arbeitsordner fuer einen heruntergeladenen Bericht (nur Daten, nie ausgefuehrt): %LOCALAPPDATA%\ServerMigration\Ad-<GUID>, nicht %TEMP%. Verknuepfungen im Elternordner brechen ab. #>
    $root = if ($script:SmAdWorkRoot) { $script:SmAdWorkRoot } else { Join-Path $env:LOCALAPPDATA 'ServerMigration' }
    if (-not (Test-Path -LiteralPath $root)) { [void](New-Item -ItemType Directory -Path $root -Force) }
    if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Der Arbeitsordner ist eine Verknuepfung, abgebrochen.' }
    $dir = Join-Path $root ('Ad-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $dir)
    $dir
}

# ---------------------------------------------------------------- Seite "Active Directory" im Berater-Tool

function Get-SmAdPageXaml {
    param([Parameter(Mandatory)][string]$Root)
    [IO.File]::ReadAllText((Join-Path $Root 'UI\Ad.xaml'))
}

function Get-SmAdPageUiNames {
    @('BtnAdrList', 'CmbAdrFiles', 'BtnAdrShow', 'BtnAdrExport', 'TxtAdrState', 'TxtAdrReport')
}

function Initialize-SmAdPage {
    <# Verdrahtet die Seite "Active Directory" (UI\Ad.xaml): Berichte im Tauschordner suchen, laden, anzeigen. Nur lesend. #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$AddLog, [Parameter(Mandatory)][scriptblock]$GetShare)
    $script:SmAdPage = @{ Ui = $Ui; Modules = $JobModules; Log = $AddLog; GetShare = $GetShare; Report = $null }
    $Ui.BtnAdrList.Add_Click({
            $st = $script:SmAdPage; $share = & $st.GetShare
            if (-not $share) { $st.Ui.TxtAdrState.Text = 'Zuerst auf der Seite Tauschordner verbinden.'; return }
            $st.Ui.TxtAdrState.Text = 'Suche Berichte ...'
            [void](Start-SmJob -Modules $st.Modules -Params @{ Share = $share } -Script {
                    param($State, $P)
                    @(Get-SmShareFiles -Share $P.Share | Where-Object { $_.Name -match $script:SmAdReportPattern } | Sort-Object Modified -Descending)
                } -OnDone {
                    param($result, $err)
                    $u = $script:SmAdPage.Ui
                    if ($err) { $u.TxtAdrState.Text = 'Fehler beim Lesen des Tauschordners.'; & $script:SmAdPage.Log ('AD: ' + $err); return }
                    $u.CmbAdrFiles.Items.Clear()
                    foreach ($f in @($result | Where-Object { $_ })) { [void]$u.CmbAdrFiles.Items.Add($f.Name) }
                    if ($u.CmbAdrFiles.Items.Count) { $u.CmbAdrFiles.SelectedIndex = 0 }
                    $u.TxtAdrState.Text = '{0} Bericht(e) gefunden.' -f $u.CmbAdrFiles.Items.Count
                })
        })
    $Ui.BtnAdrShow.Add_Click({
            $st = $script:SmAdPage; $share = & $st.GetShare; $name = [string]$st.Ui.CmbAdrFiles.SelectedItem
            if (-not $share -or -not $name) { return }
            if ($name -ne (Split-Path -Leaf $name) -or $name -notmatch $script:SmAdReportPattern) { $st.Ui.TxtAdrState.Text = 'Dateiname nicht erlaubt.'; return }
            $st.Ui.TxtAdrState.Text = 'Lade ...'
            [void](Start-SmJob -Modules $st.Modules -Params @{ Share = $share; Name = $name } -Script {
                    param($State, $P)
                    $dir = New-SmAdWorkDir
                    try { $tmp = Join-Path $dir 'bericht.json'; Receive-SmShareFile -Share $P.Share -Name $P.Name -OutFile $tmp -MaxBytes $script:SmAdMaxReportBytes; Read-SmAdReport -Path $tmp }
                    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
                } -OnDone {
                    param($result, $err)
                    $u = $script:SmAdPage.Ui
                    if ($err) { $u.TxtAdrState.Text = 'Der Bericht konnte nicht gelesen werden.'; & $script:SmAdPage.Log ('AD: ' + $err); return }
                    $script:SmAdPage.Report = $result[-1]
                    $u.TxtAdrReport.Text = Format-SmAdReportText -Report $result[-1]
                    $u.BtnAdrExport.IsEnabled = $true
                    $u.TxtAdrState.Text = 'Bericht angezeigt.'
                })
        })
    $Ui.BtnAdrExport.Add_Click({
            $st = $script:SmAdPage
            if (-not $st.Report) { return }
            if (-not (Get-Command Export-SmTable -ErrorAction SilentlyContinue)) { $st.Ui.TxtAdrState.Text = 'Der Tabellenexport ist in dieser Version noch nicht enthalten.'; return }
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Filter = 'CSV (*.csv)|*.csv|Excel (*.xlsx)|*.xlsx'; $dlg.FileName = 'AD-Domaenencontroller'
            if (-not $dlg.ShowDialog()) { return }
            try { Export-SmAdDcTable -Report $st.Report -Path $dlg.FileName; $st.Ui.TxtAdrState.Text = 'Exportiert.' } catch { $st.Ui.TxtAdrState.Text = 'Export fehlgeschlagen.'; & $st.Log ('AD: ' + $_.Exception.Message) }
        })
}
