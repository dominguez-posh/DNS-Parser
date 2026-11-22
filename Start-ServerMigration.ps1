#Requires -Version 5.1
<#
.SYNOPSIS
    Server-Migration, Berater-Tool: Tauschordner verbinden, Server-Paket ablegen, Einzeiler fuer den Server erzeugen.
.DESCRIPTION
    Phase 1 (Geruest). Die Navigation zeigt schon die spaeteren Bereiche (Projekte, DNS, DHCP, Print, AD) als Platzhalter.
    "Server-Paket ablegen" baut das ZIP fuer das Server-Fenster, legt es im Tauschordner ab (grosse Dateien in Teilen)
    und gibt den Einzeiler mit SHA256 aus. Der Einzeiler laedt das Paket auf dem Server, prueft die Pruefsumme und startet
    erst dann das Server-Fenster. Windows PowerShell 5.1, WPF.
.PARAMETER Theme
    Hell, Dunkel oder wie Windows (Standard).
.PARAMETER ParseOnly
    Nur fuer Tests: baut das Fenster, prueft die Steuerelemente und zeigt nichts an.
#>
[CmdletBinding()]
param(
    [ValidateSet('System', 'Light', 'Dark')][string]$Theme = 'System',
    [switch]$ParseOnly
)
$ErrorActionPreference = 'Stop'
$ToolVersion = '0.1.0'
$root = $PSScriptRoot
. (Join-Path $root 'Modules\SmTheme.ps1')
. (Join-Path $root 'Modules\SmShell.ps1')
. (Join-Path $root 'Modules\SmUi.ps1')
. (Join-Path $root 'Modules\SmTausch.ps1')
. (Join-Path $root 'Modules\SmPaket.ps1')
. (Join-Path $root 'Modules\SmProjekte.ps1')
. (Join-Path $root 'Modules\SmExport.ps1')
. (Join-Path $root 'Modules\SmDns.ps1')
. (Join-Path $root 'Modules\SmDnsUi.ps1')
. (Join-Path $root 'Modules\SmDhcp.ps1')
. (Join-Path $root 'Modules\SmPrint.ps1')
. (Join-Path $root 'Modules\SmAd.ps1')
$jobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmPaket.ps1'), (Join-Path $root 'Modules\SmProjekte.ps1'))
$adJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmAd.ps1'), (Join-Path $root 'Modules\SmExport.ps1'))
$dnsJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmExport.ps1'), (Join-Path $root 'Modules\SmDns.ps1'))
$dhcpJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmDhcp.ps1'))
$printJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmPrint.ps1'))

$startPage = [IO.File]::ReadAllText((Join-Path $root 'UI\Tausch.xaml'), [Text.Encoding]::UTF8).Replace('<!--PROTOKOLL-->', (Get-SmLogCardXaml))

$pages = @(
    @{ Key = 'Start'; Title = 'Tauschordner'; Glyph = 0xE753; Xaml = $startPage }
    @{ Key = 'Projekte'; Title = 'Projekte'; Glyph = 0xE8F1; Xaml = (Get-SmProjectPageXaml -Root $root) }
    @{ Key = 'DNS'; Title = 'DNS'; Glyph = 0xE774; Xaml = [IO.File]::ReadAllText((Join-Path $root 'UI\Dns.xaml'), [Text.Encoding]::UTF8) }
    @{ Key = 'DHCP'; Title = 'DHCP'; Glyph = 0xE839; Xaml = [IO.File]::ReadAllText((Join-Path $root 'UI\Dhcp.xaml'), [Text.Encoding]::UTF8) }
    @{ Key = 'Print'; Title = 'Print'; Glyph = 0xE749; Xaml = (Get-SmPrintPageXaml -Root $root) }
    @{ Key = 'AD'; Title = 'Active Directory'; Glyph = 0xE77B; Xaml = (Get-SmAdPageXaml -Root $root) }
)
$w = New-SmWindow -Root $root -Title 'Server-Migration' -Subtitle 'Berater-Tool' -Version ('Version ' + $ToolVersion) -Pages $pages -Theme $Theme
$ui = $w.Ui
Test-SmWindowNames @('TxtLink', 'BtnConnect', 'TxtShareState', 'TxtFiles', 'BtnPublish', 'TxtProgress', 'PrgUpload', 'BoxOneLiner', 'TxtOneLiner', 'TxtOneLinerPreview', 'BoxCmdPreview', 'BtnCmdToggle', 'BtnCopy', 'BtnCopySha', 'TxtSha', 'BdgStep1', 'TxtStep1', 'BdgStep2', 'TxtStep2', 'BdgStep3', 'TxtStep3',
    'BtnDnsFind', 'BtnDnsLoad', 'BtnDnsOpen', 'BtnDnsCancel', 'LstDnsZips', 'CmbDnsDate', 'ChkDnsReverse', 'PrgDnsLoad', 'TxtDnsLoad', 'TxtDnsPeriod', 'CmbDnsView', 'TxtDnsFilter', 'BtnDnsApply', 'BtnDnsExport', 'GrdDns', 'TxtDnsCount',
    'NavStart', 'NavProjekte', 'NavDNS', 'NavDHCP', 'NavPrint', 'NavAD', 'BtnTheme', 'BtnMinimize', 'BtnMaximize', 'BtnClose', 'NavList', 'PageHost')
Test-SmWindowNames @('BtnDhcpFind', 'BtnDhcpCompare', 'BtnDhcpExport', 'CmbDhcpBefore', 'CmbDhcpAfter', 'ChkDhcpEqual', 'TxtDhcpState', 'TxtDhcpCount', 'GrdDhcp')
Test-SmWindowNames (Get-SmLogUiNames)
Initialize-SmLog -Ui $ui
Initialize-SmCodeBoxes -Ui $ui
Initialize-SmCommandBox -Ui $ui
Set-SmStepState -Ui $ui
Test-SmWindowNames (Get-SmProjectUiNames)
Test-SmWindowNames (Get-SmAdPageUiNames)
$script:Share = $null
Initialize-SmAdPage -Ui $ui -JobModules $adJobModules -AddLog { param($m) Add-Log $m } -GetShare { $script:Share }
Register-SmDnsPage -Ui $ui -JobModules $dnsJobModules -GetShare { $script:Share } -AddLog { param($m) Add-Log $m }
Test-SmWindowNames (Get-SmPrintPageUiNames)
if ($ParseOnly) { 'PARSE OK'; return }

function Add-Log([string]$Line) {
    Add-SmLogLine -Ui $ui -Line $Line
}
function Update-Progress($State) {
    $line = $null
    while ($State.Log.TryDequeue([ref]$line)) { Add-Log $line }
    if ($State.Total -gt 0) {
        $ui.PrgUpload.Visibility = 'Visible'
        $ui.PrgUpload.Value = [math]::Min(100, 100 * $State.Sent / $State.Total)
        $ui.TxtProgress.Text = '{0} von {1}' -f (Format-SmSize $State.Sent), (Format-SmSize $State.Total)
    }
}

$ui.BtnConnect.Add_Click({
        $link = $null
        try { $link = Test-SmShareLink $ui.TxtLink.Text } catch { $ui.TxtShareState.Text = 'Link ungültig'; Add-Log ('Fehler: ' + $_.Exception.Message); return }
        $ui.BtnConnect.IsEnabled = $false; $ui.TxtShareState.Text = 'Verbinde …'; Add-Log 'Verbinde mit dem Tauschordner'
        [void](Start-SmJob -Modules $jobModules -Params @{ Link = $link } -Script {
                param($State, $P)
                $share = Connect-SmShare -Link $P.Link
                [pscustomobject]@{ Share = $share; Files = @(Get-SmShareFiles -Share $share) }
            } -OnDone {
                param($result, $err)
                $ui.BtnConnect.IsEnabled = $true
                if ($err) { $script:Share = $null; $ui.BtnPublish.IsEnabled = $false; $ui.TxtShareState.Text = 'Nicht erreichbar'; Set-SmStepState -Ui $ui; Add-Log ('Fehler: ' + $err); return }
                $r = $result[-1]
                $script:Share = $r.Share
                $ui.TxtShareState.Text = 'Verbunden: ' + $r.Share.Name
                $ui.BtnPublish.IsEnabled = $true
                Set-SmStepState -Ui $ui -Done @(1)
                $ui.TxtFiles.Text = if (@($r.Files).Count) { (@($r.Files) | ForEach-Object { '{0}  ({1})' -f $_.Name, (Format-SmSize $_.Length) }) -join "`r`n" } else { '(Ordner ist leer)' }
                $ui.TxtFiles.Visibility = 'Visible'
                Add-Log ('Verbunden: {0} ({1} Dateien)' -f $r.Share.Name, @($r.Files).Count)
            })
    })

$ui.BtnPublish.Add_Click({
        if (-not $script:Share) { return }
        $ui.BtnPublish.IsEnabled = $false; $ui.BoxOneLiner.Visibility = 'Collapsed'; Set-SmStepState -Ui $ui -Done @(1); $ui.PrgUpload.Value = 0; $ui.TxtProgress.Text = 'Baue Paket …'
        Add-Log 'Baue das Server-Paket und lege es im Tauschordner ab'
        $out = Join-Path $env:TEMP 'ServerMigration-Berater'   # nur das Paket, der Einzeiler wird nie in eine Datei geschrieben
        [void](Start-SmJob -Modules $jobModules -Params @{ Share = $script:Share; Root = $root; Out = $out } -OnTick { param($s) Update-Progress $s } -Script {
                param($State, $P)
                Publish-SmServerPackage -Share $P.Share -RepoRoot $P.Root -OutDir $P.Out -Progress { param($sent, $total) $State.Sent = $sent; $State.Total = $total }
            } -OnDone {
                param($result, $err)
                $ui.BtnPublish.IsEnabled = $true
                if ($err) { $ui.TxtProgress.Text = 'Fehlgeschlagen'; Add-Log ('Fehler: ' + $err); return }
                $r = $result[-1]
                $ui.TxtProgress.Text = 'Fertig'
                Set-SmOneLiner -Ui $ui -Text $r.OneLiner
                Set-SmHashChip -Text $ui.TxtSha -Sha $r.Package.Sha256
                Set-SmStepState -Ui $ui -Done @(1, 2)
                $ui.BoxOneLiner.Visibility = 'Visible'
                Add-Log ('Paket im Tauschordner: {0} ({1}), SHA256 {2}' -f $r.Remote.Name, (Format-SmSize $r.Remote.Length), $r.Package.Sha256)
            })
    })

$ui.BtnCopy.Add_Click({
        if ($ui.TxtOneLiner.Text) { [System.Windows.Clipboard]::SetText($ui.TxtOneLiner.Text); Show-SmCopied -Button $ui.BtnCopy -Text 'Kopiert'; Set-SmStepState -Ui $ui -Done @(1, 2, 3) }
    })
$ui.BtnCopySha.Add_Click({
        if ($ui.TxtSha.Tag) { [System.Windows.Clipboard]::SetText([string]$ui.TxtSha.Tag); Show-SmCopied -Button $ui.BtnCopySha }
    })

# aktives Projekt: sein Tauschordner-Link kommt in die Seite Tauschordner (verbunden wird per Klick)
Initialize-SmProjectPage -Ui $ui -JobModules $jobModules -AddLog ${function:Add-Log} -OnActiveChanged {
    param($project)
    if ($project -and $project['ShareLink'] -and -not (Test-SmShareHostConfirmed $project)) { Add-Log ('Tauschordner-Link aus Projekt NICHT übernommen (Host nicht bestätigt): ' + $project['Name']); return }
    if ($project -and $project['ShareLink']) { $ui.TxtLink.Text = [string]$project['ShareLink']; $ui.TxtShareState.Text = 'Link aus dem Projekt übernommen, bitte Verbinden'; Add-Log ('Tauschordner-Link aus Projekt: ' + $project['Name']) }
}

Register-SmDhcpPage -Ui $ui -JobModules $dhcpJobModules -GetShare { $script:Share } -AddLog { param($m) Add-Log $m }
Initialize-SmPrintPage -Ui $ui -JobModules $printJobModules -AddLog ${function:Add-Log} -GetShare { $script:Share }

Select-SmPage 'Start'
[void]$w.Window.ShowDialog()
