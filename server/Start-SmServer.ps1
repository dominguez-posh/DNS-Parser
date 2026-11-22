#Requires -Version 5.1
<#
.SYNOPSIS
    Server-Migration, Server-Fenster: laeuft auf dem Zielserver (ueber die Bastion), gestartet mit dem Einzeiler aus dem Tauschordner.
.DESCRIPTION
    Phase 1 (Geruest). Zeigt die Verbindung zum Tauschordner und laedt Dateien dorthin (grosse in Teilen).
    Die Bereiche DNS, DHCP, Print und AD sind Platzhalter fuer die naechsten Phasen. Windows PowerShell 5.1, WPF.
.PARAMETER ShareLink
    Freigabelink des Tauschordners. Ohne Angabe arbeitet das Fenster nur lokal.
.PARAMETER Theme
    Hell, Dunkel oder wie Windows (Standard).
.PARAMETER ParseOnly
    Nur fuer Tests: baut das Fenster, prueft die Steuerelemente und zeigt nichts an.
#>
[CmdletBinding()]
param(
    [string]$ShareLink,
    [ValidateSet('System', 'Light', 'Dark')][string]$Theme = 'System',
    [switch]$ParseOnly
)
$ErrorActionPreference = 'Stop'
$ToolVersion = '0.1.0'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $root 'Modules\SmTheme.ps1')
. (Join-Path $root 'Modules\SmShell.ps1')
. (Join-Path $root 'Modules\SmTausch.ps1')
. (Join-Path $root 'server\SmDnsServer.ps1')
. (Join-Path $root 'Modules\SmDhcp.ps1')
. (Join-Path $root 'server\SmDhcpServer.ps1')
. (Join-Path $root 'Modules\SmPrint.ps1')
. (Join-Path $root 'server\SmPrintServer.ps1')
$jobModules = @((Join-Path $root 'Modules\SmTausch.ps1'))
$dnsJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'server\SmDnsServer.ps1'))
$dhcpJobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'server\SmDnsServer.ps1'), (Join-Path $root 'Modules\SmDhcp.ps1'), (Join-Path $root 'server\SmDhcpServer.ps1'))
$printModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'server\SmDnsServer.ps1'), (Join-Path $root 'Modules\SmPrint.ps1'), (Join-Path $root 'server\SmPrintServer.ps1'))

$startPage = @'
<ScrollViewer xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Style="{DynamicResource PageScroll}">
    <StackPanel Margin="40,32,40,28" MaxWidth="900" HorizontalAlignment="Left">
        <TextBlock Text="Dieser Server" Style="{DynamicResource PageTitle}"/>
        <TextBlock x:Name="TxtServer" Style="{DynamicResource Subtitle}"/>
        <Border x:Name="BoxAdmin" Style="{DynamicResource CardBox}" Margin="0,16,0,0" Background="{DynamicResource WarningBg}" Padding="16,10" Visibility="Collapsed">
            <TextBlock Foreground="{DynamicResource Warning}" TextWrapping="Wrap" Text="Dieses Fenster läuft nicht als Administrator. Für Änderungen bitte PowerShell mit 'Als Administrator ausführen' öffnen und den Einzeiler erneut einfügen."/>
        </Border>

        <Border Style="{DynamicResource CardBox}" Margin="0,20,0,0" Background="{DynamicResource Card}" Padding="20,16">
            <StackPanel>
                <TextBlock Text="Tauschordner" Style="{DynamicResource CardTitle}"/>
                <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
                    <Button x:Name="BtnRefresh" Content="Ordner prüfen" Tag="&#xE72C;" Style="{DynamicResource PrimaryButton}" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtShareState" Text="Kein Tauschordner (nur lokal)" VerticalAlignment="Center" Foreground="{DynamicResource MutedText}"/>
                </StackPanel>
                <TextBox x:Name="TxtFiles" Style="{DynamicResource SelectableText}" Margin="0,10,0,0" MaxHeight="140" AcceptsReturn="True" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" Visibility="Collapsed"/>
                <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
                    <Button x:Name="BtnUpload" Content="Datei hochladen …" Tag="&#xE898;" IsEnabled="False" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtProgress" VerticalAlignment="Center" Foreground="{DynamicResource MutedText}"/>
                </StackPanel>
                <ProgressBar x:Name="PrgUpload" Style="{DynamicResource ThinProgress}" Margin="0,10,0,0" Minimum="0" Maximum="100" Value="0" Visibility="Collapsed"/>
            </StackPanel>
        </Border>

        <TextBlock Text="Protokoll" Style="{DynamicResource FieldLabel}" Margin="0,20,0,6"/>
        <TextBox x:Name="TxtLog" Style="{DynamicResource SelectableText}" AcceptsReturn="True" TextWrapping="Wrap" MinHeight="90" MaxHeight="220" VerticalScrollBarVisibility="Auto" FontSize="12"/>
    </StackPanel>
</ScrollViewer>
'@

$pages = @(
    @{ Key = 'Start'; Title = 'Dieser Server'; Glyph = 0xE977; Xaml = $startPage }
    @{ Key = 'DNS'; Title = 'DNS'; Glyph = 0xE774; Xaml = [IO.File]::ReadAllText((Join-Path $root 'UI\DnsServer.xaml'), [Text.Encoding]::UTF8) }
    @{ Key = 'DHCP'; Title = 'DHCP'; Glyph = 0xE839; Xaml = [IO.File]::ReadAllText((Join-Path $root 'UI\DhcpServer.xaml'), [Text.Encoding]::UTF8) }
    @{ Key = 'Print'; Title = 'Print'; Glyph = 0xE749; Xaml = (Get-SmPrintServerPageXaml -Root $root) }
    @{ Key = 'AD'; Title = 'Active Directory'; Glyph = 0xE77B; Phase = 6; Text = 'FSMO-Rollen, DSRM-Kennwort, Funktionsebenen und Schema mit Vorprüfungen.' }
)
$w = New-SmWindow -Root $root -Title 'Server-Migration' -Subtitle 'Server-Fenster' -Version ('Version ' + $ToolVersion) -Pages $pages -Theme $Theme
$ui = $w.Ui
Test-SmWindowNames @('TxtServer', 'BoxAdmin', 'BtnRefresh', 'TxtShareState', 'TxtFiles', 'BtnUpload', 'TxtProgress', 'PrgUpload', 'TxtLog',
    'TxtDnsState', 'TxtDnsDetail', 'BtnDnsRefresh', 'BoxDnsEnable', 'TxtDnsPath', 'TxtDnsMax', 'BtnDnsEnable', 'BoxDnsOn', 'BtnDnsDisable', 'BoxDnsLogs', 'TxtDnsLogInfo', 'BtnDnsUpload', 'TxtDnsProgress', 'PrgDns',
    'NavStart', 'NavDNS', 'NavDHCP', 'NavPrint', 'NavAD', 'BtnTheme', 'BtnMinimize', 'BtnMaximize', 'BtnClose', 'NavList', 'PageHost')
Test-SmWindowNames @('BtnDhcpCheck', 'TxtDhcpCheck', 'BtnDhcpExport', 'TxtDhcpExport', 'PrgDhcpExport', 'TxtDhcpExportSha', 'ChkDhcpNoLeases', 'BtnDhcpCopySha', 'ChkDhcpAfterNoLeases', 'TxtDhcpShaIn', 'TxtDhcpShaState', 'BtnDhcpFind', 'BtnDhcpDownload', 'LstDhcpExports', 'TxtDhcpDlSha', 'BtnDhcpOpen',
    'BoxDhcpImport', 'TxtDhcpInfo', 'RdoDhcpAll', 'RdoDhcpSel', 'LstDhcpScopes', 'ChkDhcpLeases', 'BtnDhcpImport', 'TxtDhcpImport', 'BtnDhcpAuth', 'TxtDhcpAuth', 'BtnDhcpAfter', 'TxtDhcpAfter', 'BtnDhcpOldList', 'LstDhcpOldScopes', 'BtnDhcpDeactivate')
Test-SmWindowNames (Get-SmPrintServerUiNames)
if ($ParseOnly) { 'PARSE OK'; return }

$script:Share = $null
function Add-Log([string]$Line) {
    $ui.TxtLog.AppendText(('{0:HH:mm:ss}  {1}' -f (Get-Date), $Line) + "`r`n")
    $ui.TxtLog.ScrollToEnd()
}
function Update-Progress($State) {
    if ($State.Total -gt 0) {
        $ui.PrgUpload.Visibility = 'Visible'
        $ui.PrgUpload.Value = [math]::Min(100, 100 * $State.Sent / $State.Total)
        $ui.TxtProgress.Text = '{0} von {1}' -f (Format-SmSize $State.Sent), (Format-SmSize $State.Total)
    }
}

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
$ui.TxtServer.Text = '{0} · {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME
if (-not $isAdmin) { $ui.BoxAdmin.Visibility = 'Visible'; Add-Log 'Das Fenster läuft nicht als Administrator.' }

function Update-Share {
    if (-not $ShareLink) { return }
    $ui.BtnRefresh.IsEnabled = $false; $ui.TxtShareState.Text = 'Verbinde …'
    [void](Start-SmJob -Modules $jobModules -Params @{ Link = $ShareLink } -Script {
            param($State, $P)
            $share = Connect-SmShare -Link $P.Link
            [pscustomobject]@{ Share = $share; Files = @(Get-SmShareFiles -Share $share) }
        } -OnDone {
            param($result, $err)
            $ui.BtnRefresh.IsEnabled = $true
            if ($err) { $script:Share = $null; $ui.BtnUpload.IsEnabled = $false; $ui.TxtShareState.Text = 'Nicht erreichbar'; Add-Log ('Tauschordner: ' + $err); return }
            $r = $result[-1]
            $script:Share = $r.Share
            $ui.TxtShareState.Text = 'Verbunden: ' + $r.Share.Name
            $ui.BtnUpload.IsEnabled = $true
            $ui.TxtFiles.Text = if (@($r.Files).Count) { (@($r.Files) | ForEach-Object { '{0}  ({1})' -f $_.Name, (Format-SmSize $_.Length) }) -join "`r`n" } else { '(Ordner ist leer)' }
            $ui.TxtFiles.Visibility = 'Visible'
            Add-Log ('Tauschordner verbunden: {0} ({1} Dateien)' -f $r.Share.Name, @($r.Files).Count)
        })
}
$ui.BtnRefresh.Add_Click({ Update-Share })

$ui.BtnUpload.Add_Click({
        if (-not $script:Share) { return }
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title = 'Datei für den Tauschordner wählen'
        if (-not $dlg.ShowDialog()) { return }
        $path = $dlg.FileName
        if ((Split-Path -Leaf $path) -notmatch '^[\w.\-]+$') { Add-Log 'Dateiname mit Sonderzeichen oder Leerzeichen: bitte umbenennen (nur Buchstaben, Ziffern, Punkt, Bindestrich, Unterstrich).'; return }
        $ui.BtnUpload.IsEnabled = $false; $ui.PrgUpload.Value = 0; $ui.TxtProgress.Text = 'Lade hoch …'
        Add-Log ('Lade hoch: ' + (Split-Path -Leaf $path))
        [void](Start-SmJob -Modules $jobModules -Params @{ Share = $script:Share; Path = $path } -OnTick { param($s) Update-Progress $s } -Script {
                param($State, $P)
                Send-SmShareFile -Share $P.Share -Path $P.Path -Progress { param($sent, $total) $State.Sent = $sent; $State.Total = $total }
            } -OnDone {
                param($result, $err)
                $ui.BtnUpload.IsEnabled = $true
                if ($err) { $ui.TxtProgress.Text = 'Fehlgeschlagen'; Add-Log ('Fehler: ' + $err); return }
                $ui.TxtProgress.Text = 'Fertig'
                Add-Log ('Im Tauschordner: {0} ({1})' -f $result[-1].Name, (Format-SmSize $result[-1].Length))
                Update-Share
            })
    })

Initialize-SmPrintServerPage -Ui $ui -JobModules $printModules -AddLog ${function:Add-Log} -GetShare { $script:Share }
if (-not $ShareLink) { Add-Log 'Kein Tauschordner angegeben (nur lokal).' }
Register-SmDnsServerPage -Ui $ui -JobModules $dnsJobModules -GetShare { $script:Share } -AddLog { param($m) Add-Log $m }
Register-SmDhcpServerPage -Ui $ui -JobModules $dhcpJobModules -GetShare { $script:Share } -AddLog { param($m) Add-Log $m }
Select-SmPage 'Start'
Update-Share
[void]$w.Window.ShowDialog()
