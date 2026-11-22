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
. (Join-Path $root 'Modules\SmTausch.ps1')
. (Join-Path $root 'Modules\SmPaket.ps1')
. (Join-Path $root 'Modules\SmProjekte.ps1')
$jobModules = @((Join-Path $root 'Modules\SmTausch.ps1'), (Join-Path $root 'Modules\SmPaket.ps1'), (Join-Path $root 'Modules\SmProjekte.ps1'))

$startPage = @'
<ScrollViewer xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Style="{DynamicResource PageScroll}">
    <StackPanel Margin="40,32,40,28" MaxWidth="900" HorizontalAlignment="Left">
        <TextBlock Text="Tauschordner und Server-Paket" Style="{DynamicResource PageTitle}"/>
        <TextBlock Style="{DynamicResource Subtitle}" Text="Der Tauschordner ist ein SharePoint- oder OneDrive-Ordner, der mit 'Jeder mit dem Link kann bearbeiten' geteilt ist. Darüber kommt das Server-Paket zum Kunden und kommen Ergebnisse zurück."/>

        <Border Style="{DynamicResource CardBox}" Margin="0,20,0,0" Background="{DynamicResource Card}" Padding="20,16">
            <StackPanel>
                <TextBlock Text="1  Tauschordner verbinden" Style="{DynamicResource CardTitle}"/>
                <TextBlock Style="{DynamicResource Hint}" Margin="0,4,0,8" Text="Freigabelink des Ordners einfügen. Ablaufdatum setzen und den Link nach dem Projekt löschen."/>
                <TextBox x:Name="TxtLink" Padding="8,6" AutomationProperties.Name="Freigabelink des Tauschordners"/>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                    <Button x:Name="BtnConnect" Content="Verbinden" Style="{DynamicResource PrimaryButton}" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtShareState" Text="Nicht verbunden" VerticalAlignment="Center" Foreground="{DynamicResource MutedText}"/>
                </StackPanel>
                <TextBox x:Name="TxtFiles" Style="{DynamicResource SelectableText}" Margin="0,10,0,0" MaxHeight="120" AcceptsReturn="True" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" Visibility="Collapsed"/>
            </StackPanel>
        </Border>

        <Border Style="{DynamicResource CardBox}" Margin="0,16,0,0" Background="{DynamicResource Card}" Padding="20,16">
            <StackPanel>
                <TextBlock Text="2  Server-Paket ablegen" Style="{DynamicResource CardTitle}"/>
                <TextBlock Style="{DynamicResource Hint}" Margin="0,4,0,8" Text="Baut das Paket für das Server-Fenster, legt es im Tauschordner ab (große Dateien in Teilen) und erzeugt den Einzeiler mit Prüfsumme."/>
                <StackPanel Orientation="Horizontal">
                    <Button x:Name="BtnPublish" Content="Paket ablegen" Style="{DynamicResource PrimaryButton}" IsEnabled="False" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtProgress" VerticalAlignment="Center" Foreground="{DynamicResource MutedText}"/>
                </StackPanel>
                <ProgressBar x:Name="PrgUpload" Style="{DynamicResource ThinProgress}" Margin="0,10,0,0" Minimum="0" Maximum="100" Value="0" Visibility="Collapsed"/>
            </StackPanel>
        </Border>

        <Border x:Name="BoxOneLiner" Style="{DynamicResource CardBox}" Margin="0,16,0,0" Background="{DynamicResource Card}" Padding="20,16" Visibility="Collapsed">
            <StackPanel>
                <TextBlock Text="3  Einzeiler für den Server" Style="{DynamicResource CardTitle}"/>
                <TextBlock Style="{DynamicResource Hint}" Margin="0,4,0,8" Text="Auf dem Server in einer PowerShell einfügen (Administrator). Stimmt die Prüfsumme nicht, wird nichts ausgeführt. Die Skriptfreigabe gilt nur für diesen PowerShell-Prozess."/>
                <TextBlock Foreground="{DynamicResource Warning}" FontWeight="SemiBold" TextWrapping="Wrap" Margin="0,0,0,8" Text="Link mit kurzem Ablaufdatum anlegen und nach dem Projekt löschen."/>
                <TextBox x:Name="TxtOneLiner" Style="{DynamicResource SelectableText}" AcceptsReturn="True" TextWrapping="Wrap" MaxHeight="140" VerticalScrollBarVisibility="Auto" FontFamily="{DynamicResource MonoFont}" FontSize="12"/>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                    <Button x:Name="BtnCopy" Content="Einzeiler kopieren" Tag="&#xE8C8;" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtSha" VerticalAlignment="Center" Foreground="{DynamicResource MutedText}" FontFamily="{DynamicResource MonoFont}" FontSize="12"/>
                </StackPanel>
            </StackPanel>
        </Border>

        <TextBlock Text="Protokoll" Style="{DynamicResource FieldLabel}" Margin="0,20,0,6"/>
        <TextBox x:Name="TxtLog" Style="{DynamicResource SelectableText}" AcceptsReturn="True" TextWrapping="Wrap" MinHeight="90" MaxHeight="220" VerticalScrollBarVisibility="Auto" FontSize="12"/>
    </StackPanel>
</ScrollViewer>
'@

$pages = @(
    @{ Key = 'Start'; Title = 'Tauschordner'; Glyph = 0xE753; Xaml = $startPage }
    @{ Key = 'Projekte'; Title = 'Projekte'; Glyph = 0xE8F1; Xaml = (Get-SmProjectPageXaml -Root $root) }
    @{ Key = 'DNS'; Title = 'DNS'; Glyph = 0xE774; Phase = 3; Text = 'Logging einschalten, Logs sammeln, Clients und DNS-Server auswerten.' }
    @{ Key = 'DHCP'; Title = 'DHCP'; Glyph = 0xE839; Phase = 4; Text = 'Bereiche, Reservierungen und Leases exportieren, importieren und vergleichen.' }
    @{ Key = 'Print'; Title = 'Print'; Glyph = 0xE749; Phase = 5; Text = 'Drucker, Treiber und Ports exportieren und importieren, Zugriffe auswerten.' }
    @{ Key = 'AD'; Title = 'Active Directory'; Glyph = 0xE77B; Phase = 6; Text = 'FSMO-Rollen, DSRM-Kennwort, Funktionsebenen und Schema mit Vorprüfungen.' }
)
$w = New-SmWindow -Root $root -Title 'Server-Migration' -Subtitle 'Berater-Tool' -Version ('Version ' + $ToolVersion) -Pages $pages -Theme $Theme
$ui = $w.Ui
Test-SmWindowNames @('TxtLink', 'BtnConnect', 'TxtShareState', 'TxtFiles', 'BtnPublish', 'TxtProgress', 'PrgUpload', 'BoxOneLiner', 'TxtOneLiner', 'BtnCopy', 'TxtSha', 'TxtLog',
    'NavStart', 'NavProjekte', 'NavDNS', 'NavDHCP', 'NavPrint', 'NavAD', 'BtnTheme', 'BtnMinimize', 'BtnMaximize', 'BtnClose', 'NavList', 'PageHost')
Test-SmWindowNames (Get-SmProjectUiNames)
if ($ParseOnly) { 'PARSE OK'; return }

$script:Share = $null
function Add-Log([string]$Line) {
    $ui.TxtLog.AppendText(('{0:HH:mm:ss}  {1}' -f (Get-Date), $Line) + "`r`n")
    $ui.TxtLog.ScrollToEnd()
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
                if ($err) { $script:Share = $null; $ui.BtnPublish.IsEnabled = $false; $ui.TxtShareState.Text = 'Nicht erreichbar'; Add-Log ('Fehler: ' + $err); return }
                $r = $result[-1]
                $script:Share = $r.Share
                $ui.TxtShareState.Text = 'Verbunden: ' + $r.Share.Name
                $ui.BtnPublish.IsEnabled = $true
                $ui.TxtFiles.Text = if (@($r.Files).Count) { (@($r.Files) | ForEach-Object { '{0}  ({1})' -f $_.Name, (Format-SmSize $_.Length) }) -join "`r`n" } else { '(Ordner ist leer)' }
                $ui.TxtFiles.Visibility = 'Visible'
                Add-Log ('Verbunden: {0} ({1} Dateien)' -f $r.Share.Name, @($r.Files).Count)
            })
    })

$ui.BtnPublish.Add_Click({
        if (-not $script:Share) { return }
        $ui.BtnPublish.IsEnabled = $false; $ui.BoxOneLiner.Visibility = 'Collapsed'; $ui.PrgUpload.Value = 0; $ui.TxtProgress.Text = 'Baue Paket …'
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
                $ui.TxtOneLiner.Text = $r.OneLiner
                $ui.TxtSha.Text = 'SHA256 ' + $r.Package.Sha256
                $ui.BoxOneLiner.Visibility = 'Visible'
                Add-Log ('Paket im Tauschordner: {0} ({1}), SHA256 {2}' -f $r.Remote.Name, (Format-SmSize $r.Remote.Length), $r.Package.Sha256)
            })
    })

$ui.BtnCopy.Add_Click({
        if ($ui.TxtOneLiner.Text) { [System.Windows.Clipboard]::SetText($ui.TxtOneLiner.Text); Show-SmToast 'Einzeiler kopiert.' }
    })

# aktives Projekt: sein Tauschordner-Link kommt in die Seite Tauschordner (verbunden wird per Klick)
Initialize-SmProjectPage -Ui $ui -JobModules $jobModules -AddLog ${function:Add-Log} -OnActiveChanged {
    param($project)
    if ($project -and $project['ShareLink']) { $ui.TxtLink.Text = [string]$project['ShareLink']; $ui.TxtShareState.Text = 'Link aus dem Projekt übernommen, bitte Verbinden'; Add-Log ('Tauschordner-Link aus Projekt: ' + $project['Name']) }
}

Select-SmPage 'Start'
[void]$w.Window.ShowDialog()
