<#
.SYNOPSIS
    Berater-Tool, Seite DNS: ZIPs aus dem Tauschordner holen und auswerten, Ansichten, Filter, Export als Excel oder CSV.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht Modules\SmShell.ps1, SmTausch.ps1, SmDns.ps1). Die Rechenarbeit laeuft in Hintergrundauftraegen
    (Start-SmJob), die Oberflaeche bleibt bedienbar. Die Logik steckt in SmDns.ps1, hier nur Oberflaeche.
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

function Register-SmDnsPage {
    param(
        [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string[]]$JobModules,
        [Parameter(Mandatory)][scriptblock]$GetShare, [Parameter(Mandatory)][scriptblock]$AddLog
    )
    $script:SmDnsAdv = @{ Ui = $Ui; Modules = $JobModules; GetShare = $GetShare; AddLog = $AddLog; Log = $null; Files = @{}; Busy = $false; Share = $null }

    $Ui.GrdDns.Add_AutoGeneratingColumn({
            param($s, $e)
            $e.Column.Header = [regex]::Replace([string]$e.PropertyName, '(?<=[a-z])(?=[A-Z])', ' ')
        })
    $Ui.BtnDnsFind.Add_Click({
            $c = $script:SmDnsAdv; $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'DNS: Zuerst auf der Seite Tauschordner verbinden.'; return }
            if ($c.Busy) { return }
            $c.Busy = $true; $c.Ui.BtnDnsFind.IsEnabled = $false; $c.Ui.TxtDnsLoad.Text = 'Suche …'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share } -Script {
                    param($State, $P)
                    @(Get-SmShareFiles -Share $P.Share | Where-Object { $_.Name -match '^SM-DNS-[\w.\-]+\.zip$' } | Sort-Object Modified -Descending)
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDnsAdv; $u = $c2.Ui; $c2.Busy = $false; $u.BtnDnsFind.IsEnabled = $true
                    if ($err) { $u.TxtDnsLoad.Text = 'Fehler'; & $c2.AddLog ('DNS: ' + $err); return }
                    $files = @($result | Where-Object { $_ -and $_.Name })
                    $c2.Files = @{}; $u.LstDnsZips.Items.Clear()
                    foreach ($f in $files) { $label = '{0}  ({1})' -f $f.Name, (Format-SmSize $f.Length); $c2.Files[$label] = $f; [void]$u.LstDnsZips.Items.Add($label) }
                    $c2.Share = & $c2.GetShare
                    $u.LstDnsZips.Visibility = if ($files.Count) { 'Visible' } else { 'Collapsed' }
                    if ($files.Count) { $u.LstDnsZips.SelectAll() }
                    $u.BtnDnsLoad.IsEnabled = [bool]$files.Count
                    $u.TxtDnsLoad.Text = if ($files.Count) { "$($files.Count) DNS-ZIP(s) im Tauschordner" } else { 'Keine DNS-ZIPs (SM-DNS-*.zip) im Tauschordner' }
                    & $c2.AddLog ('DNS: {0} ZIP(s) im Tauschordner gefunden' -f $files.Count)
                })
        })
    $Ui.BtnDnsLoad.Add_Click({
            $c = $script:SmDnsAdv; $u = $c.Ui
            $sel = @($u.LstDnsZips.SelectedItems | ForEach-Object { $c.Files[[string]$_] } | Where-Object { $_ })
            if (-not $sel.Count) { return }
            Start-SmDnsLoad -Remote $sel
        })
    $Ui.BtnDnsOpen.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Title = 'DNS-ZIP oder Log wählen'; $dlg.Multiselect = $true
            $dlg.Filter = 'DNS-ZIP und Log (*.zip;*.log;*.txt)|*.zip;*.log;*.txt|Alle Dateien (*.*)|*.*'
            if ($dlg.ShowDialog()) { Start-SmDnsLoad -Local @($dlg.FileNames) }
        })
    $Ui.BtnDnsCancel.Add_Click({ $c = $script:SmDnsAdv; if ($c.Log) { $c.Log.Cancel = $true; & $c.AddLog 'DNS: Abbruch angefordert.' } })
    $Ui.CmbDnsView.Add_SelectionChanged({ if ($script:SmDnsAdv.Log) { Show-SmDnsView } })
    $Ui.BtnDnsApply.Add_Click({ Show-SmDnsView })
    $Ui.TxtDnsFilter.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Show-SmDnsView } })
    $Ui.BtnDnsExport.Add_Click({
            $c = $script:SmDnsAdv; $u = $c.Ui
            if (-not $c.Log -or $c.Busy) { return }
            $view = [string]$u.CmbDnsView.SelectedItem.Tag
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Title = 'Tabelle speichern'; $dlg.Filter = 'Excel (*.xlsx)|*.xlsx|CSV (*.csv)|*.csv'; $dlg.FileName = ('dns-{0}-{1:yyyyMMdd}' -f $view, (Get-Date)); $dlg.AddExtension = $true; $dlg.DefaultExt = 'xlsx'
            if (-not $dlg.ShowDialog()) { return }
            $c.Busy = $true; $u.BtnDnsExport.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Params @{ Log = $c.Log; View = $view; Filter = $u.TxtDnsFilter.Text; Path = $dlg.FileName } -Script {
                    param($State, $P)
                    Export-SmTable -Rows ($P.Log.Query($P.View, $P.Filter)) -Path $P.Path
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDnsAdv; $c2.Busy = $false; $c2.Ui.BtnDnsExport.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DNS: Export fehlgeschlagen: ' + $err); return }
                    & $c2.AddLog ('DNS: Tabelle exportiert, {0} Zeilen (Ansicht und Filter wie angezeigt).' -f $result[-1])
                    Show-SmToast 'Tabelle exportiert.'
                })
        })
}

function Start-SmDnsLoad {
    param([object[]]$Remote = @(), [string[]]$Local = @())
    $c = $script:SmDnsAdv; $u = $c.Ui
    if ($c.Busy) { return }
    Initialize-SmDnsEngine
    $log = New-SmDnsLog
    $c.Log = $log; $c.Busy = $true
    $order = [string]$u.CmbDnsDate.SelectedItem.Tag
    $u.BtnDnsLoad.IsEnabled = $false; $u.BtnDnsFind.IsEnabled = $false; $u.BtnDnsOpen.IsEnabled = $false; $u.BtnDnsCancel.IsEnabled = $true
    $u.BtnDnsExport.IsEnabled = $false; $u.BtnDnsApply.IsEnabled = $false; $u.CmbDnsView.IsEnabled = $false
    $u.PrgDnsLoad.Value = 0; $u.PrgDnsLoad.Visibility = 'Visible'; $u.TxtDnsLoad.Text = 'Starte …'
    & $c.AddLog ('DNS: Auswertung gestartet ({0} Datei(en))' -f ($Remote.Count + $Local.Count))
    [void](Start-SmJob -Modules $c.Modules -Params @{ Log = $log; Remote = $Remote; Local = $Local; Share = $c.Share; Order = $order; Reverse = [bool]$u.ChkDnsReverse.IsChecked } -OnTick {
            param($s)
            $c2 = $script:SmDnsAdv; $u2 = $c2.Ui
            $line = $null; while ($s.Log.TryDequeue([ref]$line)) { & $c2.AddLog $line }
            if ($c2.Log) {
                $tot = [math]::Max(1, $c2.Log.BytesTotal)
                $u2.PrgDnsLoad.Value = [math]::Min(100, 100 * $c2.Log.BytesDone / $tot)
                $u2.TxtDnsLoad.Text = '{0} · {1:N0} Pakete gelesen{2}' -f $s.Text, $c2.Log.RowCount, $(if ($c2.Log.BytesTotal -gt 0) { ' · ' + (Format-SmSize $c2.Log.BytesDone) + ' von ' + (Format-SmSize $c2.Log.BytesTotal) } else { '' })
            }
        } -Script {
            param($State, $P)
            $log = $P.Log
            $work = $null
            $tempFull = [IO.Path]::GetFullPath($env:TEMP)
            try {
                foreach ($f in @($P.Remote)) {
                    $State.Text = 'Lade ' + $f.Name
                    $name = [string]$f.Name
                    if ($name -notmatch '^SM-DNS-[\w.\-]+\.zip$') { $State.Log.Enqueue('Dateiname uebersprungen (nicht erlaubt).'); continue }
                    if ($f.Length -gt $script:SmDnsLimits.MaxZipBytes) { $State.Log.Enqueue("Zu gross, uebersprungen: $name"); continue }
                    if (-not $work) { $work = Join-Path $tempFull ('ServerMigration-dnsload-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory -Path $work) }
                    $zip = Join-Path $work $name
                    Receive-SmShareFile -Share $P.Share -Name $name -OutFile $zip -MaxBytes $script:SmDnsLimits.MaxZipBytes
                    $State.Text = 'Werte aus: ' + $name
                    $r = Import-SmDnsZip -Log $log -Path $zip -DateFormat $null
                    foreach ($w in $r.Warnings) { $State.Log.Enqueue("$name`: $w") }
                    if ($r.Meta) { $State.Log.Enqueue(('{0}: Server {1}, Kultur {2}, Datumsformat {3}' -f $name, $r.Meta.Server, $r.Meta.Culture, $r.Meta.DateFormat)) }
                    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                }
                foreach ($path in @($P.Local)) {
                    $State.Text = 'Werte aus: ' + (Split-Path -Leaf $path)
                    if ($path -match '(?i)\.zip$') {
                        $r = Import-SmDnsZip -Log $log -Path $path -DateFormat $null
                        foreach ($w in $r.Warnings) { $State.Log.Enqueue("$(Split-Path -Leaf $path): $w") }
                    }
                    else { Add-SmDnsLogFile -Log $log -Path $path -Order $P.Order }
                }
            }
            finally {
                if ($work) {
                    $wf = [IO.Path]::GetFullPath($work)
                    if ($wf.StartsWith($tempFull.TrimEnd('\') + '\ServerMigration-dnsload-', [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $wf -Recurse -Force -ErrorAction SilentlyContinue }
                }
            }
            if ($P.Reverse -and $log.RowCount -gt 0) {
                $State.Text = 'Loese Namen der Clients auf'
                $ips = @($log.Query('Clients', '') | Select-Object -First 300 | Where-Object { -not $log.Known.ContainsKey($_.Ip) } | ForEach-Object { $_.Ip })
                $names = Resolve-SmDnsReverse -Ips $ips
                foreach ($k in $names.Keys) { $log.SetReverse($k, $names[$k]) }
            }
            foreach ($line in $log.Sources) { $State.Log.Enqueue('DNS: ' + $line) }
        } -OnDone {
            param($result, $err)
            $c2 = $script:SmDnsAdv; $u2 = $c2.Ui; $log2 = $c2.Log
            $c2.Busy = $false
            $u2.BtnDnsFind.IsEnabled = $true; $u2.BtnDnsOpen.IsEnabled = $true; $u2.BtnDnsCancel.IsEnabled = $false
            $u2.BtnDnsLoad.IsEnabled = [bool]$u2.LstDnsZips.Items.Count
            $u2.PrgDnsLoad.Visibility = 'Collapsed'
            if ($err) { $u2.TxtDnsLoad.Text = 'Fehlgeschlagen'; & $c2.AddLog ('DNS: Fehler: ' + $err); if (-not $log2 -or $log2.RowCount -eq 0) { return } }
            if (-not $log2 -or $log2.RowCount -eq 0) { $u2.TxtDnsLoad.Text = 'Keine DNS-Pakete gefunden'; $u2.TxtDnsPeriod.Text = ''; return }
            $u2.TxtDnsLoad.Text = 'Fertig'
            $u2.TxtDnsPeriod.Text = 'Zeitraum der Logs: {0} bis {1}  ·  {2:N0} Pakete aus {3:N0} Zeilen{4}{5}' -f $log2.FirstText, $log2.LastText, $log2.RowCount, $log2.Lines,
            $(if ($log2.Skipped) { ('  ·  {0:N0} Zeilen nicht lesbar' -f $log2.Skipped) } else { '' }), $(if ($log2.Truncated) { '  ·  gekürzt (Zeilenlimit erreicht)' } else { '' })
            $u2.CmbDnsView.IsEnabled = $true; $u2.BtnDnsApply.IsEnabled = $true; $u2.BtnDnsExport.IsEnabled = $true
            $u2.CmbDnsView.SelectedIndex = 0
            Show-SmDnsView
        })
}

function Show-SmDnsView {
    $c = $script:SmDnsAdv; $u = $c.Ui; $log = $c.Log
    if (-not $log -or $c.Busy) { return }
    $view = [string]$u.CmbDnsView.SelectedItem.Tag
    $c.Busy = $true; $u.TxtDnsCount.Text = 'Berechne …'
    [void](Start-SmJob -Modules $c.Modules -Params @{ Log = $log; View = $view; Filter = $u.TxtDnsFilter.Text } -Script {
            param($State, $P)
            $P.Log.GetPage($P.View, $P.Filter, 5000)
        } -OnDone {
            param($result, $err)
            $c2 = $script:SmDnsAdv; $u2 = $c2.Ui; $c2.Busy = $false
            if ($err) { $u2.TxtDnsCount.Text = 'Fehler'; & $c2.AddLog ('DNS: ' + $err); return }
            $page = $result[-1]
            $u2.GrdDns.ItemsSource = $page.Items
            $u2.TxtDnsCount.Text = if ($page.Cut) { 'Angezeigt: {0:N0} von {1:N0} Treffern. Der Export enthält alle Treffer.' -f $page.Items.Count, $page.Total } else { '{0:N0} Treffer' -f $page.Total }
        })
}
