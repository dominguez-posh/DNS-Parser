# Gemeinsame Bausteine der Oberflaeche (beide Fenster): Protokoll, Pruefsummen-Chip, Schrittanzeige, Kopier-Bestaetigung,
# einklappbarer Befehl. Stile dazu: UI\Theme.xaml. Regeln: docs\DESIGN.md. Braucht Modules\SmShell.ps1 (Show-SmToast, Fenster).
# Rein darstellend: nichts hier aendert Daten oder Ablaeufe.

$script:SmLogLines = New-Object 'System.Collections.Generic.List[string]'
$script:SmCopyOrig = @{}
$script:SmLogMax = 500

function Format-SmShortHash {
    <# Lange Hexwerte (Pruefsummen) gekuerzt: erste 8 und letzte 4 Zeichen mit Auslassung. Kurze Werte bleiben unveraendert. #>
    param([string]$Sha, [int]$Head = 8, [int]$Tail = 4)
    if (-not $Sha -or $Sha.Length -le ($Head + $Tail + 1)) { return $Sha }
    $Sha.Substring(0, $Head) + [string][char]0x2026 + $Sha.Substring($Sha.Length - $Tail)
}

function Format-SmLogText {
    <# Kuerzt lange Werte in einer Protokollzeile (Pruefsummen ab 40 Hexzeichen, Links ab 60 Zeichen). Der volle Text bleibt im Tooltip. #>
    param([string]$Line)
    $t = [regex]::Replace($Line, '\b[0-9A-Fa-f]{40,}\b', { param($m) Format-SmShortHash $m.Value })
    [regex]::Replace($t, 'https?://\S{50,}', { param($m) $m.Value.Substring(0, 40) + [string][char]0x2026 })
}

function Get-SmLogKind {
    <# Ordnet eine Protokollzeile Fehler, Hinweis, Erfolg oder Info zu (nur fuer die Darstellung). #>
    param([string]$Line)
    if ($Line -match '(?i)^fehler|\bfehler\b|fehlgeschlagen|nicht erreichbar|nicht lesbar|ung(ue|ü)ltig') { return 'Error' }
    if (($Line -match '(?i)^hinweis|warnung|abgebrochen|nicht als administrator|nicht aktiviert|nicht .bernommen') -or ($Line -cmatch '\bNICHT\b')) { return 'Warn' }
    if ($Line -match '(?i)^(verbunden|tauschordner verbunden|fertig|paket im tauschordner|im tauschordner|hochgeladen|exportiert|heruntergeladen|importiert)|erfolgreich|gespeichert') { return 'Ok' }
    'Info'
}

function Get-SmLogCardXaml {
    <# XAML der Protokollkarte (einklappbar, Kopieren). Namen: BtnLogToggle, BtnLogCopy, TxtLogCount, BoxLogBody, TxtLogEmpty, ScrLog, PnlLog. #>
    @'
<Border Style="{DynamicResource CardBox}" Margin="0,16,0,0" Background="{DynamicResource Card}" Padding="20,12,14,12">
    <StackPanel>
        <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Protokoll" Style="{DynamicResource CardTitle}"/>
                <TextBlock x:Name="TxtLogCount" Style="{DynamicResource Hint}" VerticalAlignment="Center" Margin="10,1,0,0"/>
            </StackPanel>
            <Button x:Name="BtnLogCopy" Grid.Column="1" Content="Kopieren" Style="{DynamicResource GhostButton}" MinHeight="28" Padding="10,4" FontSize="12" Foreground="{DynamicResource MutedText}" ToolTip="Protokoll in die Zwischenablage kopieren" AutomationProperties.Name="Protokoll kopieren"/>
            <Button x:Name="BtnLogToggle" Grid.Column="2" Content="&#xE70E;" Style="{DynamicResource IconButton}" ToolTip="Protokoll ein- oder ausklappen" AutomationProperties.Name="Protokoll ein- oder ausklappen"/>
        </Grid>
        <Border x:Name="BoxLogBody" BorderBrush="{DynamicResource Divider}" BorderThickness="0,1,0,0" Margin="0,8,6,0" Padding="0,10,0,0">
            <Grid>
                <TextBlock x:Name="TxtLogEmpty" Style="{DynamicResource Hint}" Text="Noch keine Einträge."/>
                <ScrollViewer x:Name="ScrLog" Style="{DynamicResource PageScroll}" MaxHeight="220" Focusable="False"><StackPanel x:Name="PnlLog"/></ScrollViewer>
            </Grid>
        </Border>
    </StackPanel>
</Border>
'@
}

function Get-SmLogUiNames { @('BtnLogToggle', 'BtnLogCopy', 'TxtLogCount', 'BoxLogBody', 'TxtLogEmpty', 'ScrLog', 'PnlLog') }

function Initialize-SmLog {
    <# Verdrahtet die Protokollkarte: Einklappen und Kopieren. #>
    param([Parameter(Mandatory)]$Ui)
    $Ui.BtnLogToggle.Add_Click({
            $u = $script:SmWin.Ui
            $open = $u.BoxLogBody.Visibility -ne 'Visible'
            $u.BoxLogBody.Visibility = if ($open) { 'Visible' } else { 'Collapsed' }
            $u.BtnLogToggle.Content = [string][char]$(if ($open) { 0xE70E } else { 0xE70D })
        })
    $Ui.BtnLogCopy.Add_Click({
            if ($script:SmLogLines.Count -eq 0) { return }
            [System.Windows.Clipboard]::SetText(($script:SmLogLines -join "`r`n"))
            Show-SmCopied -Button $script:SmWin.Ui.BtnLogCopy
        })
}

function Add-SmLogLine {
    <# Haengt eine Zeile ans Protokoll: Symbol je Art, Zeit in Mono und gedimmt, Meldung normal, lange Werte gekuerzt. #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string]$Line)
    $time = '{0:HH:mm:ss}' -f (Get-Date)
    [void]$script:SmLogLines.Add($time + '  ' + $Line)
    $kind = Get-SmLogKind $Line
    $short = Format-SmLogText $Line

    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = New-Object System.Windows.Thickness 0, 0, 0, 5
    foreach ($len in @((New-Object System.Windows.GridLength 18), [System.Windows.GridLength]::Auto, (New-Object System.Windows.GridLength 1, 'Star'))) {
        $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = $len; [void]$grid.ColumnDefinitions.Add($cd)
    }
    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Glyph')
    $icon.FontSize = 12; $icon.VerticalAlignment = 'Top'; $icon.Margin = New-Object System.Windows.Thickness 0, 1, 0, 0
    switch ($kind) {
        'Error' { $icon.Text = [string][char]0xE783; $icon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'DangerText') }
        'Warn' { $icon.Text = [string][char]0xE7BA; $icon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Warning') }
        'Ok' { $icon.Text = [string][char]0xE73E; $icon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'SuccessDot') }
    }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'LogTime'); $tb.Text = $time
    $msg = New-Object System.Windows.Controls.TextBlock
    $msg.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'LogText'); $msg.Text = $short
    if ($kind -eq 'Error') { $msg.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'DangerText') }
    elseif ($kind -eq 'Warn') { $msg.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Warning') }
    if ($short -ne $Line) { $grid.ToolTip = $Line }
    [System.Windows.Controls.Grid]::SetColumn($tb, 1); [System.Windows.Controls.Grid]::SetColumn($msg, 2)
    [void]$grid.Children.Add($icon); [void]$grid.Children.Add($tb); [void]$grid.Children.Add($msg)

    [void]$Ui.PnlLog.Children.Add($grid)
    if ($Ui.PnlLog.Children.Count -gt $script:SmLogMax) { $Ui.PnlLog.Children.RemoveAt(0); $script:SmLogLines.RemoveAt(0) }
    $Ui.TxtLogEmpty.Visibility = 'Collapsed'
    $Ui.TxtLogCount.Text = '{0} Einträge' -f $Ui.PnlLog.Children.Count
    $Ui.ScrLog.ScrollToEnd()
}

function Set-SmHashChip {
    <# Zeigt eine Pruefsumme als Chip: gekuerzt, voller Wert im Tooltip und im Tag des Textfelds. Leerer Wert blendet den Chip aus. #>
    param([Parameter(Mandatory)]$Text, [string]$Sha)
    $p = $Text.Parent
    while ($p -and -not ($p -is [System.Windows.Controls.Border])) { $p = $p.Parent }
    if (-not $Sha) {
        $Text.Text = ''; $Text.Tag = $null; $Text.ToolTip = $null
        if ($p) { $p.Visibility = 'Collapsed'; $p.ToolTip = $null }
        return
    }
    $Text.Text = Format-SmShortHash $Sha
    $Text.Tag = $Sha
    $tip = 'SHA256 (vollständig): ' + $Sha
    $Text.ToolTip = $tip
    if ($p) { $p.ToolTip = $tip; $p.Visibility = 'Visible' }
}

function Set-SmStepState {
    <# Schrittanzeige 1 bis 3: erledigt (Haken auf gruenem Grund) oder offen (Zahl). Namen BdgStepN und TxtStepN. #>
    param([Parameter(Mandatory)]$Ui, [int[]]$Done = @())
    foreach ($i in 1..3) {
        $b = $Ui["BdgStep$i"]; $t = $Ui["TxtStep$i"]
        if (-not $b -or -not $t) { continue }
        if ($Done -contains $i) {
            $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SuccessBg')
            $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Success')
            $t.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'IconFont')
            $t.Text = [string][char]0xE73E
        }
        else {
            $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Divider')
            $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'MutedText')
            $t.ClearValue([System.Windows.Controls.TextBlock]::FontFamilyProperty)
            $t.Text = [string]$i
        }
    }
}

function Show-SmCopied {
    <# Bestaetigung am Knopf: Beschriftung wechselt fuer ein paar Sekunden auf "Kopiert" mit Haken, dann zurueck. #>
    param([Parameter(Mandatory)]$Button, [string]$Text = 'Kopiert', [int]$Seconds = 2)
    $key = [string]$Button.Name
    if (-not $script:SmCopyOrig.ContainsKey($key)) { $script:SmCopyOrig[$key] = @{ Content = $Button.Content; Tag = $Button.Tag; Timer = $null } }
    $store = $script:SmCopyOrig
    $orig = $store[$key]
    $Button.Content = if ($Button.Content -is [string] -and $Button.Content.Length -eq 1 -and [int][char]$Button.Content -ge 57344 -and [int][char]$Button.Content -le 63743) { [string][char]0xE73E } else { $Text }
    if ($Button.Tag) { $Button.Tag = [string][char]0xE73E }
    if ($orig.Timer) { $orig.Timer.Stop() }
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromSeconds($Seconds)
    $t.Add_Tick({
            $t.Stop(); $Button.Content = $orig.Content; $Button.Tag = $orig.Tag
            $store.Remove($key)
        }.GetNewClosure())
    $orig.Timer = $t
    $t.Start()
}

function Set-SmOneLiner {
    <# Einzeiler setzen: voller Text im Codefeld (eingeklappt), einzeilige Vorschau gekuerzt. #>
    param([Parameter(Mandatory)]$Ui, [string]$Text)
    $Ui.TxtOneLiner.Text = $Text
    $flat = [regex]::Replace([string]$Text, '\s+', ' ').Trim()
    $Ui.TxtOneLinerPreview.Text = $flat
    $Ui.TxtOneLiner.Visibility = 'Collapsed'
    $Ui.BoxCmdPreview.Visibility = 'Visible'
    $Ui.BtnCmdToggle.Content = 'Befehl anzeigen'
}

function Initialize-SmCommandBox {
    <# Verdrahtet "Befehl anzeigen/ausblenden" (Vorschau gegen vollen Text). #>
    param([Parameter(Mandatory)]$Ui)
    $Ui.BtnCmdToggle.Add_Click({
            $u = $script:SmWin.Ui
            $open = $u.TxtOneLiner.Visibility -ne 'Visible'
            $u.TxtOneLiner.Visibility = if ($open) { 'Visible' } else { 'Collapsed' }
            $u.BoxCmdPreview.Visibility = if ($open) { 'Collapsed' } else { 'Visible' }
            $u.BtnCmdToggle.Content = if ($open) { 'Befehl ausblenden' } else { 'Befehl anzeigen' }
        })
}

function Initialize-SmCodeBoxes {
    <# Codefelder (Style CodeBox) schreibgeschuetzt machen und mit senkrechtem Scrollbalken versehen. Das geschieht im Code, nicht im XAML:
       aeltere .NET-Versionen kennen TextBoxBase-Eigenschaften in Styles der TextBox nicht. #>
    param([Parameter(Mandatory)]$Ui)
    $style = [System.Windows.Application]::Current.TryFindResource('CodeBox')
    foreach ($el in @($Ui.Values)) {
        if ($el -is [System.Windows.Controls.TextBox] -and $style -and $el.Style -eq $style) {
            $el.IsReadOnly = $true; $el.AcceptsReturn = $true; $el.VerticalScrollBarVisibility = 'Auto'
        }
    }
}
