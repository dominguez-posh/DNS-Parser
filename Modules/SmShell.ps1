# Gemeinsame Huelle beider Fenster (Berater-Tool und Server-Fenster): eigene Titelleiste, Navigation links, hell/dunkel,
# Seiten aus dem Code, Hintergrundauftraege ohne eingefrorene Oberflaeche. Braucht Modules\SmTheme.ps1 (vorher laden).

$script:SmPageNs = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'

function Get-SmXamlNames {
    <# Namen (x:Name / Name) aller Elemente eines XAML-Textes. #>
    param([Parameter(Mandatory)][string]$Xaml)
    [xml]$x = $Xaml
    foreach ($node in $x.SelectNodes("//*[@*[local-name()='Name']]")) {
        ($node.Attributes | Where-Object LocalName -eq 'Name' | Select-Object -First 1).Value
    }
}

function New-SmPlaceholderXaml {
    param([string]$Title, [string]$Text, [int]$Phase)
    $t = [Security.SecurityElement]::Escape($Title); $d = [Security.SecurityElement]::Escape($Text)
    @"
<ScrollViewer $script:SmPageNs Style="{DynamicResource PageScroll}">
    <StackPanel Margin="40,32,40,28" MaxWidth="900" HorizontalAlignment="Left">
        <TextBlock Text="$t" Style="{DynamicResource PageTitle}"/>
        <TextBlock Text="$d" Style="{DynamicResource Subtitle}"/>
        <Border Style="{DynamicResource CardBox}" Margin="0,20,0,0" Background="{DynamicResource Card}" Padding="20,16">
            <StackPanel>
                <Border Style="{DynamicResource Pill}" Background="{DynamicResource AccentSubtle}" Padding="10,2"><TextBlock Text="Platzhalter, kommt in Phase $Phase" FontSize="12" FontWeight="SemiBold" Foreground="{DynamicResource Primary}"/></Border>
                <TextBlock Style="{DynamicResource Hint}" Margin="0,10,0,0" Text="Dieser Bereich ist noch nicht gebaut. Das Geruest (Titelleiste, Navigation, Theme, Tauschordner) steht."/>
            </StackPanel>
        </Border>
    </StackPanel>
</ScrollViewer>
"@
}

function New-SmWindow {
    <#
    .SYNOPSIS
        Baut das Fenster aus UI\Shell.xaml. Pages: Hashtables mit Key, Title, Glyph (Zeichencode), Xaml (Seite) oder Text und Phase (Platzhalter).
        Liefert ein Objekt mit Window, Ui (Name -> Element, auch die der Seiten) und Navigate.
        Zeigt nichts an; das macht der Aufrufer (ShowDialog) oder auch nicht (-ParseOnly).
    #>
    param(
        [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Title, [string]$Subtitle = '', [string]$Version = '',
        [Parameter(Mandatory)][hashtable[]]$Pages, [ValidateSet('Light', 'Dark', 'System')][string]$Theme = 'System'
    )
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    if (-not [System.Windows.Application]::Current) { [void](New-Object System.Windows.Application) }
    [System.Windows.Application]::Current.ShutdownMode = 'OnExplicitShutdown'
    $mode = if ($Theme -eq 'System') { Get-SmSystemTheme } else { $Theme }
    Set-SmTheme -Mode $mode -Path (Join-Path $Root 'UI\Theme.xaml')

    $xamlText = [IO.File]::ReadAllText((Join-Path $Root 'UI\Shell.xaml'))
    [xml]$xaml = $xamlText
    $window = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($xaml))
    $ui = @{}
    foreach ($n in (Get-SmXamlNames $xamlText)) { $ui[$n] = $window.FindName($n) }
    $window.Title = $Title
    $ui.TxtTitle.Text = $Title
    $ui.TxtSubtitle.Text = $Subtitle
    $ui.TxtVersion.Text = $Version

    $script:SmWin = [pscustomobject]@{ Window = $window; Ui = $ui; Root = $Root; Pages = @{}; Current = $null; ToastTimer = $null }
    $win = $script:SmWin

    # Seiten und Navigation
    foreach ($p in $Pages) {
        $xamlPage = if ($p.Xaml) { $p.Xaml } else { New-SmPlaceholderXaml -Title $p.Title -Text $p.Text -Phase $p.Phase }
        [xml]$px = $xamlPage
        $pageRoot = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($px))
        $pageRoot.Visibility = 'Collapsed'
        [void]$ui.PageHost.Children.Add($pageRoot)
        foreach ($n in (Get-SmXamlNames $xamlPage)) { $ui[$n] = $pageRoot.FindName($n) }
        $win.Pages[$p.Key] = $pageRoot

        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.SetResourceReference([System.Windows.Controls.Control]::StyleProperty, 'NavItem')
        $rb.GroupName = 'Nav'
        $rb.Tag = $p.Key
        [System.Windows.Automation.AutomationProperties]::SetName($rb, [string]$p.Title)
        $row = New-Object System.Windows.Controls.StackPanel
        $row.Orientation = 'Horizontal'
        $glyph = New-Object System.Windows.Controls.TextBlock
        $glyph.Style = $window.Resources['NavGlyph']
        $glyph.Text = [string][char]$p.Glyph
        $label = New-Object System.Windows.Controls.TextBlock
        $label.Text = [string]$p.Title
        [void]$row.Children.Add($glyph); [void]$row.Children.Add($label)
        $rb.Content = $row
        [void]$ui.NavList.Children.Add($rb)
        $ui["Nav$($p.Key)"] = $rb
        $rb.Add_Checked({ param($src) Show-SmPage ([string]$src.Tag) })
    }

    # Titelleiste
    $ui.BtnTheme.Content = [string][char]$(if ($mode -eq 'Dark') { 0xE706 } else { 0xE708 })
    $ui.BtnTheme.Add_Click({
            $next = if ($script:SmCurrentTheme -eq 'Dark') { 'Light' } else { 'Dark' }
            Set-SmTheme -Mode $next -Path (Join-Path $script:SmWin.Root 'UI\Theme.xaml')
            $script:SmWin.Ui.BtnTheme.Content = [string][char]$(if ($next -eq 'Dark') { 0xE706 } else { 0xE708 })
        })
    $ui.BtnMinimize.Add_Click({ $script:SmWin.Window.WindowState = 'Minimized' })
    $ui.BtnMaximize.Add_Click({ $w = $script:SmWin.Window; $w.WindowState = if ($w.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' } })
    $ui.BtnClose.Add_Click({ $script:SmWin.Window.Close() })
    $window.Add_StateChanged({
            $w = $script:SmWin.Window; $u = $script:SmWin.Ui
            $max = $w.WindowState -eq 'Maximized'
            $u.BtnMaximize.Content = [string]$(if ($max) { [char]0xE923 } else { [char]0xE922 })
            # ein maximiertes Chrome-Fenster ragt um den Rahmen ueber den Bildschirm: Inhalt nach innen holen
            $u.RootGrid.Margin = if ($max) { [System.Windows.SystemParameters]::WindowResizeBorderThickness } else { New-Object System.Windows.Thickness 0 }
        })

    [pscustomobject]@{ Window = $window; Ui = $ui }
}

function Show-SmPage {
    param([Parameter(Mandatory)][string]$Key)
    $win = $script:SmWin
    foreach ($k in $win.Pages.Keys) { $win.Pages[$k].Visibility = if ($k -eq $Key) { 'Visible' } else { 'Collapsed' } }
    $win.Current = $Key
}

function Select-SmPage {
    <# Waehlt einen Navigationspunkt (zeigt die Seite). #>
    param([Parameter(Mandatory)][string]$Key)
    $script:SmWin.Ui["Nav$Key"].IsChecked = $true
}

function Test-SmWindowNames {
    <# Prueft, dass alle Namen vorhanden sind; wirft sonst. Fuer -ParseOnly. #>
    param([Parameter(Mandatory)][string[]]$Names)
    foreach ($n in $Names) { if (-not $script:SmWin.Ui[$n]) { throw "Steuerelement fehlt: $n" } }
}

function Show-SmToast {
    param([Parameter(Mandatory)][string]$Text, [int]$Seconds = 4)
    $u = $script:SmWin.Ui
    $u.TxtToast.Text = $Text
    $u.BoxToast.Visibility = 'Visible'
    if ($script:SmWin.ToastTimer) { $script:SmWin.ToastTimer.Stop() }
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromSeconds($Seconds)
    $t.Add_Tick({ $script:SmWin.Ui.BoxToast.Visibility = 'Collapsed'; $this.Stop() })
    $script:SmWin.ToastTimer = $t
    $t.Start()
}

function Start-SmJob {
    <#
    .SYNOPSIS
        Fuehrt einen Auftrag in einem eigenen Runspace aus, damit die Oberflaeche bedienbar bleibt.
    .DESCRIPTION
        Script bekommt ($State, $Params). $State ist eine synchronisierte Hashtable mit Sent, Total und Log (ConcurrentQueue).
        OnTick($State) laeuft alle 250 ms im Oberflaechenthread, OnDone($Result, $ErrorText) einmal am Ende.
        Die Module werden im Runspace per Dot-Source geladen.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Params = @{}, [string[]]$Modules = @(),
        [scriptblock]$OnTick, [Parameter(Mandatory)][scriptblock]$OnDone
    )
    $state = [hashtable]::Synchronized(@{ Sent = 0L; Total = 0L; Log = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]') })
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'MTA'; $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $load = ($Modules | ForEach-Object { ". '" + $_.Replace("'", "''") + "'" }) -join "`n"
    if ($load) { [void]$ps.AddScript($load).AddStatement() }
    [void]$ps.AddScript($Script.ToString()).AddArgument($state).AddArgument($Params)
    $handle = $ps.BeginInvoke()
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $job = @{ Ps = $ps; Rs = $rs; Handle = $handle; Timer = $timer; State = $state; OnTick = $OnTick; OnDone = $OnDone }
    $timer.Add_Tick({
            if ($job.OnTick) { try { & $job.OnTick $job.State } catch { } }
            if (-not $job.Handle.IsCompleted) { return }
            $job.Timer.Stop()
            $result = $null; $err = $null
            try { $result = @($job.Ps.EndInvoke($job.Handle)) } catch { $err = $_.Exception.InnerException.Message; if (-not $err) { $err = $_.Exception.Message } }
            if (-not $err -and $job.Ps.Streams.Error.Count) { $err = [string]$job.Ps.Streams.Error[0] }
            $job.Ps.Dispose(); $job.Rs.Dispose()
            & $job.OnDone $result $err
        }.GetNewClosure())
    $timer.Start()
    $job
}

function Format-SmSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    ('{0:N0} KB' -f [math]::Ceiling($Bytes / 1KB))
}
