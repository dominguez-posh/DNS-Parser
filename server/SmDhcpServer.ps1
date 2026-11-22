<#
.SYNOPSIS
    Server-Fenster, Bereich DHCP: Export am alten Server, Import und Autorisierung am neuen Server, Bereiche am alten Server deaktivieren.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht Modules\SmTausch.ps1 und Modules\SmDhcp.ps1, fuer die Oberflaeche Modules\SmShell.ps1).
    Die Cmdlets stammen aus dem Modul DhcpServer (Windows Server, Rolle DHCP). Parameter laut Microsoft Learn:
      Export-DhcpServer -File [-ScopeId] [-Prefix] [-Leases] [-Force] ...
      Import-DhcpServer -File -BackupPath [-ScopeId] [-Prefix] [-ScopeOverwrite] [-Leases] [-ServerConfigOnly] [-Force] ...
      Add-DhcpServerInDC [[-DnsName]] [[-IPAddress]]; Get-DhcpServerInDC; Set-DhcpServerv4Scope -ScopeId -State (Active|InActive).
    Failover: Die Doku von Export-/Import-DhcpServer nennt Failover-Beziehungen nicht (Serverkonfiguration: Klassen, Optionen, Richtlinien, Filter,
    Servereigenschaften). Das Tool nimmt sie deshalb nicht als uebertragen an: Es haelt sie in der Zusammenfassung fest, weist vor dem Import darauf hin
    und nennt das Neuanlegen (Add-DhcpServerv4Failover) als manuellen Schritt.
    Jede aendernde Aktion (Import, Autorisierung, Deaktivieren) hat Vorpruefung, Bestaetigung im Fenster und eine Protokollzeile ohne Geheimnisse.
    Alles aus dem Tauschordner gilt als feindlich (siehe Modules\SmDhcp.ps1). Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmDhcpAuditPath = $null   # Standard: %ProgramData%\ServerMigration\dhcp-protokoll.log (Tests setzen einen eigenen Pfad)
# Protokoll- und Sicherungsordner werden mit Protect-SmDnsStateDir (server\SmDnsServer.ps1) gehaertet, keine eigene Kopie. Die Datei muss vor dieser geladen sein.

function Test-SmDhcpAdmin {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false }
}

function Get-SmDhcpHostName {
    $h = ([string]$env:COMPUTERNAME) -replace '[^A-Za-z0-9\-]', ''
    if ($h.Length -gt 30) { $h = $h.Substring(0, 30) }
    if (-not $h) { $h = 'server' }
    $h
}

function Write-SmDhcpAudit {
    <# Protokollzeile fuer eine Aktion (ohne Geheimnisse: keine Links, keine Kennwoerter): ins Fenster und in %ProgramData%\ServerMigration\dhcp-protokoll.log. #>
    param([Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)][string]$Text, [scriptblock]$Log)
    $clean = [regex]::Replace($Text, '(?i)\b(?:https?|ftp)://\S+', '<Adresse>')
    $line = 'DHCP {0}: {1}' -f $Action, $clean
    try {
        $path = if ($script:SmDhcpAuditPath) { $script:SmDhcpAuditPath } else { Join-Path (Get-SmDnsStateDir) 'dhcp-protokoll.log' }
        $dir = Split-Path -Parent $path
        Protect-SmDnsStateDir -Path $dir   # Ordner immer haerten und pruefen (Administratoren und SYSTEM), sonst wird nicht geschrieben
        Add-Content -LiteralPath $path -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}\{2}  {3}' -f (Get-Date), $env:USERDOMAIN, $env:USERNAME, $line) -Encoding UTF8
    }
    catch {
        # Ein Schreibfehler im Protokoll wird angezeigt, nicht still geschluckt
        $warn = 'DHCP Protokoll: Die Protokollzeile konnte nicht geschrieben werden: ' + [regex]::Replace($_.Exception.Message, '(?i)\b(?:https?|ftp)://\S+', '<Adresse>')
        if ($Log) { & $Log $warn }
        Write-Warning $warn
    }
    if ($Log) { & $Log $line }
    $line
}

function Remove-SmDhcpTemp {
    <# Loescht nur Ordner, die dieses Tool selbst unter %TEMP% angelegt hat (Pfad per GetFullPath geprueft). #>
    param([string]$Dir, [string]$TempRoot = $env:TEMP)
    if (-not $Dir) { return }
    $full = [IO.Path]::GetFullPath($Dir)
    $prefix = [IO.Path]::GetFullPath($TempRoot).TrimEnd('\') + '\ServerMigration-dhcp-'
    if ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
}

function New-SmDhcpTemp {
    param([string]$TempRoot = $env:TEMP)
    $d = Join-Path ([IO.Path]::GetFullPath($TempRoot)) ('ServerMigration-dhcp-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $d)
    $d
}

# ---------------------------------------------------------------- Vorpruefung

function Get-SmDhcpAuthState {
    <# $true: dieser Server steht in der AD-Liste der autorisierten DHCP-Server, $false: nicht, $null: nicht lesbar (kein AD, keine Rechte). #>
    try { $list = @(Get-DhcpServerInDC -ErrorAction Stop) } catch { return $null }
    $name = [string]$env:COMPUTERNAME
    $ips = @()
    try { $ips = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object { $_.GetIPProperties().UnicastAddresses } | ForEach-Object { $_.Address.ToString() }) } catch { }
    foreach ($e in $list) {
        $dn = [string]$e.DnsName
        if ($dn -ieq $name -or $dn -like ($name + '.*')) { return $true }
        if ($e.IPAddress -and ($ips -contains ([string]$e.IPAddress))) { return $true }
    }
    $false
}

function Test-SmDhcpPrecheck {
    <#
    .SYNOPSIS
        Vorpruefung je Aktion (Export, Import, Deactivate, Authorize): Cmdlets des Moduls DhcpServer, DHCP-Dienst, Administrator, Autorisierung in AD.
        Liefert Ok (kein blockierender Punkt), Items (Name, Ok, Blocking, Text) und Lines (Text fuer die Anzeige).
    #>
    param([Parameter(Mandatory)][ValidateSet('Export', 'Import', 'Deactivate', 'Authorize')][string]$Mode)
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($n, $ok, $block, $t) $items.Add([pscustomobject]@{ Name = $n; Ok = [bool]$ok; Blocking = [bool]$block; Text = $t }) }
    $need = switch ($Mode) {
        'Export' { @('Export-DhcpServer', 'Get-DhcpServerv4Scope') }
        'Import' { @('Import-DhcpServer', 'Get-DhcpServerv4Scope') }
        'Deactivate' { @('Get-DhcpServerv4Scope', 'Set-DhcpServerv4Scope') }
        'Authorize' { @('Add-DhcpServerInDC', 'Get-DhcpServerInDC') }
    }
    $missing = @($need | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if ($missing) { & $add 'Modul DhcpServer' $false $true ('Fehlt: ' + ($missing -join ', ') + '. Ist die DHCP-Rolle samt Verwaltungswerkzeugen installiert?') }
    else { & $add 'Modul DhcpServer' $true $false 'Cmdlets vorhanden' }
    $svc = $null
    try { $svc = Get-Service -Name 'DHCPServer' -ErrorAction Stop } catch { }
    if (-not $svc) { & $add 'DHCP-Dienst' $false $true 'Der Dienst DHCPServer ist auf diesem Server nicht vorhanden (Rolle DHCP nicht installiert).' }
    elseif ([string]$svc.Status -ne 'Running') { & $add 'DHCP-Dienst' $false $true ('Der Dienst DHCPServer laeuft nicht (Status ' + $svc.Status + ').') }
    else { & $add 'DHCP-Dienst' $true $false 'Dienst laeuft' }
    if (Test-SmDhcpAdmin) { & $add 'Administrator' $true $false 'Das Fenster laeuft als Administrator' }
    else { & $add 'Administrator' $false $true 'Das Fenster laeuft nicht als Administrator.' }
    $auth = if (Get-Command Get-DhcpServerInDC -ErrorAction SilentlyContinue) { Get-SmDhcpAuthState } else { $null }
    switch ($Mode) {
        'Authorize' {
            if ($auth -eq $true) { & $add 'Autorisierung in AD' $false $true 'Dieser Server ist bereits in AD autorisiert. Nichts zu tun.' }
            elseif ($null -eq $auth) { & $add 'Autorisierung in AD' $false $true 'Die Autorisierungsliste in AD ist nicht lesbar (Domaene erreichbar? Rechte als Enterprise Admin oder delegiert?).' }
            else { & $add 'Autorisierung in AD' $true $false 'Noch nicht autorisiert' }
        }
        default {
            if ($auth -eq $true) { & $add 'Autorisierung in AD' $true $false 'In AD autorisiert' }
            elseif ($auth -eq $false) { & $add 'Autorisierung in AD' $true $false 'Noch nicht in AD autorisiert (Hinweis: folgt nach dem Import als eigener Schritt)' }
            else { & $add 'Autorisierung in AD' $true $false 'Autorisierung in AD nicht lesbar (Hinweis, kein Hindernis)' }
        }
    }
    $arr = $items.ToArray()
    [pscustomobject]@{ Mode = $Mode; Ok = (-not (@($arr | Where-Object { -not $_.Ok -and $_.Blocking }).Count)); Items = $arr; Lines = @($arr | ForEach-Object { '{0} {1}: {2}' -f $(if ($_.Ok) { '[ok]' } else { '[!!]' }), $_.Name, $_.Text }) }
}

# ---------------------------------------------------------------- Zusammenfassung

function Invoke-SmDhcpSafe {
    <# Fuehrt einen Abschnitt aus; ein Fehler (z. B. kein IPv6 eingerichtet) wird in der Fehlerliste vermerkt und bricht nichts ab. #>
    param([Parameter(Mandatory)]$Errors, [Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][scriptblock]$Script)
    try { @(& $Script) } catch { $Errors.Add(('{0}: {1}' -f $What, $_.Exception.Message)); @() }
}

function ConvertTo-SmDhcpOptionRows {
    param($Values)
    @($Values | Where-Object { $_ } | ForEach-Object { [ordered]@{ Id = [int]$_.OptionId; Name = [string]$_.Name; Value = (@($_.Value) | ForEach-Object { [string]$_ }) -join ',' } })
}

function Get-SmDhcpSummary {
    <#
    .SYNOPSIS
        Liest den Stand des lokalen DHCP-Servers: Bereiche (v4 und v6) mit Optionen, Reservierungen, Ausschluessen und Anzahl der Leases,
        Optionen auf Serverebene, Failover-Beziehungen, Richtlinien, Filter, DNS-Update-Einstellungen und Bindungen (Format SmDhcpSummary 1).
    #>
    param([scriptblock]$Log, [switch]$NoLeases)
    $err = New-Object System.Collections.Generic.List[string]
    $leaseTotal = 0
    $s4 = New-Object System.Collections.Generic.List[object]
    foreach ($s in (Invoke-SmDhcpSafe $err 'Bereiche v4' { Get-DhcpServerv4Scope -ErrorAction Stop })) {
        $id = $s.ScopeId.ToString()
        if ($Log) { & $Log ('Lese Bereich ' + $id) }
        $opt = @(ConvertTo-SmDhcpOptionRows (Invoke-SmDhcpSafe $err "Optionen $id" { Get-DhcpServerv4OptionValue -ScopeId $id -ErrorAction Stop }))
        $res = @(Invoke-SmDhcpSafe $err "Reservierungen $id" { Get-DhcpServerv4Reservation -ScopeId $id -ErrorAction Stop } | ForEach-Object { [ordered]@{ Ip = $_.IPAddress.ToString(); ClientId = [string]$_.ClientId; Name = [string]$_.Name } })
        $exc = @(Invoke-SmDhcpSafe $err "Ausschluesse $id" { Get-DhcpServerv4ExclusionRange -ScopeId $id -ErrorAction Stop } | ForEach-Object { [ordered]@{ Start = $_.StartRange.ToString(); End = $_.EndRange.ToString() } })
        $ll = @(Invoke-SmDhcpSafe $err "Leases $id" { Get-DhcpServerv4Lease -ScopeId $id -AllLeases -ErrorAction Stop })
        $leases = $ll.Count
        $leaseList = New-Object System.Collections.Generic.List[object]
        if (-not $NoLeases) {
            # je Adresse: nur IP und Client-Kennung (MAC), keine Hostnamen; begrenzt, damit die Datei lesbar bleibt
            foreach ($l in $ll) {
                if ($leaseList.Count -ge $script:SmDhcpMaxLeasesPerScope -or $leaseTotal -ge 300000) { $err.Add("Leases ${id}: Liste gekuerzt (Grenze erreicht)"); break }
                $leaseList.Add([ordered]@{ Ip = $l.IPAddress.ToString(); ClientId = [string]$l.ClientId }); $leaseTotal++
            }
        }
        $pol = @(Invoke-SmDhcpSafe $err "Richtlinien $id" { Get-DhcpServerv4Policy -ScopeId $id -ErrorAction Stop } | ForEach-Object { [string]$_.Name })
        $s4.Add([ordered]@{
                ScopeId = $id; Name = [string]$s.Name; Mask = $(if ($s.SubnetMask) { $s.SubnetMask.ToString() } else { '' })
                Start = $(if ($s.StartRange) { $s.StartRange.ToString() } else { '' }); End = $(if ($s.EndRange) { $s.EndRange.ToString() } else { '' })
                State = [string]$s.State; LeaseDuration = [string]$s.LeaseDuration; Leases = $leases; LeaseList = $leaseList.ToArray()
                Options = $opt; Reservations = $res; Exclusions = $exc; Policies = $pol
            })
    }
    $s6 = New-Object System.Collections.Generic.List[object]
    foreach ($s in (Invoke-SmDhcpSafe $err 'Bereiche v6' { Get-DhcpServerv6Scope -ErrorAction Stop })) {
        $px = $s.Prefix.ToString()
        $opt = @(ConvertTo-SmDhcpOptionRows (Invoke-SmDhcpSafe $err "Optionen $px" { Get-DhcpServerv6OptionValue -Prefix $px -ErrorAction Stop }))
        $res = @(Invoke-SmDhcpSafe $err "Reservierungen $px" { Get-DhcpServerv6Reservation -Prefix $px -ErrorAction Stop } | ForEach-Object { [ordered]@{ Ip = $_.IPAddress.ToString(); ClientId = [string]$_.ClientDuid; Name = [string]$_.Name } })
        $exc = @(Invoke-SmDhcpSafe $err "Ausschluesse $px" { Get-DhcpServerv6ExclusionRange -Prefix $px -ErrorAction Stop } | ForEach-Object { [ordered]@{ Start = $_.StartRange.ToString(); End = $_.EndRange.ToString() } })
        $leases = @(Invoke-SmDhcpSafe $err "Leases $px" { Get-DhcpServerv6Lease -Prefix $px -ErrorAction Stop }).Count
        $s6.Add([ordered]@{ Prefix = $px; Name = [string]$s.Name; State = [string]$s.State; Leases = $leases; Options = $opt; Reservations = $res; Exclusions = $exc })
    }
    $fo = @(Invoke-SmDhcpSafe $err 'Failover' { Get-DhcpServerv4Failover -ErrorAction Stop } | ForEach-Object {
            [ordered]@{ Name = [string]$_.Name; Partner = [string]$_.PartnerServer; Mode = [string]$_.Mode; State = [string]$_.State; Scopes = @($_.ScopeId | Where-Object { $_ } | ForEach-Object { $_.ToString() }) }
        })
    $pol = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Invoke-SmDhcpSafe $err 'Richtlinien Server' { Get-DhcpServerv4Policy -ErrorAction Stop })) { $pol.Add([ordered]@{ Name = [string]$p.Name; Scope = ''; Enabled = [bool]$p.Enabled }) }
    foreach ($s in $s4) {
        foreach ($p in (Invoke-SmDhcpSafe $err ('Richtlinien ' + $s.ScopeId) { Get-DhcpServerv4Policy -ScopeId $s.ScopeId -ErrorAction Stop })) { $pol.Add([ordered]@{ Name = [string]$p.Name; Scope = $s.ScopeId; Enabled = [bool]$p.Enabled }) }
    }
    $fl = @(Invoke-SmDhcpSafe $err 'Filterliste' { Get-DhcpServerv4FilterList -ErrorAction Stop }) | Select-Object -First 1
    $fe = @(Invoke-SmDhcpSafe $err 'Filter' { Get-DhcpServerv4Filter -ErrorAction Stop } | ForEach-Object { [ordered]@{ List = [string]$_.List; Mac = [string]$_.MacAddress; Description = [string]$_.Description } })
    $dns = New-Object System.Collections.Generic.List[object]
    $dnsProps = 'DynamicUpdates', 'DeleteDnsRROnLeaseExpiry', 'UpdateDnsRRForOlderClients', 'DisableDnsPtrRRUpdate', 'NameProtection', 'DnsSuffix'
    foreach ($d in (Invoke-SmDhcpSafe $err 'DNS-Update Server' { Get-DhcpServerv4DnsSetting -ErrorAction Stop })) {
        foreach ($n in $dnsProps) { if ($d.PSObject.Properties[$n]) { $dns.Add([ordered]@{ Scope = ''; Name = $n; Value = [string]$d.$n }) } }
    }
    foreach ($s in $s4) {
        foreach ($d in (Invoke-SmDhcpSafe $err ('DNS-Update ' + $s.ScopeId) { Get-DhcpServerv4DnsSetting -ScopeId $s.ScopeId -ErrorAction Stop })) {
            foreach ($n in $dnsProps) { if ($d.PSObject.Properties[$n]) { $dns.Add([ordered]@{ Scope = $s.ScopeId; Name = $n; Value = [string]$d.$n }) } }
        }
    }
    $bind = @(Invoke-SmDhcpSafe $err 'Bindungen' { Get-DhcpServerv4Binding -ErrorAction Stop } | ForEach-Object { [ordered]@{ Interface = [string]$_.InterfaceAlias; Ip = [string]$_.IPAddress; State = [string]$_.BindingState } })
    [ordered]@{
        Format = 'SmDhcpSummary'; Version = 1; Server = [string]$env:COMPUTERNAME; Created = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Authorized = ((Get-SmDhcpAuthState) -eq $true); LeasesIncluded = (-not $NoLeases)
        Scopes4 = $s4.ToArray(); Scopes6 = $s6.ToArray()
        ServerOptions4 = @(ConvertTo-SmDhcpOptionRows (Invoke-SmDhcpSafe $err 'Serveroptionen v4' { Get-DhcpServerv4OptionValue -ErrorAction Stop }))
        ServerOptions6 = @(ConvertTo-SmDhcpOptionRows (Invoke-SmDhcpSafe $err 'Serveroptionen v6' { Get-DhcpServerv6OptionValue -ErrorAction Stop }))
        Failover = $fo; Policies = $pol.ToArray()
        Filters = [ordered]@{ AllowEnabled = [bool]($fl -and $fl.Allow); DenyEnabled = [bool]($fl -and $fl.Deny); Entries = $fe }
        DnsUpdate = $dns.ToArray(); Bindings = $bind; Errors = $err.ToArray()
    }
}

function Write-SmDhcpSummaryFile {
    <# Schreibt die Zusammenfassung als JSON (UTF-8 ohne BOM) und prueft sie sofort mit derselben Pruefung wie das Berater-Tool. Liefert die geprueften Daten. #>
    param([Parameter(Mandatory)]$Summary, [Parameter(Mandatory)][string]$Path)
    $json = ConvertTo-Json -InputObject $Summary -Depth 8
    [IO.File]::WriteAllBytes($Path, (New-Object Text.UTF8Encoding($false)).GetBytes($json))
    Read-SmDhcpSummaryFile -Path $Path
}

# ---------------------------------------------------------------- Export (alter Server) und Zusammenfassung (neuer Server)

function New-SmDhcpExport {
    <# Export-DhcpServer -File -Leases plus Zusammenfassung, beides in ein ZIP (dhcp-export.xml, dhcp-summary.json). Liefert Pfad, Name, SHA256, Laenge und die Zusammenfassung. #>
    param([Parameter(Mandatory)][string]$WorkDir, [scriptblock]$Log, [switch]$NoLeases)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $xml = Join-Path $WorkDir $script:SmDhcpXmlEntry
    $json = Join-Path $WorkDir $script:SmDhcpSummaryEntry
    if ($Log) { & $Log $(if ($NoLeases) { 'Export-DhcpServer ohne Leases ...' } else { 'Export-DhcpServer mit Leases ...' }) }
    if ($NoLeases) { Export-DhcpServer -File $xml -ErrorAction Stop } else { Export-DhcpServer -File $xml -Leases -ErrorAction Stop }
    if (-not (Test-Path -LiteralPath $xml) -or (Get-Item -LiteralPath $xml).Length -eq 0) { throw 'Export-DhcpServer hat keine Datei geschrieben.' }
    [void](Test-SmDhcpXmlSafe -Path $xml)
    if ($Log) { & $Log 'Lese die Zusammenfassung (Bereiche, Optionen, Reservierungen, Failover ...)' }
    $summary = Write-SmDhcpSummaryFile -Summary (Get-SmDhcpSummary -Log $Log -NoLeases:$NoLeases) -Path $json
    $name = 'DHCP-Export-{0}-{1}.zip' -f (Get-SmDhcpHostName), (Get-Date -Format 'yyyyMMdd-HHmmss')
    $zipPath = Join-Path $WorkDir $name
    $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
    try {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $xml, $script:SmDhcpXmlEntry, 'Optimal')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $json, $script:SmDhcpSummaryEntry, 'Optimal')
    }
    finally { $zip.Dispose() }
    [pscustomobject]@{ Path = $zipPath; Name = $name; Sha256 = (Get-SmSha256Local $zipPath); Length = (Get-Item -LiteralPath $zipPath).Length; Summary = $summary }
}

function Get-SmSha256Local {
    <# SHA256 einer Datei (eigene Kopie, damit das Modul auch ohne Modules\SmPaket.ps1 im Server-Paket laeuft). #>
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = [IO.File]::OpenRead($Path)
    try { $h = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
    -join ($h | ForEach-Object { $_.ToString('X2') })
}

function Get-SmSha256Bytes {
    <# SHA256 von Bytes im Speicher (voll, Grossbuchstaben). #>
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    -join ($h | ForEach-Object { $_.ToString('X2') })
}

function Publish-SmDhcpExport {
    <# Alter Server: Vorpruefung, Export, ZIP in den Tauschordner (grosse Dateien in Teilen). Liefert Name, Sha256, Laenge und Zusammenfassung. #>
    param([Parameter(Mandatory)]$Share, [scriptblock]$Progress, [scriptblock]$Log = { param($m) }, [string]$TempRoot = $env:TEMP, [switch]$NoLeases)
    $pre = Test-SmDhcpPrecheck -Mode Export
    if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    $work = New-SmDhcpTemp -TempRoot $TempRoot
    try {
        $exp = New-SmDhcpExport -WorkDir $work -Log $Log -NoLeases:$NoLeases
        & $Log ('ZIP gepackt: {0} ({1:N1} MB), SHA256 {2}' -f $exp.Name, ($exp.Length / 1MB), $exp.Sha256)
        $remote = Send-SmShareFile -Share $Share -Path $exp.Path -Progress $Progress
        [void](Write-SmDhcpAudit -Action 'Export' -Text ('{0}, SHA256 {1}, {2} Bereiche v4, {3} v6, {4}' -f $exp.Name, $exp.Sha256, @($exp.Summary.Scopes4).Count, @($exp.Summary.Scopes6).Count, $(if ($NoLeases) { 'ohne Leases' } else { 'mit Leases' })) -Log $Log)
        [pscustomobject]@{ Name = $remote.Name; Length = $remote.Length; Sha256 = $exp.Sha256; Summary = $exp.Summary }
    }
    finally { Remove-SmDhcpTemp -Dir $work -TempRoot $TempRoot }
}

function Publish-SmDhcpAfter {
    <# Neuer Server (nach dem Import): gleiche Zusammenfassung erzeugen und als DHCP-Nachher-*.json hochladen. #>
    param([Parameter(Mandatory)]$Share, [scriptblock]$Progress, [scriptblock]$Log = { param($m) }, [string]$TempRoot = $env:TEMP, [switch]$NoLeases)
    $pre = Test-SmDhcpPrecheck -Mode Export
    if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    $work = New-SmDhcpTemp -TempRoot $TempRoot
    try {
        $name = 'DHCP-Nachher-{0}-{1}.json' -f (Get-SmDhcpHostName), (Get-Date -Format 'yyyyMMdd-HHmmss')
        $path = Join-Path $work $name
        $summary = Write-SmDhcpSummaryFile -Summary (Get-SmDhcpSummary -Log $Log -NoLeases:$NoLeases) -Path $path
        $sha = Get-SmSha256Local $path
        $remote = Send-SmShareFile -Share $Share -Path $path -Progress $Progress
        [void](Write-SmDhcpAudit -Action 'Zusammenfassung hochgeladen' -Text ('{0}, SHA256 {1}, {2} Bereiche v4, {3} v6, {4}' -f $name, $sha, @($summary.Scopes4).Count, @($summary.Scopes6).Count, $(if ($NoLeases) { 'ohne Leases' } else { 'mit Leases' })) -Log $Log)
        [pscustomobject]@{ Name = $remote.Name; Length = $remote.Length; Sha256 = $sha; Summary = $summary }
    }
    finally { Remove-SmDhcpTemp -Dir $work -TempRoot $TempRoot }
}

# ---------------------------------------------------------------- Import (neuer Server)

function Get-SmDhcpImportRoot {
    <# Arbeitsordner des Imports: unter dem gehaerteten Ordner ProgramData\ServerMigration (nie unter %TEMP%, das auch ein nicht erhoehter Prozess des Benutzers beschreiben kann). #>
    Join-Path (Get-SmDnsStateDir) 'Dhcp'
}

function Assert-SmDhcpNoReparse {
    <# Bricht ab, wenn Ordner oder Datei eine Verknuepfung (ReparsePoint) ist. #>
    param([Parameter(Mandatory)][string[]]$Path)
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) { throw "Fehlt: $p" }
        if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Verknuepfung (ReparsePoint) statt Datei oder Ordner, abgebrochen: $p" }
    }
}

function New-SmDhcpImportDir {
    <# Neuer Ordner Import-<GUID> im gehaerteten Importordner (Protect-SmDnsStateDir auf jeder Ebene, ReparsePoint-Pruefung). #>
    param([string]$ImportRoot)
    if (-not $ImportRoot) { Protect-SmDnsStateDir -Path (Get-SmDnsStateDir); $ImportRoot = Get-SmDhcpImportRoot }
    Protect-SmDnsStateDir -Path $ImportRoot
    $d = Join-Path ([IO.Path]::GetFullPath($ImportRoot)) ('Import-' + [guid]::NewGuid().ToString('N'))
    Protect-SmDnsStateDir -Path $d
    Assert-SmDhcpNoReparse -Path $d
    $d
}

function Close-SmDhcpImport {
    <# Raeumt nach dem Import auf: Handles schliessen, dann den Import-<GUID>-Ordner loeschen (nur dieser Name, Pfad per GetFullPath, keine Verknuepfung). #>
    param($Down, $Opened)
    foreach ($h in @($(if ($Opened) { $Opened.XmlHandle }), $(if ($Down) { $Down.Handle }))) { if ($h) { try { $h.Dispose() } catch { } } }
    $dir = if ($Down) { $Down.Dir } elseif ($Opened) { Split-Path -Parent $Opened.XmlPath }
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { return }
    $full = [IO.Path]::GetFullPath($dir)
    if ((Split-Path -Leaf $full) -notmatch '^Import-[0-9a-f]{32}$') { return }
    if ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
}

function Receive-SmDhcpExport {
    <#
    Laedt ein DHCP-Export-ZIP direkt in einen neuen, gehaerteten Ordner (Import-<GUID> unter ProgramData\ServerMigration\Dhcp) und liefert den SHA256.
    Der SHA256 wird ueber genau die Bytes gebildet, die dort liegen; das Handle (FileShare.Read) bleibt bis Close-SmDhcpImport offen,
    damit niemand die Datei schreiben oder ersetzen kann. Entpackt wird noch nichts.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)]$Remote, [Alias('TempRoot')][string]$ImportRoot)
    if ((Get-SmDhcpFileKind $Remote.Name) -ne 'Export') { throw 'Das ist kein DHCP-Export (DHCP-Export-<Server>-<Datum>.zip).' }
    if ([long]$Remote.Length -gt $script:SmDhcpMaxZipBytes) { throw 'Das ZIP ist groesser als erlaubt.' }
    $dir = New-SmDhcpImportDir -ImportRoot $ImportRoot
    $h = $null
    try {
        $zip = Join-Path $dir 'export.zip'
        Receive-SmShareFile -Share $Share -Name $Remote.Name -OutFile $zip -MaxBytes $script:SmDhcpMaxZipBytes
        Assert-SmDhcpNoReparse -Path $dir, $zip
        $h = New-Object IO.FileStream($zip, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $len = $h.Length
        if ($len -gt $script:SmDhcpMaxZipBytes -or $len -ne [long]$Remote.Length) { throw 'Die heruntergeladene Datei hat nicht die erwartete Groesse.' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = $sha.ComputeHash($h) } finally { $sha.Dispose() }
        $h.Position = 0
        [pscustomobject]@{ Dir = $dir; ZipPath = $zip; Name = $Remote.Name; Sha256 = (-join ($hash | ForEach-Object { $_.ToString('X2') })); Length = $len; Handle = $h }
    }
    catch { if ($h) { $h.Dispose() }; Close-SmDhcpImport -Down ([pscustomobject]@{ Dir = $dir; Handle = $null }); throw }
}

function Open-SmDhcpExport {
    <# Entpackt genau die zwei erwarteten Eintraege (feste Namen, begrenzte Groesse), prueft die XML (keine DTD) und die Zusammenfassung. #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)][string]$ExpectedSha)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    # Ohne vollstaendig passende Pruefsumme (am alten Server angezeigt, hier eingegeben) wird nichts entpackt.
    if (-not (Test-SmDhcpShaMatch -Expected (Get-SmSha256Local $ZipPath) -Entered $ExpectedSha)) { throw 'Die eingegebene Pruefsumme passt nicht zur heruntergeladenen Datei. Nichts geoeffnet.' }
    Assert-SmDhcpNoReparse -Path $Dir, $ZipPath
    $zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    $xmlPath = Join-Path $Dir $script:SmDhcpXmlEntry
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        if ($names.Count -ne 2 -or ($names -cnotcontains $script:SmDhcpXmlEntry) -or ($names -cnotcontains $script:SmDhcpSummaryEntry)) { throw 'Das ZIP enthaelt nicht genau dhcp-export.xml und dhcp-summary.json.' }
        $e = $zip.Entries | Where-Object { $_.FullName -ceq $script:SmDhcpXmlEntry }
        if ($e.Length -gt $script:SmDhcpMaxXmlBytes) { throw 'Die Export-XML im ZIP ist groesser als erlaubt.' }
        $src = $e.Open()
        $dst = [IO.File]::Open($xmlPath, 'CreateNew', 'Write', 'None')
        try {
            $buf = New-Object byte[] (1MB); $total = 0L
            while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
                $total += $n
                if ($total -gt $script:SmDhcpMaxXmlBytes) { throw 'Die Export-XML ist groesser als erlaubt.' }
                $dst.Write($buf, 0, $n)
            }
        }
        finally { $dst.Dispose(); $src.Dispose() }
    }
    finally { $zip.Dispose() }
    # Handle auf die XML (FileShare.Read) bis Close-SmDhcpImport: danach kann niemand sie schreiben oder ersetzen, auch nicht waehrend Import-DhcpServer laeuft.
    Assert-SmDhcpNoReparse -Path $xmlPath
    $xh = New-Object IO.FileStream($xmlPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Test-SmDhcpXmlSafe -Path $xmlPath)
        $summary = Read-SmDhcpSummaryFile -Path $ZipPath
        # Importiert wird die XML, nicht die Zusammenfassung: Bereiche und Optionen 3/6/15/44/252 kommen aus der XML und muessen zur Zusammenfassung passen.
        $facts = Read-SmDhcpXmlFacts -Path $xmlPath
        $mismatch = @(Compare-SmDhcpSummaryXml -Summary $summary -Facts $facts)
    }
    catch { $xh.Dispose(); throw }
    [pscustomobject]@{ XmlPath = $xmlPath; Summary = $summary; Facts = $facts; Mismatch = $mismatch; XmlHandle = $xh }
}

function ConvertTo-SmDhcpUInt {
    param([Parameter(Mandatory)][string]$Ip)
    $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [uint64]($b[0] * 16777216 + $b[1] * 65536 + $b[2] * 256 + $b[3])
}

function Test-SmDhcpSubnetOverlap {
    <# $true, wenn sich die IPv4-Netze (Bereichs-ID mit Maske) ueberschneiden. Ohne Maske zaehlt nur die Bereichs-ID. #>
    param([string]$IdA, [string]$MaskA, [string]$IdB, [string]$MaskB)
    $a1 = ConvertTo-SmDhcpUInt $IdA; $b1 = ConvertTo-SmDhcpUInt $IdB
    $a2 = $a1 + $(if ($MaskA) { 4294967295 - (ConvertTo-SmDhcpUInt $MaskA) } else { 0 })
    $b2 = $b1 + $(if ($MaskB) { 4294967295 - (ConvertTo-SmDhcpUInt $MaskB) } else { 0 })
    ($a1 -le $b2 -and $b1 -le $a2)
}

function Get-SmDhcpFailoverNote {
    param($Summary)
    $f = @($Summary.Failover)
    if (-not $f.Count) { return '' }
    'Am alten Server gibt es {0} Failover-Beziehung(en) ({1}). Export und Import uebertragen sie nicht (die Dokumentation von Import-DhcpServer nennt sie nicht). Nach dem Import am neuen Server von Hand neu anlegen (Add-DhcpServerv4Failover), danach pruefen. Die Bereiche am alten Server nicht loeschen oder deaktivieren, solange sie in einer Beziehung stehen: das wuerde zum Partner repliziert.' -f $f.Count, (($f | ForEach-Object { $_.Name }) -join ', ')
}

function Get-SmDhcpImportPlan {
    <#
    .SYNOPSIS
        Vorpruefung des Imports: gewaehlte Bereiche (alle oder einzelne), Ueberlappung mit vorhandenen Bereichen am neuen Server, Hinweis auf Failover.
        Blocking: Ueberschneidung mit einem Bereich anderer ID (nicht importierbar). Existing: Bereich mit gleicher ID ist schon da und wird nur mit
        ScopeOverwrite ersetzt, sonst uebersprungen. Der Zielserver "leer oder nicht" steht in TargetEmpty.
    #>
    param([Parameter(Mandatory)]$Summary, [Parameter(Mandatory)]$Facts, [switch]$All, [string[]]$ScopeIds = @(), [string[]]$Prefixes = @())
    # Die Bereiche kommen aus der Export-XML (Facts), nicht aus der Zusammenfassung. Weichen beide ab, wird nicht importiert.
    $sel4 = @(); $sel6 = @()
    if ($All) { $sel4 = @($Facts.Scopes4); $sel6 = @($Facts.Scopes6) }
    else {
        foreach ($id in $ScopeIds) { $m = @($Facts.Scopes4 | Where-Object { $_.Id -eq $id }); if (-not $m) { throw "Bereich $id steht nicht in der Export-XML." }; $sel4 += $m[0] }
        foreach ($px in $Prefixes) { $m = @($Facts.Scopes6 | Where-Object { $_.Id -eq $px }); if (-not $m) { throw "Praefix $px steht nicht in der Export-XML." }; $sel6 += $m[0] }
    }
    $mismatch = @(Compare-SmDhcpSummaryXml -Summary $Summary -Facts $Facts)
    $local4 = @(Get-DhcpServerv4Scope -ErrorAction Stop)
    $local6 = @(); try { $local6 = @(Get-DhcpServerv6Scope -ErrorAction Stop) } catch { }
    $blocking = New-Object System.Collections.Generic.List[string]; $existing4 = @(); $existing6 = @()
    foreach ($s in $sel4) {
        foreach ($l in $local4) {
            $lid = $l.ScopeId.ToString()
            if ($lid -eq $s.Id) { $existing4 += $s.Id; continue }
            if (Test-SmDhcpSubnetOverlap $s.Id $s.Mask $lid $(if ($l.SubnetMask) { $l.SubnetMask.ToString() } else { '' })) { $blocking.Add(('Bereich {0} ueberlappt mit dem vorhandenen Bereich {1}.' -f $s.Id, $lid)) }
        }
    }
    foreach ($s in $sel6) { if (@($local6 | Where-Object { $_.Prefix.ToString() -eq $s.Id }).Count) { $existing6 += $s.Id } }
    foreach ($m in $mismatch) { $blocking.Add('Zusammenfassung und Export-XML weichen ab, es wird nichts importiert: ' + $m) }
    # Was wirklich importiert wird (aus der XML): Serveroptionen und Optionen der gewaehlten Bereiche
    $preview = New-Object System.Collections.Generic.List[string]
    $fmt = { param($o) $parts = @($script:SmDhcpCheckedOptions | Where-Object { $o.ContainsKey([string]$_) } | ForEach-Object { '{0}={1}' -f $_, $o[[string]$_] }); if ($parts.Count) { $parts -join '; ' } else { '(keine der Optionen 3, 6, 15, 44, 252)' } }
    $preview.Add('Serveroptionen (aus der XML): ' + (& $fmt $Facts.ServerOptions))
    foreach ($s in $sel4) { $preview.Add(('Bereich {0} {1} (aus der XML): {2}' -f $s.Id, $s.Name, (& $fmt $s.Options)).Replace('  ', ' ')) }
    foreach ($s in $sel6) { $preview.Add(('IPv6-Praefix {0} {1} (aus der XML)' -f $s.Id, $s.Name).Replace('  ', ' ')) }
    $warn = New-Object System.Collections.Generic.List[string]
    $count = $local4.Count + $local6.Count
    if ($count) { $warn.Add(('Der neue Server hat bereits {0} Bereich(e). Vorhandene Bereiche mit gleicher ID werden nur nach ausdruecklicher Bestaetigung ersetzt, sonst uebersprungen.' -f $count)) }
    $fn = Get-SmDhcpFailoverNote -Summary $Summary
    if ($fn) { $warn.Add($fn) }
    if (-not ($sel4.Count + $sel6.Count)) { $warn.Add('Kein Bereich gewaehlt: nur die Serverkonfiguration (Optionen, Richtlinien, Filter) wird importiert.') }
    [pscustomobject]@{
        Ok = ($blocking.Count -eq 0); All = [bool]$All; Selected4 = @($sel4 | ForEach-Object { $_.Id }); Selected6 = @($sel6 | ForEach-Object { $_.Id })
        Existing4 = @($existing4); Existing6 = @($existing6); Blocking = $blocking.ToArray(); Warnings = $warn.ToArray(); TargetEmpty = ($count -eq 0); FailoverNote = $fn
        Preview = $preview.ToArray(); Mismatch = $mismatch
    }
}

function Invoke-SmDhcpImport {
    <#
    .SYNOPSIS
        Import-DhcpServer -File -BackupPath [-Leases] [-ScopeId] [-Prefix] [-ScopeOverwrite] [-ServerConfigOnly] -Force.
        Der Aufrufer hat vorher Vorpruefung und Bestaetigung eingeholt; hier wird sie noch einmal geprueft.
        ScopeOverwrite nur, wenn ausdruecklich verlangt. Liefert Warnungen, den Sicherungspfad und den Failover-Hinweis.
    #>
    param(
        [Parameter(Mandatory)]$Opened, [Parameter(Mandatory)]$Plan, [switch]$Leases, [switch]$ScopeOverwrite, [switch]$ServerConfigOnly,
        [scriptblock]$Log = { param($m) }, [string]$BackupRoot
    )
    $pre = Test-SmDhcpPrecheck -Mode Import
    if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    if (-not $Plan.Ok) { throw ('Import nicht moeglich: ' + ($Plan.Blocking -join ' ')) }
    if (@($Opened.Mismatch).Count) { throw ('Zusammenfassung und Export-XML weichen ab, es wird nichts importiert: ' + (@($Opened.Mismatch) -join ' ')) }
    if (-not (Test-Path -LiteralPath $Opened.XmlPath)) { throw 'Die Export-XML fehlt.' }
    Assert-SmDhcpNoReparse -Path (Split-Path -Parent $Opened.XmlPath), $Opened.XmlPath   # direkt vor Import-DhcpServer; das Handle in Opened.XmlHandle haelt die Datei gesperrt
    # Sicherungsordner: der Elternordner (ProgramData\ServerMigration) und der Ordner selbst werden gehaertet und geprueft (Besitzer und Zugriffsliste nur Administratoren und SYSTEM)
    if (-not $BackupRoot) {
        Protect-SmDnsStateDir -Path (Get-SmDnsStateDir)
        $BackupRoot = Join-Path (Get-SmDnsStateDir) ('dhcp-sicherung-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    Protect-SmDnsStateDir -Path $BackupRoot
    $a = @{ File = $Opened.XmlPath; BackupPath = $BackupRoot; Force = $true; ErrorAction = 'Stop' }
    if ($ServerConfigOnly) { $a.ServerConfigOnly = $true }
    else {
        if ($Leases) { $a.Leases = $true }
        if ($ScopeOverwrite) { $a.ScopeOverwrite = $true }
        if (-not $Plan.All) {
            if ($Plan.Selected4.Count) { $a.ScopeId = [Net.IPAddress[]]@($Plan.Selected4 | ForEach-Object { [Net.IPAddress]::Parse($_) }) }
            if ($Plan.Selected6.Count) { $a.Prefix = [Net.IPAddress[]]@($Plan.Selected6 | ForEach-Object { [Net.IPAddress]::Parse($_) }) }
        }
    }
    $what = if ($ServerConfigOnly) { 'nur Serverkonfiguration' } elseif ($Plan.All) { 'alle Bereiche' } else { ('{0} Bereich(e) v4, {1} v6' -f $Plan.Selected4.Count, $Plan.Selected6.Count) }
    [void](Write-SmDhcpAudit -Action 'Import gestartet' -Text ('{0}{1}{2}, Sicherung in {3}' -f $what, $(if ($a.Leases) { ', mit Leases' } else { '' }), $(if ($a.ScopeOverwrite) { ', vorhandene Bereiche werden ersetzt' } else { '' }), $BackupRoot) -Log $Log)
    $w = @()
    try { Import-DhcpServer @a -WarningVariable w }
    catch {
        [void](Write-SmDhcpAudit -Action 'Import fehlgeschlagen' -Text $_.Exception.Message -Log $Log)
        throw
    }
    foreach ($x in @($w)) { & $Log ('Warnung von Import-DhcpServer: ' + [string]$x) }
    [void](Write-SmDhcpAudit -Action 'Import beendet' -Text ('{0} Warnung(en)' -f @($w).Count) -Log $Log)
    [pscustomobject]@{ Warnings = @($w | ForEach-Object { [string]$_ }); BackupPath = $BackupRoot; FailoverNote = $Plan.FailoverNote }
}

function Invoke-SmDhcpAuthorize {
    <# Add-DhcpServerInDC fuer diesen Server (nach dem Import, mit Bestaetigung durch den Aufrufer). #>
    param([scriptblock]$Log = { param($m) })
    $pre = Test-SmDhcpPrecheck -Mode Authorize
    if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    [void](Write-SmDhcpAudit -Action 'Autorisierung gestartet' -Text ('Add-DhcpServerInDC fuer ' + $env:COMPUTERNAME) -Log $Log)
    try { Add-DhcpServerInDC -ErrorAction Stop | Out-Null }
    catch {
        [void](Write-SmDhcpAudit -Action 'Autorisierung fehlgeschlagen' -Text $_.Exception.Message -Log $Log)
        throw
    }
    $now = Get-SmDhcpAuthState
    [void](Write-SmDhcpAudit -Action 'Autorisierung beendet' -Text $(if ($now -eq $true) { 'Server steht in der Liste der autorisierten DHCP-Server' } else { 'Eintrag angelegt, in der Liste noch nicht zu sehen (Replikation abwarten)' }) -Log $Log)
    $now
}

# ---------------------------------------------------------------- Bereiche am alten Server deaktivieren

function Get-SmDhcpLocalScopes {
    <# Bereiche dieses Servers fuer die Auswahl (Art, Bereich, Name, Status). #>
    $out = @()
    $out += @(Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Kind = 'v4'; Id = $_.ScopeId.ToString(); Name = [string]$_.Name; State = [string]$_.State } })
    try { $out += @(Get-DhcpServerv6Scope -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Kind = 'v6'; Id = $_.Prefix.ToString(); Name = [string]$_.Name; State = [string]$_.State } }) } catch { }
    $out
}

function Get-SmDhcpDeactivatePlan {
    <# Vorpruefung: gewaehlte Bereiche muessen existieren; Bereiche in einer Failover-Beziehung werden gemeldet (die Aenderung wuerde zum Partner repliziert). #>
    param([string[]]$ScopeIds = @(), [string[]]$Prefixes = @())
    $local4 = @(Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object { $_.ScopeId.ToString() })
    $local6 = @(); try { $local6 = @(Get-DhcpServerv6Scope -ErrorAction Stop | ForEach-Object { $_.Prefix.ToString() }) } catch { }
    $missing = @(@($ScopeIds | Where-Object { $local4 -notcontains $_ }) + @($Prefixes | Where-Object { $local6 -notcontains $_ }))
    $warn = New-Object System.Collections.Generic.List[string]
    foreach ($id in $ScopeIds) {
        $f = @(Get-DhcpServerv4Failover -ScopeId $id -ErrorAction SilentlyContinue)
        if ($f.Count) { $warn.Add(('Bereich {0} steht in der Failover-Beziehung {1}: das Deaktivieren wird zum Partner repliziert.' -f $id, (($f | ForEach-Object { $_.Name }) -join ', '))) }
    }
    [pscustomobject]@{ Ok = ($missing.Count -eq 0 -and ($ScopeIds.Count + $Prefixes.Count) -gt 0); Missing = $missing; Warnings = $warn.ToArray(); ScopeIds = @($ScopeIds); Prefixes = @($Prefixes) }
}

function Invoke-SmDhcpDeactivate {
    <# Set-DhcpServerv4Scope/-v6Scope -State InActive fuer die gewaehlten Bereiche (alter Server, nach dem Import, mit Bestaetigung durch den Aufrufer). Rueckweg: -State Active. #>
    param([string[]]$ScopeIds = @(), [string[]]$Prefixes = @(), [scriptblock]$Log = { param($m) })
    $pre = Test-SmDhcpPrecheck -Mode Deactivate
    if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden: ' + (($pre.Items | Where-Object { -not $_.Ok -and $_.Blocking } | ForEach-Object { $_.Text }) -join ' ')) }
    $plan = Get-SmDhcpDeactivatePlan -ScopeIds $ScopeIds -Prefixes $Prefixes
    if (-not $plan.Ok) { throw ('Bereiche nicht gefunden oder keine Auswahl: ' + ($plan.Missing -join ', ')) }
    foreach ($id in $ScopeIds) {
        Set-DhcpServerv4Scope -ScopeId ([Net.IPAddress]::Parse($id)) -State InActive -ErrorAction Stop
        [void](Write-SmDhcpAudit -Action 'Bereich deaktiviert' -Text ('v4 ' + $id) -Log $Log)
    }
    foreach ($px in $Prefixes) {
        Set-DhcpServerv6Scope -Prefix ([Net.IPAddress]::Parse($px)) -State InActive -ErrorAction Stop
        [void](Write-SmDhcpAudit -Action 'Bereich deaktiviert' -Text ('v6 ' + $px) -Log $Log)
    }
    $ScopeIds.Count + $Prefixes.Count
}

function Get-SmDhcpDeactivateText {
    <# Text der Bestaetigung zum Deaktivieren: nennt den Server (Computername). Hat dieser Server in dieser Sitzung importiert, kommt eine zusaetzliche Warnung. #>
    param([Parameter(Mandatory)]$Plan, [string]$ServerName = $env:COMPUTERNAME, [bool]$ImportedHere = $false)
    $t = "Diese Bereiche werden am Server $ServerName DEAKTIVIERT (Status InActive). Clients bekommen von diesem Server dann keine Adressen mehr.`n`n" + (($Plan.ScopeIds + $Plan.Prefixes) -join ', ')
    if ($ImportedHere) { $t += "`n`nACHTUNG: Dieser Server ($ServerName) hat in dieser Sitzung selbst importiert. Er ist vermutlich der NEUE Server. Deaktiviert werden sollen die Bereiche am ALTEN Server. Nur fortfahren, wenn Sie das wirklich hier wollen." }
    if ($Plan.Warnings.Count) { $t += "`n`nHinweise:`n- " + ($Plan.Warnings -join "`n- ") }
    $t + "`n`nNur ausfuehren, wenn der neue Server die Bereiche uebernommen hat und autorisiert ist. Rueckgaengig: Bereich wieder aktivieren.`n`nFortfahren?"
}

function Get-SmDhcpExportText {
    <# Text der Bestaetigung zum Export: nennt die personenbezogenen Daten (MAC-Adressen, Hostnamen), wenn Leases mitgehen. #>
    param([switch]$NoLeases)
    if ($NoLeases) { return "Der DHCP-Server wird OHNE Leases exportiert (Export-DhcpServer) und als ZIP in den Tauschordner gelegt.`n`nEnthalten sind Bereiche, Optionen und Reservierungen. Reservierungen nennen Geraetenamen und MAC-Adressen.`nEr aendert nichts am DHCP-Server.`n`nFortfahren?" }
    "Der DHCP-Server wird MIT Leases exportiert (Export-DhcpServer -Leases) und als ZIP in den Tauschordner gelegt.`n`nDie Leases enthalten MAC-Adressen und Hostnamen der Geraete. Das sind personenbezogene Daten. Wenn Sie sie nicht brauchen, brechen Sie ab und waehlen `"Ohne Leases exportieren`". Den Tauschordner nach dem Projekt loeschen.`nDer Export aendert nichts am DHCP-Server.`n`nFortfahren?"
}

# ---------------------------------------------------------------- Oberflaeche

function Register-SmDhcpServerPage {
    <# Haengt die Knoepfe des DHCP-Bereichs ein (UI\DhcpServer.xaml). Die Logik steckt in den Funktionen oben, hier nur Oberflaeche und Bestaetigungen. #>
    param(
        [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string[]]$JobModules,
        [Parameter(Mandatory)][scriptblock]$GetShare, [Parameter(Mandatory)][scriptblock]$AddLog
    )
    $script:SmDhcpSrv = @{ Ui = $Ui; Modules = $JobModules; GetShare = $GetShare; AddLog = $AddLog; Remote = @{}; Down = $null; Opened = $null; OldScopes = @{}; LastSha = $null; ImportedHere = $false }
    $Ui.BtnDhcpCopySha.IsEnabled = $false
    $Ui.BoxDhcpImport.Visibility = 'Collapsed'

    $Ui.BtnDhcpCheck.Add_Click({
            $c = $script:SmDhcpSrv; $c.Ui.TxtDhcpCheck.Text = 'Pruefe ...'
            [void](Start-SmJob -Modules $c.Modules -Script {
                    param($State, $P)
                    @('Export', 'Import', 'Authorize') | ForEach-Object { $r = Test-SmDhcpPrecheck -Mode $_; [pscustomobject]@{ Mode = $_; Lines = $r.Lines; Ok = $r.Ok } }
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv
                    if ($err) { $c2.Ui.TxtDhcpCheck.Text = 'Fehler'; & $c2.AddLog ('DHCP: ' + $err); return }
                    $names = @{ Export = 'Export und Deaktivieren'; Import = 'Import'; Authorize = 'Autorisierung' }
                    $c2.Ui.TxtDhcpCheck.Text = (@($result | ForEach-Object { $names[$_.Mode] + ($(if ($_.Ok) { ' (bereit)' } else { ' (nicht bereit)' })) + "`r`n  " + ($_.Lines -join "`r`n  ") }) -join "`r`n")
                })
        })

    $Ui.BtnDhcpExport.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui; $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'DHCP: Kein Tauschordner verbunden (Seite "Dieser Server", "Ordner pruefen").'; return }
            $noLeases = [bool]$u.ChkDhcpNoLeases.IsChecked
            $msg = Get-SmDhcpExportText -NoLeases:$noLeases
            if ([System.Windows.MessageBox]::Show($msg, 'DHCP exportieren', 'YesNo', 'Question') -ne 'Yes') { & $c.AddLog 'DHCP-Export abgebrochen.'; return }
            $u.BtnDhcpExport.IsEnabled = $false; $u.BtnDhcpCopySha.IsEnabled = $false; $c.LastSha = $null; $u.PrgDhcpExport.Value = 0; $u.PrgDhcpExport.Visibility = 'Visible'; $u.TxtDhcpExport.Text = 'Exportiere ...'; $u.TxtDhcpExportSha.Text = ''
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; NoLeases = $noLeases } -Script {
                    param($State, $P)
                    Publish-SmDhcpExport -Share $P.Share -NoLeases:$P.NoLeases -Progress { param($sent, $total) $State.Sent = $sent; $State.Total = $total } -Log { param($m) $State.Log.Enqueue($m) }
                } -OnTick { param($s) Write-SmDhcpJobLog $s; if ($s.Total -gt 0) { $script:SmDhcpSrv.Ui.PrgDhcpExport.Value = [math]::Min(100, 100 * $s.Sent / $s.Total) } } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $c2.Ui.BtnDhcpExport.IsEnabled = $true
                    if ($err) { $c2.Ui.TxtDhcpExport.Text = 'Fehlgeschlagen'; & $c2.AddLog ('DHCP-Export: Fehler: ' + $err); return }
                    $r = $result[-1]
                    $c2.Ui.TxtDhcpExport.Text = 'Fertig: ' + $r.Name
                    $c2.LastSha = [string]$r.Sha256
                    $c2.Ui.BtnDhcpCopySha.IsEnabled = $true
                    $c2.Ui.TxtDhcpExportSha.Text = 'SHA256 ' + $r.Sha256 + '   (mit "SHA256 kopieren" holen und am neuen Server einfuegen)'
                })
        })
    $Ui.BtnDhcpCopySha.Add_Click({
            $c = $script:SmDhcpSrv
            if (-not $c.LastSha) { return }
            try { [System.Windows.Clipboard]::SetText($c.LastSha); & $c.AddLog 'DHCP: SHA256 des Exports in die Zwischenablage kopiert.' }
            catch { & $c.AddLog ('DHCP: Kopieren fehlgeschlagen: ' + $_.Exception.Message) }
        })

    $Ui.BtnDhcpFind.Add_Click({
            $c = $script:SmDhcpSrv; $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'DHCP: Kein Tauschordner verbunden (Seite "Dieser Server", "Ordner pruefen").'; return }
            $c.Ui.BtnDhcpFind.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share } -Script {
                    param($State, $P)
                    @(Get-SmShareFiles -Share $P.Share | Where-Object { (Get-SmDhcpFileKind $_.Name) -eq 'Export' } | Sort-Object Modified -Descending)
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u = $c2.Ui; $u.BtnDhcpFind.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DHCP: ' + $err); return }
                    $u.LstDhcpExports.Items.Clear(); $c2.Remote = @{}
                    foreach ($f in @($result | Where-Object { $_ -and $_.Name })) { $label = '{0}  ({1})' -f $f.Name, (Format-SmSize $f.Length); $c2.Remote[$label] = $f; [void]$u.LstDhcpExports.Items.Add($label) }
                    $u.BtnDhcpDownload.IsEnabled = ($u.LstDhcpExports.Items.Count -gt 0)
                    if ($u.LstDhcpExports.Items.Count) { $u.LstDhcpExports.SelectedIndex = 0 }
                    & $c2.AddLog ('DHCP: {0} Export(e) im Tauschordner' -f $u.LstDhcpExports.Items.Count)
                })
        })

    $Ui.BtnDhcpDownload.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui; $share = & $c.GetShare
            $remote = $c.Remote[[string]$u.LstDhcpExports.SelectedItem]
            if (-not $share -or -not $remote) { return }
            if ($c.Down) { Close-SmDhcpImport -Down $c.Down -Opened $c.Opened; $c.Down = $null }
            $c.Opened = $null; $u.BoxDhcpImport.Visibility = 'Collapsed'; $u.TxtDhcpShaIn.Text = ''; $u.TxtDhcpShaIn.IsEnabled = $false; $u.TxtDhcpShaState.Text = ''; $u.BtnDhcpOpen.IsEnabled = $false
            $u.BtnDhcpDownload.IsEnabled = $false; $u.TxtDhcpDlSha.Text = 'Lade herunter ...'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; Remote = $remote } -Script {
                    param($State, $P)
                    Receive-SmDhcpExport -Share $P.Share -Remote $P.Remote
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u2 = $c2.Ui; $u2.BtnDhcpDownload.IsEnabled = $true
                    if ($err) { $u2.TxtDhcpDlSha.Text = 'Fehlgeschlagen'; & $c2.AddLog ('DHCP: Download fehlgeschlagen: ' + $err); return }
                    $c2.Down = $result[-1]
                    $u2.TxtDhcpDlSha.Text = 'Berechnet am neuen Server: SHA256 ' + $c2.Down.Sha256
                    $u2.TxtDhcpShaIn.IsEnabled = $true; $u2.TxtDhcpShaState.Text = 'Bitte die vollstaendige SHA256 vom alten Server einfuegen.'
                    & $c2.AddLog ('DHCP: heruntergeladen: {0} ({1}), SHA256 {2}' -f $c2.Down.Name, (Format-SmSize $c2.Down.Length), $c2.Down.Sha256)
                })
        })
    $Ui.TxtDhcpShaIn.Add_TextChanged({
            $c = $script:SmDhcpSrv; $u = $c.Ui
            $ok = [bool]($c.Down -and (Test-SmDhcpShaMatch -Expected $c.Down.Sha256 -Entered $u.TxtDhcpShaIn.Text))
            $u.BtnDhcpOpen.IsEnabled = $ok
            $u.TxtDhcpShaState.Text = if (-not $c.Down) { '' } elseif ($ok) { 'Die Pruefsumme stimmt vollstaendig ueberein.' } elseif (-not $u.TxtDhcpShaIn.Text.Trim()) { 'Bitte die vollstaendige SHA256 vom alten Server einfuegen.' } else { 'Die Pruefsumme stimmt NICHT ueberein (oder ist unvollstaendig). Oeffnen und Import bleiben aus.' }
        })

    $Ui.BtnDhcpOpen.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui
            if (-not $c.Down -or -not (Test-SmDhcpShaMatch -Expected $c.Down.Sha256 -Entered $u.TxtDhcpShaIn.Text)) { $u.BtnDhcpOpen.IsEnabled = $false; return }
            $entered = $u.TxtDhcpShaIn.Text
            & $c.AddLog ('DHCP: eingegebene SHA256 stimmt vollstaendig mit der Datei ueberein: ' + $c.Down.Sha256)
            $u.BtnDhcpOpen.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Params @{ Zip = $c.Down.ZipPath; Dir = $c.Down.Dir; Sha = $entered } -Script {
                    param($State, $P)
                    Open-SmDhcpExport -ZipPath $P.Zip -Dir $P.Dir -ExpectedSha $P.Sha
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u2 = $c2.Ui; $u2.BtnDhcpOpen.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DHCP: Export abgelehnt: ' + $err); return }
                    $c2.Opened = $result[-1]; $s = $c2.Opened.Summary
                    $u2.LstDhcpScopes.Items.Clear()
                    # Die Liste kommt aus der Export-XML (das, was importiert wird); Namen und Lease-Zahl ergaenzt die Zusammenfassung
                    foreach ($x in $c2.Opened.Facts.Scopes4) { $m = @($s.Scopes4 | Where-Object { $_.ScopeId -eq $x.Id }); [void]$u2.LstDhcpScopes.Items.Add(('v4  {0}  {1}  ({2} Leases)' -f $x.Id, $x.Name, $(if ($m.Count) { $m[0].Leases } else { '?' }))) }
                    foreach ($x in $c2.Opened.Facts.Scopes6) { $m = @($s.Scopes6 | Where-Object { $_.Prefix -eq $x.Id }); [void]$u2.LstDhcpScopes.Items.Add(('v6  {0}  {1}  ({2} Leases)' -f $x.Id, $x.Name, $(if ($m.Count) { $m[0].Leases } else { '?' }))) }
                    $u2.TxtDhcpInfo.Text = 'Export von {0} ({1}): {2} Bereich(e) v4, {3} v6 laut Export-XML. {4}{5}' -f $s.Server, $s.Created, @($c2.Opened.Facts.Scopes4).Count, @($c2.Opened.Facts.Scopes6).Count, (Get-SmDhcpFailoverNote -Summary $s), $(if ($c2.Opened.Mismatch.Count) { "`r`nZusammenfassung und Export-XML weichen ab, Import gesperrt: " + ($c2.Opened.Mismatch -join ' ') } else { '' })
                    if ($c2.Opened.Mismatch.Count) { & $c2.AddLog ('DHCP: Zusammenfassung und Export-XML weichen ab: ' + ($c2.Opened.Mismatch -join ' ')) }
                    $u2.RdoDhcpAll.IsChecked = $true
                    $u2.BoxDhcpImport.Visibility = 'Visible'
                    & $c2.AddLog 'DHCP: Export geprueft (XML ohne DTD, Zusammenfassung gueltig)'
                })
        })

    $Ui.BtnDhcpImport.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui
            if (-not $c.Opened) { return }
            $all = [bool]$u.RdoDhcpAll.IsChecked
            $ids = @(); $px = @()
            if (-not $all) {
                foreach ($item in $u.LstDhcpScopes.SelectedItems) { $p = ([string]$item) -split '\s+'; if ($p[0] -eq 'v4') { $ids += $p[1] } else { $px += $p[1] } }
                if (-not ($ids.Count + $px.Count)) { & $c.AddLog 'DHCP: Keine Bereiche ausgewaehlt.'; return }
            }
            $leases = [bool]$u.ChkDhcpLeases.IsChecked
            $u.BtnDhcpImport.IsEnabled = $false; $u.TxtDhcpImport.Text = 'Pruefe ...'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Summary = $c.Opened.Summary; Facts = $c.Opened.Facts; All = $all; Ids = $ids; Px = $px } -Script {
                    param($State, $P)
                    $pre = Test-SmDhcpPrecheck -Mode Import
                    $plan = $null
                    if ($pre.Ok) { $plan = Get-SmDhcpImportPlan -Summary $P.Summary -Facts $P.Facts -All:$P.All -ScopeIds $P.Ids -Prefixes $P.Px }
                    [pscustomobject]@{ Pre = $pre; Plan = $plan }
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u2 = $c2.Ui; $u2.BtnDhcpImport.IsEnabled = $true; $u2.TxtDhcpImport.Text = ''
                    if ($err) { & $c2.AddLog ('DHCP: Vorpruefung: ' + $err); return }
                    $r = $result[-1]
                    if (-not $r.Pre.Ok) { $u2.TxtDhcpImport.Text = ($r.Pre.Lines -join "`r`n"); & $c2.AddLog 'DHCP: Vorpruefung des Imports nicht bestanden.'; return }
                    $plan = $r.Plan
                    if (-not $plan.Ok) { $u2.TxtDhcpImport.Text = ($plan.Blocking -join "`r`n"); & $c2.AddLog ('DHCP: Import nicht moeglich: ' + ($plan.Blocking -join ' ')); return }
                    $what = if ($plan.All) { 'ALLE Bereiche (laut Export-XML) und die Serverkonfiguration' } else { ('Bereiche (laut Export-XML): ' + (($plan.Selected4 + $plan.Selected6) -join ', ')) }
                    $msg = "Import auf diesem Server (Import-DhcpServer)`n`n$what`n" + $(if ([bool]$u2.ChkDhcpLeases.IsChecked) { "mit Leases`n" } else { "ohne Leases`n" }) +
                    "`nWas die Export-XML enthaelt (das wird importiert):`n- " + ($plan.Preview -join "`n- ") + "`n" +
                    $(if ($plan.Warnings.Count) { "`nHinweise:`n- " + ($plan.Warnings -join "`n- ") + "`n" } else { '' }) +
                    "`nVor der Aenderung sichert der Import die DHCP-Datenbank. Fortfahren?"
                    if ([System.Windows.MessageBox]::Show($msg, 'DHCP importieren', 'YesNo', 'Warning') -ne 'Yes') { & $c2.AddLog 'DHCP-Import abgebrochen.'; return }
                    $over = $false
                    $exist = @($plan.Existing4) + @($plan.Existing6)
                    if ($exist.Count) {
                        $ans = [System.Windows.MessageBox]::Show(("Diese Bereiche gibt es am neuen Server schon:`n`n" + ($exist -join ', ') + "`n`nJa = vorhandene Bereiche LOESCHEN und aus dem Export neu anlegen`nNein = vorhandene Bereiche behalten und uebersprungen`nAbbrechen = nichts importieren"), 'Vorhandene Bereiche', 'YesNoCancel', 'Warning')
                        if ($ans -eq 'Cancel') { & $c2.AddLog 'DHCP-Import abgebrochen.'; return }
                        $over = ($ans -eq 'Yes')
                        if ($over -and [System.Windows.MessageBox]::Show('Wirklich: die vorhandenen Bereiche werden geloescht und neu angelegt.', 'Vorhandene Bereiche ersetzen', 'YesNo', 'Stop') -ne 'Yes') { & $c2.AddLog 'DHCP-Import abgebrochen.'; return }
                    }
                    $u2.BtnDhcpImport.IsEnabled = $false; $u2.TxtDhcpImport.Text = 'Importiere ...'
                    [void](Start-SmJob -Modules $c2.Modules -Params @{ Opened = $c2.Opened; Plan = $plan; Leases = [bool]$u2.ChkDhcpLeases.IsChecked; Over = $over } -Script {
                            param($State, $P)
                            Invoke-SmDhcpImport -Opened $P.Opened -Plan $P.Plan -Leases:$P.Leases -ScopeOverwrite:$P.Over -Log { param($m) $State.Log.Enqueue($m) }
                        } -OnTick { param($s) Write-SmDhcpJobLog $s } -OnDone {
                            param($result2, $err2)
                            $c3 = $script:SmDhcpSrv; $c3.Ui.BtnDhcpImport.IsEnabled = $true
                            # Aufraeumen: Handles zu, Arbeitsordner weg (auch nach einem Fehler; fuer einen neuen Versuch neu herunterladen)
                            Close-SmDhcpImport -Down $c3.Down -Opened $c3.Opened; $c3.Down = $null; $c3.Opened = $null
                            $c3.Ui.BtnDhcpImport.IsEnabled = $false; $c3.Ui.TxtDhcpShaIn.Text = ''; $c3.Ui.TxtDhcpShaIn.IsEnabled = $false; $c3.Ui.BtnDhcpOpen.IsEnabled = $false
                            if ($err2) { $c3.Ui.TxtDhcpImport.Text = 'Fehlgeschlagen'; & $c3.AddLog ('DHCP-Import: Fehler: ' + $err2); return }
                            $r2 = $result2[-1]
                            $c3.ImportedHere = $true   # fuer die Warnung beim Deaktivieren: dieser Server hat in dieser Sitzung importiert
                            $c3.Ui.TxtDhcpImport.Text = 'Fertig. ' + $(if ($r2.Warnings.Count) { '{0} Warnung(en), siehe Protokoll. ' -f $r2.Warnings.Count } else { '' }) + 'Naechste Schritte: Autorisieren, Zusammenfassung hochladen, Failover von Hand.'
                            if ($r2.FailoverNote) { & $c3.AddLog ('DHCP: ' + $r2.FailoverNote) }
                        })
                })
        })

    $Ui.BtnDhcpAuth.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui
            $u.BtnDhcpAuth.IsEnabled = $false; $u.TxtDhcpAuth.Text = 'Pruefe ...'
            [void](Start-SmJob -Modules $c.Modules -Script { param($State, $P) Test-SmDhcpPrecheck -Mode Authorize } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u2 = $c2.Ui; $u2.BtnDhcpAuth.IsEnabled = $true
                    if ($err) { $u2.TxtDhcpAuth.Text = 'Fehler'; & $c2.AddLog ('DHCP: ' + $err); return }
                    $pre = $result[-1]; $u2.TxtDhcpAuth.Text = ($pre.Lines -join "`r`n")
                    if (-not $pre.Ok) { & $c2.AddLog 'DHCP: Vorpruefung der Autorisierung nicht bestanden.'; return }
                    $msg = "Dieser Server ($env:COMPUTERNAME) wird in Active Directory als DHCP-Server autorisiert (Add-DhcpServerInDC). Danach vergibt er Adressen im Netz.`n`nDer alte Server sollte vorher seine Bereiche deaktiviert haben, sonst vergeben zwei Server dieselben Adressen.`n`nFortfahren?"
                    if ([System.Windows.MessageBox]::Show($msg, 'DHCP-Server autorisieren', 'YesNo', 'Warning') -ne 'Yes') { & $c2.AddLog 'DHCP-Autorisierung abgebrochen.'; return }
                    $u2.BtnDhcpAuth.IsEnabled = $false
                    [void](Start-SmJob -Modules $c2.Modules -Script { param($State, $P) Invoke-SmDhcpAuthorize -Log { param($m) $State.Log.Enqueue($m) } } -OnTick { param($s) Write-SmDhcpJobLog $s } -OnDone {
                            param($result2, $err2)
                            $c3 = $script:SmDhcpSrv; $c3.Ui.BtnDhcpAuth.IsEnabled = $true
                            if ($err2) { $c3.Ui.TxtDhcpAuth.Text = 'Fehlgeschlagen'; & $c3.AddLog ('DHCP-Autorisierung: Fehler: ' + $err2); return }
                            $c3.Ui.TxtDhcpAuth.Text = 'Autorisierung angestossen.'
                        })
                })
        })

    $Ui.BtnDhcpAfter.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui; $share = & $c.GetShare
            if (-not $share) { & $c.AddLog 'DHCP: Kein Tauschordner verbunden.'; return }
            $noLeases = [bool]$u.ChkDhcpAfterNoLeases.IsChecked
            if (-not $noLeases -and [System.Windows.MessageBox]::Show("Die Datei enthaelt je Adresse die Lease-Zuordnung mit MAC-Adressen der Geraete. Das sind personenbezogene Daten. Wenn Sie sie nicht brauchen, brechen Sie ab und setzen Sie den Haken `"Ohne Leases`".`n`nFortfahren?", 'Stand hochladen', 'YesNo', 'Question') -ne 'Yes') { & $c.AddLog 'DHCP: Hochladen abgebrochen.'; return }
            $u.BtnDhcpAfter.IsEnabled = $false; $u.TxtDhcpAfter.Text = 'Lese und lade hoch ...'
            [void](Start-SmJob -Modules $c.Modules -Params @{ Share = $share; NoLeases = $noLeases } -Script {
                    param($State, $P)
                    Publish-SmDhcpAfter -Share $P.Share -NoLeases:$P.NoLeases -Log { param($m) $State.Log.Enqueue($m) }
                } -OnTick { param($s) Write-SmDhcpJobLog $s } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $c2.Ui.BtnDhcpAfter.IsEnabled = $true
                    if ($err) { $c2.Ui.TxtDhcpAfter.Text = 'Fehlgeschlagen'; & $c2.AddLog ('DHCP: Fehler: ' + $err); return }
                    $c2.Ui.TxtDhcpAfter.Text = 'Hochgeladen: ' + $result[-1].Name + '  SHA256 ' + $result[-1].Sha256
                })
        })

    $Ui.BtnDhcpOldList.Add_Click({
            $c = $script:SmDhcpSrv
            [void](Start-SmJob -Modules $c.Modules -Script { param($State, $P) Get-SmDhcpLocalScopes } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u = $c2.Ui
                    if ($err) { & $c2.AddLog ('DHCP: ' + $err); return }
                    $u.LstDhcpOldScopes.Items.Clear(); $c2.OldScopes = @{}
                    foreach ($s in @($result | Where-Object { $_ -and $_.Id })) { $label = '{0}  {1}  {2}  [{3}]' -f $s.Kind, $s.Id, $s.Name, $s.State; $c2.OldScopes[$label] = $s; [void]$u.LstDhcpOldScopes.Items.Add($label) }
                    $u.BtnDhcpDeactivate.IsEnabled = ($u.LstDhcpOldScopes.Items.Count -gt 0)
                })
        })
    $Ui.BtnDhcpDeactivate.Add_Click({
            $c = $script:SmDhcpSrv; $u = $c.Ui
            $sel = @($u.LstDhcpOldScopes.SelectedItems | ForEach-Object { $c.OldScopes[[string]$_] } | Where-Object { $_ })
            if (-not $sel.Count) { & $c.AddLog 'DHCP: Keine Bereiche zum Deaktivieren ausgewaehlt.'; return }
            $ids = @($sel | Where-Object Kind -eq 'v4' | ForEach-Object { $_.Id }); $px = @($sel | Where-Object Kind -eq 'v6' | ForEach-Object { $_.Id })
            $u.BtnDhcpDeactivate.IsEnabled = $false
            [void](Start-SmJob -Modules $c.Modules -Params @{ Ids = $ids; Px = $px } -Script {
                    param($State, $P)
                    $pre = Test-SmDhcpPrecheck -Mode Deactivate
                    $plan = $null; if ($pre.Ok) { $plan = Get-SmDhcpDeactivatePlan -ScopeIds $P.Ids -Prefixes $P.Px }
                    [pscustomobject]@{ Pre = $pre; Plan = $plan }
                } -OnDone {
                    param($result, $err)
                    $c2 = $script:SmDhcpSrv; $u2 = $c2.Ui; $u2.BtnDhcpDeactivate.IsEnabled = $true
                    if ($err) { & $c2.AddLog ('DHCP: ' + $err); return }
                    $r = $result[-1]
                    if (-not $r.Pre.Ok) { & $c2.AddLog ('DHCP: Vorpruefung nicht bestanden: ' + (($r.Pre.Lines | Where-Object { $_ -like '`[!!`]*' }) -join ' ')); return }
                    if (-not $r.Plan.Ok) { & $c2.AddLog ('DHCP: Bereiche nicht gefunden: ' + ($r.Plan.Missing -join ', ')); return }
                    $msg = Get-SmDhcpDeactivateText -Plan $r.Plan -ServerName ([string]$env:COMPUTERNAME) -ImportedHere ([bool]$c2.ImportedHere)
                    if ([System.Windows.MessageBox]::Show($msg, 'Bereiche am alten Server deaktivieren', 'YesNo', 'Warning') -ne 'Yes') { & $c2.AddLog 'DHCP: Deaktivieren abgebrochen.'; return }
                    $u2.BtnDhcpDeactivate.IsEnabled = $false
                    [void](Start-SmJob -Modules $c2.Modules -Params @{ Ids = $r.Plan.ScopeIds; Px = $r.Plan.Prefixes } -Script {
                            param($State, $P)
                            Invoke-SmDhcpDeactivate -ScopeIds $P.Ids -Prefixes $P.Px -Log { param($m) $State.Log.Enqueue($m) }
                        } -OnTick { param($s) Write-SmDhcpJobLog $s } -OnDone {
                            param($result2, $err2)
                            $c3 = $script:SmDhcpSrv; $c3.Ui.BtnDhcpDeactivate.IsEnabled = $true
                            if ($err2) { & $c3.AddLog ('DHCP: Deaktivieren fehlgeschlagen: ' + $err2) }
                            $c3.Ui.BtnDhcpOldList.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
                        })
                })
        })
}

function Write-SmDhcpJobLog {
    param($State)
    $line = $null
    while ($State.Log.TryDequeue([ref]$line)) { & $script:SmDhcpSrv.AddLog $line }
}
