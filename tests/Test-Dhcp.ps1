#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 4 (DHCP): Server-Funktionen gegen nachgebaute DhcpServer-Cmdlets (Parameterlisten wie in der Microsoft-Doku, unbekannte
    Parameter lassen den Aufruf scheitern), Vorpruefungen, Export, Import, Autorisierung, Deaktivieren, Vergleichslogik mit Beispieldaten
    (contoso.local, 10.x), feindliche Daten (JSON, XML, ZIP, Dateinamen), -ParseOnly beider Fenster.
    Wird von tests\Test-ServerMigration.ps1 aufgerufen und liefert die Zahl der Fehler zurueck. Allein:
    powershell.exe -NoProfile -STA -File tests\Test-Dhcp.ps1
    Keine echten Server, keine echten Tenants, keine Links ins Netz. Beispieldaten nur mit contoso.
#>
[CmdletBinding()]
param([string]$Repo, [string]$Work)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
if (-not $Repo) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
if (-not $Work) { $Work = Join-Path $env:TEMP ('sm-dhcp-' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Force $Work | Out-Null }
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }
function ThrowsLike([scriptblock]$Block, [string]$Pattern) { try { & $Block | Out-Null; $false } catch { $_.Exception.Message -match $Pattern } }

. (Join-Path $Repo 'Modules\SmShell.ps1')
. (Join-Path $Repo 'Modules\SmTausch.ps1')
. (Join-Path $Repo 'Modules\SmDhcp.ps1')
. (Join-Path $Repo 'server\SmDhcpServer.ps1')
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$script:SmDhcpAuditPath = Join-Path $Work 'dhcp-audit.log'
$tmpRoot = Join-Path $Work 'dhcp-temp'; New-Item -ItemType Directory -Force $tmpRoot | Out-Null
$store = Join-Path $Work 'dhcp-store'; New-Item -ItemType Directory -Force $store | Out-Null

# ---------------------------------------------------------------- nachgebaute Umgebung
$script:Calls = New-Object System.Collections.Generic.List[object]
$script:IsAdmin = $true
function Test-SmDhcpAdmin { $script:IsAdmin }
function Get-Service { [CmdletBinding()] param([string]$Name) if ($null -eq $script:M.Service) { Write-Error "Dienst $Name nicht gefunden" -ErrorAction Stop }; [pscustomobject]@{ Name = $Name; Status = $script:M.Service } }

# Parameterlisten wie in der Doku (Microsoft Learn, DhcpServer-Modul); weitere Parameter gibt es nicht
function Export-DhcpServer { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][string]$File, [Net.IPAddress[]]$ScopeId, [Net.IPAddress[]]$Prefix, [switch]$Leases, [switch]$Force, [string]$ComputerName, $CimSession)
    Rec 'Export-DhcpServer' $PSBoundParameters
    [IO.File]::WriteAllText($File, '<?xml version="1.0" encoding="utf-8"?><DHCPServer><IPv4><Scope><ScopeId>10.10.0.0</ScopeId></Scope></IPv4></DHCPServer>') }
function Import-DhcpServer { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][string]$File, [Parameter(Mandatory, Position = 1)][string]$BackupPath, [Net.IPAddress[]]$ScopeId, [Net.IPAddress[]]$Prefix, [switch]$ScopeOverwrite, [switch]$Leases, [switch]$ServerConfigOnly, [switch]$Force, [string]$ComputerName, $CimSession)
    Rec 'Import-DhcpServer' $PSBoundParameters
    if ($script:M.ImportWarning) { Write-Warning $script:M.ImportWarning } }
function Get-DhcpServerInDC { [CmdletBinding()] param($CimSession, [int]$ThrottleLimit, [switch]$AsJob) if ($script:M.InDC -eq 'error') { Write-Error 'kein AD' -ErrorAction Stop }; @($script:M.InDC) }
function Add-DhcpServerInDC { [CmdletBinding()] param([Parameter(Position = 1)][string]$DnsName, [Parameter(Position = 2)][Net.IPAddress]$IPAddress, [switch]$PassThru, $CimSession, [int]$ThrottleLimit, [switch]$AsJob, [switch]$WhatIf, [switch]$Confirm)
    Rec 'Add-DhcpServerInDC' $PSBoundParameters; $script:M.InDC = @([pscustomobject]@{ DnsName = ($env:COMPUTERNAME + '.contoso.local'); IPAddress = [Net.IPAddress]'10.10.0.5' }) }
function Get-DhcpServerv4Scope { [CmdletBinding()] param([Parameter(Position = 0)][Net.IPAddress]$ScopeId, [string]$ComputerName, $CimSession) @($script:M.Scopes4 | Where-Object { -not $ScopeId -or $_.ScopeId.ToString() -eq $ScopeId.ToString() }) }
function Set-DhcpServerv4Scope { [CmdletBinding()] param([Parameter(Mandatory, Position = 1)][Net.IPAddress]$ScopeId, [ValidateSet('Active', 'InActive')][string]$State, [string]$Name, [switch]$PassThru, [string]$ComputerName)
    Rec 'Set-DhcpServerv4Scope' $PSBoundParameters }
function Get-DhcpServerv6Scope { [CmdletBinding()] param([Parameter(Position = 0)][Net.IPAddress]$Prefix) @($script:M.Scopes6) }
function Set-DhcpServerv6Scope { [CmdletBinding()] param([Parameter(Mandatory, Position = 1)][Net.IPAddress]$Prefix, [ValidateSet('Active', 'InActive')][string]$State, [switch]$PassThru)
    Rec 'Set-DhcpServerv6Scope' $PSBoundParameters }
function Get-DhcpServerv4OptionValue { [CmdletBinding()] param([string]$VendorClass, [string]$ComputerName, [Parameter(Position = 1)][Net.IPAddress]$ScopeId, [Net.IPAddress]$ReservedIP, [Parameter(Position = 0)][uint32[]]$OptionId, [string]$UserClass, [switch]$All, [switch]$Brief, [string]$PolicyName)
    if ($ScopeId) { @($script:M.Opt4[$ScopeId.ToString()]) } else { @($script:M.ServerOpt4) } }
function Get-DhcpServerv6OptionValue { [CmdletBinding()] param([string]$ComputerName, [string]$VendorClass, [Parameter(Position = 1)][Net.IPAddress]$Prefix, [Net.IPAddress]$ReservedIP, [string]$UserClass, [Parameter(Position = 0)][uint32[]]$OptionId, [switch]$All, [switch]$Brief)
    if ($Prefix) { @() } else { @($script:M.ServerOpt6) } }
function Get-DhcpServerv4Reservation { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][Net.IPAddress]$ScopeId, [string]$ComputerName) @($script:M.Res4[$ScopeId.ToString()]) }
function Get-DhcpServerv6Reservation { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][Net.IPAddress]$Prefix, [string]$ComputerName) @() }
function Get-DhcpServerv4ExclusionRange { [CmdletBinding()] param([Parameter(Position = 0)][Net.IPAddress]$ScopeId, [string]$ComputerName) @($script:M.Exc4[$ScopeId.ToString()]) }
function Get-DhcpServerv6ExclusionRange { [CmdletBinding()] param([Parameter(Position = 0)][Net.IPAddress]$Prefix, [string]$ComputerName) @() }
function Get-DhcpServerv4Lease { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][Net.IPAddress]$ScopeId, [string]$ComputerName, [switch]$AllLeases) 1..[int]$script:M.Leases4[$ScopeId.ToString()] | ForEach-Object { [pscustomobject]@{ IPAddress = [Net.IPAddress]'10.10.0.100' } } }
function Get-DhcpServerv6Lease { [CmdletBinding()] param([Parameter(Mandatory, Position = 0)][Net.IPAddress]$Prefix, [string]$ComputerName) @() }
function Get-DhcpServerv4Policy { [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, [Net.IPAddress]$ScopeId, [string]$ComputerName) @($script:M.Pol4[$(if ($ScopeId) { $ScopeId.ToString() } else { '' })]) }
function Get-DhcpServerv4Failover { [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Name, [Net.IPAddress[]]$ScopeId, [string]$ComputerName)
    @($script:M.Failover | Where-Object { -not $ScopeId -or (@($_.ScopeId | ForEach-Object { $_.ToString() }) -contains $ScopeId[0].ToString()) }) }
function Get-DhcpServerv4FilterList { [CmdletBinding()] param([string]$ComputerName) $script:M.FilterList }
function Get-DhcpServerv4Filter { [CmdletBinding()] param([string]$List, [string]$ComputerName) @($script:M.Filters) }
function Get-DhcpServerv4DnsSetting { [CmdletBinding()] param([Parameter(Position = 0)][Net.IPAddress]$ScopeId, [string]$ComputerName) $script:M.Dns }
function Get-DhcpServerv4Binding { [CmdletBinding()] param([string]$ComputerName) @($script:M.Bind) }
# Tauschordner
function Send-SmShareFile { param($Share, [string]$Path, [scriptblock]$Progress) $n = Split-Path -Leaf $Path; Copy-Item -LiteralPath $Path -Destination (Join-Path $store $n) -Force; [pscustomobject]@{ Name = $n; Length = (Get-Item -LiteralPath $Path).Length; Modified = (Get-Date) } }
function Receive-SmShareFile { param($Share, [string]$Name, [string]$OutFile) Copy-Item -LiteralPath (Join-Path $store $Name) -Destination $OutFile -Force }

function Rec([string]$Cmd, $Bound) { $h = @{}; foreach ($k in $Bound.Keys) { $h[$k] = $Bound[$k] }; $script:Calls.Add([pscustomobject]@{ Cmd = $Cmd; Args = $h }) }
function IP($s) { [Net.IPAddress]::Parse($s) }
function New-OldServer {
    $m = @{ Service = 'Running'; InDC = @([pscustomobject]@{ DnsName = ($env:COMPUTERNAME + '.contoso.local'); IPAddress = (IP '10.10.0.2') }); ImportWarning = $null }
    $m.Scopes4 = @(
        [pscustomobject]@{ ScopeId = (IP '10.10.0.0'); Name = 'Clients'; SubnetMask = (IP '255.255.255.0'); StartRange = (IP '10.10.0.100'); EndRange = (IP '10.10.0.200'); State = 'Active'; LeaseDuration = [timespan]::FromDays(8) }
        [pscustomobject]@{ ScopeId = (IP '10.20.0.0'); Name = 'Server'; SubnetMask = (IP '255.255.255.0'); StartRange = (IP '10.20.0.10'); EndRange = (IP '10.20.0.50'); State = 'Active'; LeaseDuration = [timespan]::FromDays(1) })
    $m.Scopes6 = @([pscustomobject]@{ Prefix = (IP 'fd00:10::'); Name = 'v6 Clients'; State = 'Active' })
    $o3 = [pscustomobject]@{ OptionId = 3; Name = 'Router'; Value = [string[]]@('10.10.0.1') }
    $o6 = [pscustomobject]@{ OptionId = 6; Name = 'DNS Servers'; Value = [string[]]@('10.10.0.10', '10.10.0.11') }
    $m.Opt4 = @{ '10.10.0.0' = @($o3, $o6); '10.20.0.0' = @([pscustomobject]@{ OptionId = 3; Name = 'Router'; Value = [string[]]@('10.20.0.1') }) }
    $m.ServerOpt4 = @([pscustomobject]@{ OptionId = 15; Name = 'DNS Domain Name'; Value = [string[]]@('contoso.local') })
    $m.ServerOpt6 = @([pscustomobject]@{ OptionId = 23; Name = 'DNS Recursive Name Server'; Value = [string[]]@('fd00:10::10') })
    $m.Res4 = @{ '10.10.0.0' = @([pscustomobject]@{ IPAddress = (IP '10.10.0.50'); ClientId = '00-11-22-33-44-55'; Name = 'drucker01.contoso.local' }, [pscustomobject]@{ IPAddress = (IP '10.10.0.51'); ClientId = '00-11-22-33-44-66'; Name = 'scanner01.contoso.local' }); '10.20.0.0' = @() }
    $m.Exc4 = @{ '10.10.0.0' = @([pscustomobject]@{ StartRange = (IP '10.10.0.1'); EndRange = (IP '10.10.0.20') }); '10.20.0.0' = @() }
    $m.Leases4 = @{ '10.10.0.0' = 42; '10.20.0.0' = 7 }
    $m.Pol4 = @{ '' = @([pscustomobject]@{ Name = 'Telefone'; Enabled = $true }); '10.10.0.0' = @(); '10.20.0.0' = @() }
    $m.Failover = @([pscustomobject]@{ Name = 'contoso-failover'; PartnerServer = 'dhcp2.contoso.local'; Mode = 'LoadBalance'; State = 'Normal'; ScopeId = [Net.IPAddress[]]@((IP '10.10.0.0')) })
    $m.FilterList = [pscustomobject]@{ Allow = $false; Deny = $true }
    $m.Filters = @([pscustomobject]@{ List = 'Deny'; MacAddress = 'AA-BB-CC-DD-EE-FF'; Description = 'gesperrt' })
    $m.Dns = [pscustomobject]@{ DynamicUpdates = 'OnClientRequest'; DeleteDnsRROnLeaseExpiry = $true; UpdateDnsRRForOlderClients = $false; DisableDnsPtrRRUpdate = $false; NameProtection = $false; DnsSuffix = 'contoso.local' }
    $m.Bind = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; IPAddress = (IP '10.10.0.2'); BindingState = $true })
    $m
}
function Reset-Calls { $script:Calls.Clear() }
function Calls([string]$Cmd) { , @($script:Calls | Where-Object Cmd -eq $Cmd) }
$script:M = New-OldServer

# ---------------------------------------------------------------- 1. Vorpruefungen
$pre = Test-SmDhcpPrecheck -Mode Export
Check 'Vorpruefung Export: bereit' ($pre.Ok -and $pre.Items.Count -eq 4)
$script:IsAdmin = $false
$pre = Test-SmDhcpPrecheck -Mode Import
Check 'Vorpruefung: kein Administrator blockiert' (-not $pre.Ok -and ($pre.Lines -join ' ') -match 'Administrator')
$script:IsAdmin = $true
$script:M.Service = $null
Check 'Vorpruefung: Dienst DHCPServer fehlt blockiert' (-not (Test-SmDhcpPrecheck -Mode Export).Ok)
$script:M.Service = 'Stopped'
Check 'Vorpruefung: Dienst gestoppt blockiert' (-not (Test-SmDhcpPrecheck -Mode Export).Ok)
$script:M.Service = 'Running'
$keep = ${function:Export-DhcpServer}
Remove-Item Function:\Export-DhcpServer
Check 'Vorpruefung: Modul DhcpServer fehlt blockiert (Export)' (-not (Test-SmDhcpPrecheck -Mode Export).Ok)
Check 'Vorpruefung: Modul fehlt, Import-Pruefung unberuehrt' ((Test-SmDhcpPrecheck -Mode Import).Ok)
Set-Item Function:\Export-DhcpServer $keep
$script:M.InDC = 'error'
$pre = Test-SmDhcpPrecheck -Mode Export
Check 'Vorpruefung: AD nicht lesbar ist nur ein Hinweis' ($pre.Ok -and ($pre.Lines -join ' ') -match 'nicht lesbar')
Check 'Vorpruefung Authorize: AD nicht lesbar blockiert' (-not (Test-SmDhcpPrecheck -Mode Authorize).Ok)
$script:M.InDC = @()
Check 'Autorisierung: noch nicht in der Liste' ((Get-SmDhcpAuthState) -eq $false -and (Test-SmDhcpPrecheck -Mode Authorize).Ok)
$script:M = New-OldServer
Check 'Autorisierung: Eintrag mit Servername erkannt, Authorize blockiert (schon autorisiert)' ((Get-SmDhcpAuthState) -eq $true -and -not (Test-SmDhcpPrecheck -Mode Authorize).Ok)

# ---------------------------------------------------------------- 2. Zusammenfassung und Export (alter Server)
$raw = Get-SmDhcpSummary
Check 'Zusammenfassung: Bereiche v4/v6, Failover, Filter' (@($raw.Scopes4).Count -eq 2 -and @($raw.Scopes6).Count -eq 1 -and @($raw.Failover).Count -eq 1 -and $raw.Filters.DenyEnabled -eq $true -and @($raw.Errors).Count -eq 0)
$jp = Join-Path $Work 'sum.json'
$sum = Write-SmDhcpSummaryFile -Summary $raw -Path $jp
$a = $sum.Scopes4 | Where-Object ScopeId -eq '10.10.0.0'
Check 'Zusammenfassung: Optionen, Reservierungen, Ausschluesse, Leases je Bereich' (@($a.Options).Count -eq 2 -and (@($a.Options | Where-Object Id -eq 6)[0].Value -eq '10.10.0.10,10.10.0.11') -and @($a.Reservations).Count -eq 2 -and @($a.Exclusions).Count -eq 1 -and $a.Leases -eq 42)
Check 'Zusammenfassung: Serveroptionen, Richtlinie, DNS-Update, Bindung, Failover-Bereiche' (@($sum.ServerOptions4).Count -eq 1 -and @($sum.Policies).Count -eq 1 -and @($sum.DnsUpdate).Count -ge 6 -and @($sum.Bindings).Count -eq 1 -and ($sum.Failover[0].Scopes -join ',') -eq '10.10.0.0')
Check 'Zusammenfassung: Dateiname-Art Export/Nachher' ((Get-SmDhcpFileKind 'DHCP-Export-DC01-20261122-101500.zip') -eq 'Export' -and (Get-SmDhcpFileKind 'DHCP-Nachher-DC02-20261122-111500.json') -eq 'Nachher' -and -not (Get-SmDhcpFileKind '..\DHCP-Export-x-20261122-101500.zip') -and -not (Get-SmDhcpFileKind 'evil.zip'))
# ein Abschnitt, der fehlschlaegt, bricht nichts ab
$keep6 = ${function:Get-DhcpServerv6Scope}
function Get-DhcpServerv6Scope { [CmdletBinding()] param() Write-Error 'IPv6 nicht eingerichtet' -ErrorAction Stop }
$rawE = Get-SmDhcpSummary
Check 'Zusammenfassung: fehlender IPv6-Teil wird vermerkt, Rest bleibt' (@($rawE.Scopes4).Count -eq 2 -and @($rawE.Errors).Count -eq 1 -and $rawE.Errors[0] -match 'v6')
Set-Item Function:\Get-DhcpServerv6Scope $keep6

Reset-Calls
$pub = Publish-SmDhcpExport -Share ([pscustomobject]@{}) -TempRoot $tmpRoot
$c = Calls 'Export-DhcpServer'
Check 'Export: Export-DhcpServer einmal mit -File und -Leases, ohne -Force' ($c.Count -eq 1 -and $c[0].Args.ContainsKey('File') -and $c[0].Args.Leases -eq $true -and -not $c[0].Args.ContainsKey('Force'))
$zipPath = Join-Path $store $pub.Name
$zipSha = (Get-FileHash $zipPath -Algorithm SHA256).Hash
Check 'Export: SHA256 stimmt mit der hochgeladenen Datei' ($pub.Sha256 -eq $zipSha)
Check 'Export: Name nach Schema' ((Get-SmDhcpFileKind $pub.Name) -eq 'Export')
$ents = @([IO.Compression.ZipFile]::OpenRead($zipPath).Entries | ForEach-Object FullName)
Check 'Export: ZIP enthaelt genau XML und Zusammenfassung' ($ents.Count -eq 2 -and $ents -contains 'dhcp-export.xml' -and $ents -contains 'dhcp-summary.json')
Check 'Export: Zusammenfassung aus dem ZIP lesbar und gueltig' ((Read-SmDhcpSummaryFile -Path $zipPath).Scopes4.Count -eq 2)
Check 'Export: Temp-Ordner aufgeraeumt' (@(Get-ChildItem -LiteralPath $tmpRoot).Count -eq 0)
$audit = Get-Content -LiteralPath $script:SmDhcpAuditPath -Raw
Check 'Export: Protokollzeile ohne Adresse/Link' ($audit -match 'DHCP Export:' -and $audit -notmatch 'https?://')
$script:IsAdmin = $false; Reset-Calls
Check 'Export: ohne Vorpruefung kein Export-DhcpServer' ((Throws { Publish-SmDhcpExport -Share ([pscustomobject]@{}) -TempRoot $tmpRoot }) -and (Calls 'Export-DhcpServer').Count -eq 0)
$script:IsAdmin = $true

# ---------------------------------------------------------------- 3. Neuer Server: Download, Pruefung, Import
$newSrv = $null
$remote = [pscustomobject]@{ Name = $pub.Name; Length = $pub.Length }
$down = Receive-SmDhcpExport -Share ([pscustomobject]@{}) -Remote $remote -TempRoot $tmpRoot
Check 'Download: SHA256 wird angezeigt und stimmt' ($down.Sha256 -eq $zipSha -and (Test-Path -LiteralPath $down.ZipPath))
Check 'Download: noch nichts entpackt' (-not (Test-Path -LiteralPath (Join-Path $down.Dir 'dhcp-export.xml')))
$op = Open-SmDhcpExport -ZipPath $down.ZipPath -Dir $down.Dir
Check 'Oeffnen: XML entpackt und geprueft, Zusammenfassung gelesen' ((Test-Path -LiteralPath $op.XmlPath) -and $op.Summary.Scopes4.Count -eq 2)
$script:M = @{ Service = 'Running'; InDC = @(); Scopes4 = @(); Scopes6 = @(); ImportWarning = $null }   # leerer neuer Server
$plan = Get-SmDhcpImportPlan -Summary $op.Summary -All
Check 'Plan: leerer Zielserver, alles, Failover-Hinweis' ($plan.Ok -and $plan.TargetEmpty -and $plan.Selected4.Count -eq 2 -and $plan.Selected6.Count -eq 1 -and $plan.FailoverNote -match 'contoso-failover' -and $plan.FailoverNote -match 'Add-DhcpServerv4Failover')
$planSel = Get-SmDhcpImportPlan -Summary $op.Summary -ScopeIds @('10.10.0.0')
Check 'Plan: einzelner Bereich' ($planSel.Selected4.Count -eq 1 -and $planSel.Selected6.Count -eq 0 -and -not $planSel.All)
Check 'Plan: unbekannter Bereich abgelehnt' (Throws { Get-SmDhcpImportPlan -Summary $op.Summary -ScopeIds @('10.99.0.0') })
$script:M.Scopes4 = @([pscustomobject]@{ ScopeId = (IP '10.10.0.0'); Name = 'Alt'; SubnetMask = (IP '255.255.255.0'); StartRange = (IP '10.10.0.1'); EndRange = (IP '10.10.0.9'); State = 'Active'; LeaseDuration = [timespan]::FromDays(1) })
$plan2 = Get-SmDhcpImportPlan -Summary $op.Summary -All
Check 'Plan: gleicher Bereich schon da wird gemeldet, nicht blockiert' ($plan2.Ok -and ($plan2.Existing4 -contains '10.10.0.0') -and -not $plan2.TargetEmpty -and ($plan2.Warnings -join ' ') -match 'ausdruecklicher Bestaetigung')
$script:M.Scopes4 = @([pscustomobject]@{ ScopeId = (IP '10.0.0.0'); Name = 'Gross'; SubnetMask = (IP '255.0.0.0'); StartRange = (IP '10.0.0.1'); EndRange = (IP '10.0.0.9'); State = 'Active'; LeaseDuration = [timespan]::FromDays(1) })
$plan3 = Get-SmDhcpImportPlan -Summary $op.Summary -All
Check 'Plan: ueberlappender Bereich (10.0.0.0/8) blockiert' (-not $plan3.Ok -and $plan3.Blocking.Count -eq 2 -and $plan3.Blocking[0] -match '10\.0\.0\.0')
Check 'Ueberlappung: Netze 10.10.0.0/24 und 10.10.1.0/24 getrennt, 10.10.0.0/16 und 10.10.1.0/24 ueberlappen' (-not (Test-SmDhcpSubnetOverlap '10.10.0.0' '255.255.255.0' '10.10.1.0' '255.255.255.0') -and (Test-SmDhcpSubnetOverlap '10.10.0.0' '255.255.0.0' '10.10.1.0' '255.255.255.0'))
Reset-Calls
Check 'Import: blockierender Plan wird nicht ausgefuehrt' ((Throws { Invoke-SmDhcpImport -Opened $op -Plan $plan3 -BackupRoot (Join-Path $Work 'bk0') }) -and (Calls 'Import-DhcpServer').Count -eq 0)
$script:M = @{ Service = 'Running'; InDC = @(); Scopes4 = @(); Scopes6 = @(); ImportWarning = 'Bereich 10.10.0.0 uebersprungen (Testwarnung)' }
$bk = Join-Path $Work 'bk1'
$res = Invoke-SmDhcpImport -Opened $op -Plan $plan -Leases -BackupRoot $bk
$ic = Calls 'Import-DhcpServer'
Check 'Import alles: -File, -BackupPath, -Leases, -Force; kein -ScopeId/-ScopeOverwrite/-ServerConfigOnly' ($ic.Count -eq 1 -and $ic[0].Args.File -eq $op.XmlPath -and $ic[0].Args.BackupPath -eq $bk -and $ic[0].Args.Leases -eq $true -and $ic[0].Args.Force -eq $true -and -not $ic[0].Args.ContainsKey('ScopeId') -and -not $ic[0].Args.ContainsKey('ScopeOverwrite') -and -not $ic[0].Args.ContainsKey('ServerConfigOnly'))
Check 'Import: Sicherungsordner angelegt, Warnung weitergereicht, Failover-Hinweis' ((Test-Path -LiteralPath $bk) -and $res.Warnings.Count -eq 1 -and $res.Warnings[0] -match 'Testwarnung' -and $res.FailoverNote -match 'Failover')
$audit = Get-Content -LiteralPath $script:SmDhcpAuditPath -Raw
Check 'Import: Protokollzeilen gestartet und beendet' ($audit -match 'DHCP Import gestartet' -and $audit -match 'DHCP Import beendet')
Reset-Calls
[void](Invoke-SmDhcpImport -Opened $op -Plan $planSel -BackupRoot (Join-Path $Work 'bk2'))
$ic = Calls 'Import-DhcpServer'
Check 'Import einzelner Bereich: -ScopeId 10.10.0.0, ohne -Leases' ($ic[0].Args.ScopeId.Count -eq 1 -and $ic[0].Args.ScopeId[0].ToString() -eq '10.10.0.0' -and -not $ic[0].Args.ContainsKey('Leases') -and -not $ic[0].Args.ContainsKey('Prefix'))
Reset-Calls
[void](Invoke-SmDhcpImport -Opened $op -Plan $plan2 -Leases -ScopeOverwrite -BackupRoot (Join-Path $Work 'bk3'))
Check 'Import mit ausdruecklichem Ueberschreiben: -ScopeOverwrite' ((Calls 'Import-DhcpServer')[0].Args.ScopeOverwrite -eq $true)
Reset-Calls
[void](Invoke-SmDhcpImport -Opened $op -Plan $plan -ServerConfigOnly -Leases -BackupRoot (Join-Path $Work 'bk4'))
$ic = Calls 'Import-DhcpServer'
Check 'Import nur Serverkonfiguration: -ServerConfigOnly, ohne -Leases/-ScopeOverwrite' ($ic[0].Args.ServerConfigOnly -eq $true -and -not $ic[0].Args.ContainsKey('Leases') -and -not $ic[0].Args.ContainsKey('ScopeOverwrite'))
Reset-Calls; $script:IsAdmin = $false
Check 'Import: ohne Administrator keine Aenderung' ((Throws { Invoke-SmDhcpImport -Opened $op -Plan $plan -BackupRoot (Join-Path $Work 'bk5') }) -and (Calls 'Import-DhcpServer').Count -eq 0)
$script:IsAdmin = $true

# Autorisierung (neuer Server)
Reset-Calls
$st = Invoke-SmDhcpAuthorize
Check 'Autorisierung: Add-DhcpServerInDC einmal, Server danach in der Liste' ((Calls 'Add-DhcpServerInDC').Count -eq 1 -and $st -eq $true)
Check 'Autorisierung: Protokollzeilen' ((Get-Content -LiteralPath $script:SmDhcpAuditPath -Raw) -match 'DHCP Autorisierung gestartet')
Reset-Calls
Check 'Autorisierung: schon autorisiert, nichts getan' ((Throws { Invoke-SmDhcpAuthorize }) -and (Calls 'Add-DhcpServerInDC').Count -eq 0)

# ---------------------------------------------------------------- 4. Alter Server: Bereiche deaktivieren
$script:M = New-OldServer; Reset-Calls
$dp = Get-SmDhcpDeactivatePlan -ScopeIds @('10.10.0.0', '10.20.0.0') -Prefixes @('fd00:10::')
Check 'Deaktivieren: Plan meldet Failover-Bereich 10.10.0.0' ($dp.Ok -and $dp.Warnings.Count -eq 1 -and $dp.Warnings[0] -match '10\.10\.0\.0' -and $dp.Warnings[0] -match 'contoso-failover')
Check 'Deaktivieren: unbekannter Bereich' (-not (Get-SmDhcpDeactivatePlan -ScopeIds @('10.99.0.0')).Ok -and -not (Get-SmDhcpDeactivatePlan).Ok)
Check 'Deaktivieren: ohne Auswahl keine Aenderung' ((Throws { Invoke-SmDhcpDeactivate }) -and $script:Calls.Count -eq 0)
$n = Invoke-SmDhcpDeactivate -ScopeIds @('10.20.0.0') -Prefixes @('fd00:10::')
$s4c = Calls 'Set-DhcpServerv4Scope'; $s6c = Calls 'Set-DhcpServerv6Scope'
Check 'Deaktivieren: nur gewaehlte Bereiche, -State InActive' ($n -eq 2 -and $s4c.Count -eq 1 -and $s4c[0].Args.ScopeId.ToString() -eq '10.20.0.0' -and $s4c[0].Args.State -eq 'InActive' -and $s6c.Count -eq 1 -and $s6c[0].Args.State -eq 'InActive')
Check 'Deaktivieren: Protokollzeilen je Bereich' (@((Get-Content -LiteralPath $script:SmDhcpAuditPath) | Where-Object { $_ -match 'DHCP Bereich deaktiviert' }).Count -eq 2)
Check 'Bereichsliste fuer die Auswahl' ((Get-SmDhcpLocalScopes).Count -eq 3)
Reset-Calls; $script:IsAdmin = $false
Check 'Deaktivieren: ohne Administrator keine Aenderung' ((Throws { Invoke-SmDhcpDeactivate -ScopeIds @('10.20.0.0') }) -and $script:Calls.Count -eq 0)
$script:IsAdmin = $true

# ---------------------------------------------------------------- 5. Vergleichslogik
$before = $sum
$after = Read-SmDhcpSummaryFile -Path $jp   # frische Kopie als Ausgangspunkt
$rows = Compare-SmDhcpSummary -Before $before -After $after
Check 'Vergleich: identische Staende ohne Unterschiede' ($rows.Count -eq 0)
$all = Compare-SmDhcpSummary -Before $before -After $after -IncludeEqual
Check 'Vergleich: mit -IncludeEqual alles als gleich' ($all.Count -gt 20 -and -not (@($all | Where-Object Ergebnis -ne 'gleich').Count))
# Nachher: Reservierung fehlt, Option geaendert, Ausschluss neu, Bereich 10.20 fehlt, neuer Bereich 10.30, Failover fehlt, Leases weniger, v6 fehlt
$m = ConvertTo-Json -InputObject $before -Depth 10 | ConvertFrom-Json
$m.Scopes4[0].Reservations = @($m.Scopes4[0].Reservations | Where-Object Ip -ne '10.10.0.51')
$m.Scopes4[0].Options[1].Value = '10.10.0.10'
$m.Scopes4[0].Exclusions = @($m.Scopes4[0].Exclusions) + [pscustomobject]@{ Start = '10.10.0.90'; End = '10.10.0.99' }
$m.Scopes4[0].Leases = 40
$m.Scopes4 = @($m.Scopes4[0], [pscustomobject]@{ ScopeId = '10.30.0.0'; Name = 'Neu'; Mask = '255.255.255.0'; Start = '10.30.0.10'; End = '10.30.0.20'; State = 'Active'; LeaseDuration = '1.00:00:00'; Leases = 0; Options = @(); Reservations = @(); Exclusions = @(); Policies = @() })
$m.Scopes6 = @()
$m.Failover = @()
$m.Authorized = $false
$aft = ConvertTo-SmDhcpSummary $m
$d = Compare-SmDhcpSummary -Before $before -After $aft
function Has($area, $cat, $el, $res) { @($d | Where-Object { $_.Bereich -like $area -and $_.Kategorie -eq $cat -and $_.Element -like $el -and $_.Ergebnis -eq $res }).Count -eq 1 }
Check 'Vergleich: Reservierung fehlt nachher' (Has 'Bereich 10.10.0.0' 'Reservierung' '10.10.0.51' 'fehlt nachher')
Check 'Vergleich: Option geaendert (anders)' (Has 'Bereich 10.10.0.0' 'Option' 'Option 6*' 'anders')
Check 'Vergleich: Ausschluss neu nachher' (Has 'Bereich 10.10.0.0' 'Ausschluss' '10.10.0.90-10.10.0.99' 'neu nachher')
Check 'Vergleich: Lease-Anzahl anders, mit Hinweis' ((Has 'Bereich 10.10.0.0' 'Leases' 'Anzahl' 'anders') -and (@($d | Where-Object { $_.Kategorie -eq 'Leases' })[0].Hinweis -match 'laufend'))
Check 'Vergleich: Bereich 10.20.0.0 fehlt nachher' (Has 'Bereich 10.20.0.0' 'Bereich' '*' 'fehlt nachher')
Check 'Vergleich: Bereich 10.30.0.0 neu nachher' (Has 'Bereich 10.30.0.0' 'Bereich' '*' 'neu nachher')
Check 'Vergleich: v6-Bereich fehlt nachher' (Has 'Bereich fd00:10::' 'Bereich' '*' 'fehlt nachher')
Check 'Vergleich: Failover fehlt nachher, Hinweis auf manuelle Anlage' ((Has 'Server' 'Failover' 'contoso-failover' 'fehlt nachher') -and (@($d | Where-Object { $_.Kategorie -eq 'Failover' })[0].Hinweis -match 'Add-DhcpServerv4Failover'))
Check 'Vergleich: Autorisierung vorher/nachher als Unterschied' (Has 'Server' 'Autorisierung' '*' 'anders')
Check 'Vergleich: unveraenderte Teile erscheinen nicht' (-not (@($d | Where-Object { $_.Bereich -eq 'Server' -and $_.Kategorie -eq 'Option' }).Count) -and -not (@($d | Where-Object { $_.Element -eq '10.10.0.50' }).Count))
Check 'Vergleich: Zeilen haben die Spalten fuer Export-SmTable' ((($d[0].PSObject.Properties.Name) -join ',') -eq 'Bereich,Kategorie,Element,Vorher,Nachher,Ergebnis,Hinweis')
Check 'Vergleich: Zusammenfassungstext zaehlt' ((Get-SmDhcpDiffText $d) -match '^\d+ Unterschiede: \d+ fehlen nachher, \d+ neu nachher, \d+ anders')
function Export-SmTable { param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string]$Path) $script:Exported = @{ Rows = $Rows; Path = $Path } }   # Vertrag der Phase 3
Export-SmTable -Rows $d -Path (Join-Path $Work 'diff.xlsx')
Check 'Export-SmTable-Vertrag: Zeilen und Pfad (gemockt)' ($script:Exported.Rows.Count -eq $d.Count -and $script:Exported.Path -like '*.xlsx')

# ---------------------------------------------------------------- 6. Feindliche Daten
function J($o) { ConvertTo-Json -InputObject $o -Depth 12 }
function Parse([string]$Json) { ConvertTo-SmDhcpSummary (ConvertFrom-Json -InputObject $Json) }
$minimal = [ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Server = 'DC01' }
Check 'JSON: Minimalform gueltig' ((Parse (J $minimal)).Scopes4.Count -eq 0)
Check 'JSON: falsches Format abgelehnt' ((Throws { Parse (J ([ordered]@{ Format = 'Anderes'; Version = 1 })) }) -and (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 2 })) }) -and (Throws { Parse '[1,2,3]' }) -and (Throws { Parse '"text"' }))
$bad = [ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes4 = @([ordered]@{ ScopeId = '10.0.0.0; calc.exe' }) }
Check 'JSON: Befehl statt Bereichs-ID abgelehnt' (Throws { Parse (J $bad) })
foreach ($v in '10.0.0', '999.1.1.1', '$(calc)', '10.0.0.0/24', 'fd00::1') { Check "JSON: ungueltige Bereichs-ID '$v' abgelehnt" (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes4 = @([ordered]@{ ScopeId = $v }) })) }) }
Check 'JSON: ungueltige Subnetzmaske, Optionsnummer, Failover-Bereich, Praefix abgelehnt' ((Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes4 = @([ordered]@{ ScopeId = '10.0.0.0'; Mask = 'x' }) })) }) -and (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; ServerOptions4 = @([ordered]@{ Id = 'abc' }) })) }) -and (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Failover = @([ordered]@{ Name = 'f'; Scopes = @('nicht-ip') }) })) }) -and (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes6 = @([ordered]@{ Prefix = '10.0.0.0' }) })) }))
$ctl = Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Server = ("DC01`r`n=cmd|calc"); Evil = 'unbekannt'; Scopes4 = @([ordered]@{ ScopeId = '10.0.0.0'; Name = ("a" + [char]7 + "b"); Hack = @{ x = 1 } }) }))
Check 'JSON: Steuerzeichen entfernt, unbekannte Felder verworfen' ($ctl.Server -notmatch "[\r\n]" -and $ctl.Scopes4[0].Name -eq 'a b' -and -not $ctl.Contains('Evil') -and -not $ctl.Scopes4[0].Contains('Hack'))
$long = Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Server = ('x' * 5000) }))
Check 'JSON: Zeichenketten auf 255 Zeichen begrenzt' ($long.Server.Length -eq 255)
$deep = ('[' * 5000) + (']' * 5000)
Check 'JSON: Verschachtelungstiefe 5000 vor dem Parsen abgelehnt' (-not (Test-SmDhcpJsonDepth $deep) -and (Test-SmDhcpJsonDepth '{"a":[1,{"b":"[[["}]}'))
$deepFile = Join-Path $Work 'deep.json'; [IO.File]::WriteAllText($deepFile, ('{"a":' * 3000) + '1' + ('}' * 3000))
Check 'JSON-Datei: zu tief verschachtelt abgelehnt' (ThrowsLike { Read-SmDhcpSummaryFile -Path $deepFile } 'tief')
$notJson = Join-Path $Work 'nojson.json'; [IO.File]::WriteAllText($notJson, '{kaputt')
Check 'JSON-Datei: kein JSON abgelehnt' (Throws { Read-SmDhcpSummaryFile -Path $notJson })
$oldMax = $script:SmDhcpMaxJsonBytes; $script:SmDhcpMaxJsonBytes = 1KB
Check 'JSON-Datei: Groessenlimit (Datei)' (ThrowsLike { Read-SmDhcpSummaryFile -Path $jp } 'gr')
Check 'JSON-Datei: Groessenlimit (Eintrag im ZIP)' (ThrowsLike { Read-SmDhcpSummaryFile -Path $zipPath } 'gr')
$script:SmDhcpMaxJsonBytes = $oldMax
Check 'Strom: ueber das Limit hinaus gelesen wird abgelehnt (auch bei falscher Groessenangabe)' ((Throws { Read-SmBoundedStream -Stream (New-Object IO.MemoryStream (, (New-Object byte[] 2048))) -Max 1024 }) -and ((Read-SmBoundedStream -Stream (New-Object IO.MemoryStream (, (New-Object byte[] 512))) -Max 1024)).Count -eq 512)
$oldMaxS = $script:SmDhcpMaxScopes; $script:SmDhcpMaxScopes = 2
Check 'JSON: zu viele Bereiche abgelehnt' (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes4 = @(1..3 | ForEach-Object { [ordered]@{ ScopeId = "10.$_.0.0" } }) })) })
$script:SmDhcpMaxScopes = $oldMaxS
$oldItems = $script:SmDhcpMaxItems; $script:SmDhcpMaxItems = 5
Check 'JSON: zu viele Eintraege insgesamt abgelehnt' (Throws { Parse (J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Scopes4 = @([ordered]@{ ScopeId = '10.0.0.0'; Reservations = @(1..10 | ForEach-Object { [ordered]@{ Ip = "10.0.0.$_" } }) }) })) })
$script:SmDhcpMaxItems = $oldItems

# XML: kein DTD, kein XXE
function XmlFile([string]$Text) { $p = Join-Path $Work ('x-' + [guid]::NewGuid().ToString('N') + '.xml'); [IO.File]::WriteAllText($p, $Text); $p }
Check 'XML: gueltig, Wurzelelement geliefert' ((Test-SmDhcpXmlSafe -Path (XmlFile '<?xml version="1.0"?><DHCPServer><IPv4/></DHCPServer>')) -eq 'DHCPServer')
Check 'XML: DOCTYPE mit externer Entity (XXE) abgelehnt' (ThrowsLike { Test-SmDhcpXmlSafe -Path (XmlFile '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><DHCPServer>&x;</DHCPServer>') } 'DTD|ungueltig')
Check 'XML: Entity-Explosion (Billion Laughs) abgelehnt' (Throws { Test-SmDhcpXmlSafe -Path (XmlFile '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><DHCPServer>&c;</DHCPServer>') })
Check 'XML: leeres DOCTYPE ohne Entity ebenfalls abgelehnt' (Throws { Test-SmDhcpXmlSafe -Path (XmlFile '<!DOCTYPE DHCPServer><DHCPServer/>') })
Check 'XML: kaputt und leer abgelehnt' ((Throws { Test-SmDhcpXmlSafe -Path (XmlFile '<DHCPServer><unzu>') }) -and (Throws { Test-SmDhcpXmlSafe -Path (XmlFile '') }))
$oldX = $script:SmDhcpMaxXmlBytes; $script:SmDhcpMaxXmlBytes = 10
Check 'XML: Groessenlimit' (ThrowsLike { Test-SmDhcpXmlSafe -Path (XmlFile '<DHCPServer><IPv4/></DHCPServer>') } 'gr')
$script:SmDhcpMaxXmlBytes = $oldX

# ZIP und Dateinamen
function MakeZip([string]$Path, [hashtable]$Entries) {
    $z = [IO.Compression.ZipFile]::Open($Path, 'Create')
    try { foreach ($k in $Entries.Keys) { $e = $z.CreateEntry($k); $s = $e.Open(); $b = [Text.Encoding]::UTF8.GetBytes($Entries[$k]); $s.Write($b, 0, $b.Length); $s.Dispose() } } finally { $z.Dispose() }
}
$goodXml = '<?xml version="1.0"?><DHCPServer/>'
$goodJson = J ([ordered]@{ Format = 'SmDhcpSummary'; Version = 1; Server = 'DC01' })
$zOk = Join-Path $Work 'z-ok.zip'; MakeZip $zOk @{ 'dhcp-export.xml' = $goodXml; 'dhcp-summary.json' = $goodJson }
$dOk = Join-Path $Work 'z-ok'; New-Item -ItemType Directory $dOk | Out-Null
Check 'ZIP: gueltiges Paket wird geoeffnet' ((Open-SmDhcpExport -ZipPath $zOk -Dir $dOk).Summary.Server -eq 'DC01')
$zExtra = Join-Path $Work 'z-extra.zip'; MakeZip $zExtra @{ 'dhcp-export.xml' = $goodXml; 'dhcp-summary.json' = $goodJson; 'evil.ps1' = 'calc' }
$dX = Join-Path $Work 'z-extra'; New-Item -ItemType Directory $dX | Out-Null
Check 'ZIP: zusaetzlicher Eintrag abgelehnt, nichts entpackt' ((Throws { Open-SmDhcpExport -ZipPath $zExtra -Dir $dX }) -and @(Get-ChildItem -LiteralPath $dX).Count -eq 0)
$zSlip = Join-Path $Work 'z-slip.zip'; MakeZip $zSlip @{ '..\..\evil.xml' = $goodXml; 'dhcp-summary.json' = $goodJson }
$dS = Join-Path $Work 'z-slip'; New-Item -ItemType Directory $dS | Out-Null
Check 'ZIP: Pfad mit .. (Zip-Slip) abgelehnt, nichts ausserhalb geschrieben' ((Throws { Open-SmDhcpExport -ZipPath $zSlip -Dir $dS }) -and -not (Test-Path (Join-Path $Work 'evil.xml')) -and -not (Test-Path (Join-Path (Split-Path $Work -Parent) 'evil.xml')))
$zNoSum = Join-Path $Work 'z-nosum.zip'; MakeZip $zNoSum @{ 'dhcp-export.xml' = $goodXml }
Check 'ZIP: ohne Zusammenfassung abgelehnt' (Throws { Read-SmDhcpSummaryFile -Path $zNoSum })
$zDtd = Join-Path $Work 'z-dtd.zip'; MakeZip $zDtd @{ 'dhcp-export.xml' = '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><DHCPServer>&x;</DHCPServer>'; 'dhcp-summary.json' = $goodJson }
$dD = Join-Path $Work 'z-dtd'; New-Item -ItemType Directory $dD | Out-Null
Reset-Calls
Check 'ZIP: Export-XML mit DTD wird vor dem Import abgelehnt' ((Throws { Open-SmDhcpExport -ZipPath $zDtd -Dir $dD }) -and (Calls 'Import-DhcpServer').Count -eq 0)
Check 'Download: Dateiname ausserhalb der Whitelist abgelehnt' ((Throws { Receive-SmDhcpExport -Share ([pscustomobject]@{}) -Remote ([pscustomobject]@{ Name = '..\..\evil.zip'; Length = 10 }) -TempRoot $tmpRoot }) -and (Throws { Receive-SmDhcpExport -Share ([pscustomobject]@{}) -Remote ([pscustomobject]@{ Name = 'DHCP-Nachher-DC01-20261122-101500.json'; Length = 10 }) -TempRoot $tmpRoot }))
Check 'Download: zu grosses ZIP abgelehnt' (Throws { Receive-SmDhcpExport -Share ([pscustomobject]@{}) -Remote ([pscustomobject]@{ Name = 'DHCP-Export-DC01-20261122-101500.zip'; Length = 600MB }) -TempRoot $tmpRoot })
Check 'Download: abweichende Groesse abgelehnt, Temp aufgeraeumt' ((Throws { Receive-SmDhcpExport -Share ([pscustomobject]@{}) -Remote ([pscustomobject]@{ Name = $pub.Name; Length = ($pub.Length + 5) }) -TempRoot $tmpRoot }) -and @(Get-ChildItem -LiteralPath $tmpRoot -Directory | Where-Object { $_.FullName -ne $down.Dir }).Count -eq 0)
Remove-SmDhcpTemp -Dir $down.Dir -TempRoot $tmpRoot
Check 'Aufraeumen: nur eigene Ordner (Ordner ausserhalb bleibt)' (-not (Test-Path $down.Dir))
$foreign = Join-Path $Work 'fremd'; New-Item -ItemType Directory $foreign | Out-Null
Remove-SmDhcpTemp -Dir $foreign -TempRoot $tmpRoot
Check 'Aufraeumen: fremder Ordner wird nicht geloescht' (Test-Path $foreign)
$hits = @(Select-String -Path (Join-Path $Repo 'Modules\SmDhcp.ps1'), (Join-Path $Repo 'server\SmDhcpServer.ps1') -Pattern 'Import-Clixml', 'ConvertFrom-CliXml', 'Invoke-Expression')
Check 'Keine Deserialisierung und kein Invoke-Expression in den DHCP-Dateien' ($hits.Count -eq 0)

# optional: Parameternamen gegen das echte Modul DhcpServer, wenn es hier installiert ist
if (Get-Module -ListAvailable -Name DhcpServer) {
    foreach ($spec in @(@('Export-DhcpServer', 'File', 'Leases', 'Force'), @('Import-DhcpServer', 'File', 'BackupPath', 'Leases', 'ScopeId', 'Prefix', 'ScopeOverwrite', 'ServerConfigOnly', 'Force'), @('Set-DhcpServerv4Scope', 'ScopeId', 'State'), @('Set-DhcpServerv6Scope', 'Prefix', 'State'), @('Add-DhcpServerInDC'), @('Get-DhcpServerv4Lease', 'ScopeId', 'AllLeases'))) {
        $cmd = (Get-Command $spec[0] -Module DhcpServer); $miss = @($spec[1..($spec.Count - 1)] | Where-Object { $_ -and -not $cmd.Parameters.ContainsKey($_) })
        Check ("Echtes Modul DhcpServer: $($spec[0]) hat die benutzten Parameter") ($miss.Count -eq 0)
    }
}
else { Write-Host 'INFO Modul DhcpServer nicht installiert: Parameternamen nur gegen die Doku-Stubs geprueft' -ForegroundColor Yellow }

# ---------------------------------------------------------------- 7. Fenster mit Seite DHCP (-ParseOnly)
foreach ($entry in @(@('Berater-Tool', 'Start-ServerMigration.ps1'), @('Server-Fenster', 'server\Start-SmServer.ps1'))) {
    $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $Repo $entry[1]) -ParseOnly -Theme Dark 2>&1 | Out-String
    Check ("$($entry[0]) mit Seite DHCP -ParseOnly (Dark): $($out.Trim())") ($out.Trim() -eq 'PARSE OK')
}
$xamlNames = @(Get-SmXamlNames ([IO.File]::ReadAllText((Join-Path $Repo 'UI\DhcpServer.xaml'), [Text.Encoding]::UTF8)))
Check 'Server-Seite: Namen im XAML vorhanden' (@(@('BtnDhcpExport', 'BtnDhcpImport', 'BtnDhcpAuth', 'BtnDhcpDeactivate', 'BtnDhcpAfter') | Where-Object { $xamlNames -notcontains $_ }).Count -eq 0)

Write-Host ''
Write-Host "$fails Fehler in tests\Test-Dhcp.ps1"
$fails
