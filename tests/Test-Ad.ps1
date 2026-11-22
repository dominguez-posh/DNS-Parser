#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 6 (Active Directory): Zuordnungen (Schema-Version, Ebenen, Betriebssystem), Logik der Ebenenpruefung
    (ein DC mit 2016 blockiert 2025), Bericht lesen (feindliche Dateien), AD-Cmdlets gemockt mit Parameterlisten laut Microsoft-Doku,
    Stub-Programme fuer repadmin, dcdiag, ntdsutil und adprep, FSMO uebertragen und Seize (nur bei unerreichbarem Inhaber),
    DSRM-Kennwort (nur ueber die Standardeingabe, Gegentest auf Kommandozeile, Protokoll, Dateien und Temp), Ebenen anheben mit
    doppelter Bestaetigung, adprep, Protokoll (Schreibfehler sichtbar, gehaerteter Ordner), -ParseOnly beider Fenster.
    Keine echte Domaene, keine echten Programme, nur Beispieldaten (contoso.local).
    Mit Windows PowerShell 5.1: powershell.exe -NoProfile -STA -File tests\Test-Ad.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$startTime = Get-Date
$work = Join-Path $env:TEMP ('sm-ad-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter 'sm-ad-test-*' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-2) } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }   # nur alte Reste (>2 h); Ordner paralleler Laeufe anderer Worktrees bleiben unberuehrt
New-Item -ItemType Directory -Force $work | Out-Null
$script:fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }
function ThrowsLike([scriptblock]$Block, [string]$Pattern) { try { & $Block | Out-Null; $false } catch { $_.Exception.Message -match $Pattern } }

. (Join-Path $repo 'Modules\SmTausch.ps1')
. (Join-Path $repo 'Modules\SmExport.ps1')
. (Join-Path $repo 'Modules\SmAd.ps1')
. (Join-Path $repo 'server\SmDnsServer.ps1')
. (Join-Path $repo 'server\SmAdServer.ps1')

# ---------------------------------------------------------------- 1. Zuordnungen
Check 'Schema 91 = Windows Server 2025' ((Get-SmAdSchemaName 91) -eq 'Windows Server 2025')
Check 'Schema 88 = 2019 / 2022, 87 = 2016, 69 = 2012 R2, 30 = 2003' ((Get-SmAdSchemaName 88) -match '2019' -and (Get-SmAdSchemaName 87) -match '2016' -and (Get-SmAdSchemaName 69) -match '2012 R2' -and (Get-SmAdSchemaName 30) -match '2003')
Check 'Schema: unbekannte Version wird benannt, nicht geraten' ((Get-SmAdSchemaName 92) -match 'neuer' -and (Get-SmAdSchemaName 75) -match 'unbekannt')
Check 'Ebene: Namen und Zahlen (Windows2016Domain, WinThreshold, Windows2025Forest, 4)' ((ConvertTo-SmAdLevelNumber 'Windows2016Domain') -eq 7 -and (ConvertTo-SmAdLevelNumber 'WinThreshold') -eq 7 -and (ConvertTo-SmAdLevelNumber 'Windows2025Forest') -eq 10 -and (ConvertTo-SmAdLevelNumber 4) -eq 4 -and (ConvertTo-SmAdLevelNumber 'Windows2008R2Domain') -eq 4 -and (ConvertTo-SmAdLevelNumber 'Windows2012R2Forest') -eq 6 -and $null -eq (ConvertTo-SmAdLevelNumber 'Quatsch'))
Check 'Ebene: Wert fuer -DomainMode / -ForestMode laut Doku' ((Get-SmAdModeParameter -Scope Domain -Level 10) -eq 'Windows2025Domain' -and (Get-SmAdModeParameter -Scope Forest -Level 7) -eq 'Windows2016Forest' -and (Get-SmAdModeParameter -Scope Domain -Level 4) -eq 'Windows2008R2Domain' -and (Get-SmAdModeParameter -Scope Forest -Level 6) -eq 'Windows2012R2Forest')
Check 'Ebene: nicht vorgesehene Zielebene abgelehnt' (Throws { Get-SmAdModeParameter -Scope Forest -Level 2 })
Check 'Betriebssystem: 2016/2019/2022 = 7, 2025 = 10, 2012 R2 = 6, unbekannt = null' ((ConvertTo-SmAdOsRank 'Windows Server 2016 Datacenter') -eq 7 -and (ConvertTo-SmAdOsRank 'Windows Server 2022 Standard') -eq 7 -and (ConvertTo-SmAdOsRank 'Windows Server 2025 Datacenter') -eq 10 -and (ConvertTo-SmAdOsRank 'Windows Server 2012 R2 Standard') -eq 6 -and (ConvertTo-SmAdOsRank 'Windows Server 2008 R2 Enterprise') -eq 4 -and $null -eq (ConvertTo-SmAdOsRank 'Linux'))
Check 'adprep-Version: Build 26100 = 2025 (Schema 91), 17763 = 2019' ((Get-SmAdAdprepServerName '10.0.26100.1').Schema -eq 91 -and (Get-SmAdAdprepServerName '10.0.17763.5').Name -eq 'Windows Server 2019' -and $null -eq (Get-SmAdAdprepServerName 'x'))
Check 'Zielebenen: nur hoehere' ((Get-SmAdLevelTargets -Current 7) -join ',' -eq '10' -and (Get-SmAdLevelTargets -Current 4) -join ',' -eq '5,6,7,10' -and -not (Get-SmAdLevelTargets -Current 10))

# ---------------------------------------------------------------- 2. Logik der Ebenenpruefung
function DC([string]$n, [string]$os, [string]$dom = 'contoso.local') { [pscustomobject]@{ HostName = $n; Domain = $dom; OperatingSystem = $os } }
$all25 = @((DC 'dc01.contoso.local' 'Windows Server 2025 Datacenter'), (DC 'dc02.contoso.local' 'Windows Server 2025 Standard'))
$with16 = @((DC 'dc01.contoso.local' 'Windows Server 2025 Datacenter'), (DC 'dc02.contoso.local' 'Windows Server 2016 Standard'))
$r = Test-SmAdLevelRaise -Scope Forest -Target 10 -Current 7 -DomainControllers $all25 -DomainName 'contoso.local' -DomainLevels @{ 'contoso.local' = 7 } -ReplicationOk $true
Check 'Ebenen: Forest 2016 -> 2025, alle DCs 2025 und Domaene auf 2016: Domaene blockiert zuerst' (-not $r.Ok -and (($r.Checks | Where-Object Name -eq 'Alle Domaenen auf Zielebene').Ok -eq $false))
$r = Test-SmAdLevelRaise -Scope Forest -Target 10 -Current 7 -DomainControllers $all25 -DomainName 'contoso.local' -DomainLevels @{ 'contoso.local' = 10 } -ReplicationOk $true
Check 'Ebenen: alle DCs 2025, Domaene 2025, Replikation ok -> erlaubt' ($r.Ok -and -not $r.TooOld.Count)
$r = Test-SmAdLevelRaise -Scope Domain -Target 10 -Current 7 -DomainControllers $with16 -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: ein DC mit 2016 blockiert 2025 (Domaene) und wird benannt' (-not $r.Ok -and $r.TooOld.Count -eq 1 -and $r.TooOld[0] -match 'dc02')
$r = Test-SmAdLevelRaise -Scope Domain -Target 7 -Current 6 -DomainControllers $with16 -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: derselbe Bestand erlaubt 2016 (DC mit 2016 genuegt)' $r.Ok
$r = Test-SmAdLevelRaise -Scope Domain -Target 10 -Current 7 -DomainControllers $all25 -DomainName 'contoso.local' -ReplicationOk $false
Check 'Ebenen: Replikationsfehler blockiert' (-not $r.Ok -and (($r.Checks | Where-Object Name -eq 'Replikation in Ordnung').Ok -eq $false))
$mixed = @((DC 'dc01.contoso.local' 'Windows Server 2025 Datacenter'), (DC 'dc9.child.contoso.local' 'Windows Server 2016 Standard' 'child.contoso.local'))
$r = Test-SmAdLevelRaise -Scope Domain -Target 10 -Current 7 -DomainControllers $mixed -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: Domaene zaehlt nur die DCs der eigenen Domaene' $r.Ok
$r = Test-SmAdLevelRaise -Scope Forest -Target 10 -Current 7 -DomainControllers $mixed -DomainName 'contoso.local' -DomainLevels @{ 'contoso.local' = 10; 'child.contoso.local' = 10 } -ReplicationOk $true
Check 'Ebenen: Forest zaehlt alle DCs (Kind-Domaene mit 2016 blockiert)' (-not $r.Ok -and $r.TooOld.Count -eq 1)
$r = Test-SmAdLevelRaise -Scope Domain -Target 7 -Current 7 -DomainControllers $all25 -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: Ziel nicht hoeher als jetzt blockiert' (-not $r.Ok)
$r = Test-SmAdLevelRaise -Scope Domain -Target 10 -Current 7 -DomainControllers @((DC 'dc03.contoso.local' 'Etwas Unbekanntes')) -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: nicht erkennbares Betriebssystem blockiert' (-not $r.Ok)
$r = Test-SmAdLevelRaise -Scope Domain -Target 10 -Current 7 -DomainControllers @() -DomainName 'contoso.local' -ReplicationOk $true
Check 'Ebenen: keine DCs gefunden blockiert' (-not $r.Ok)

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- 3. Stub-Programme und gemockte AD-Cmdlets (Parameterlisten laut Microsoft Learn)
$stubDir = Join-Path $work 'stubs'; New-Item -ItemType Directory -Force $stubDir | Out-Null
$src = @'
using System; using System.IO;
class P { static int Main(string[] a) {
  string dir = Environment.GetEnvironmentVariable("SM_STUB_DIR");
  string name = Path.GetFileNameWithoutExtension(System.Reflection.Assembly.GetExecutingAssembly().Location).ToLower();
  File.AppendAllText(Path.Combine(dir, name + ".args.log"), string.Join("|", a) + "\r\n");
  File.AppendAllText(Path.Combine(dir, name + ".path.log"), System.Reflection.Assembly.GetExecutingAssembly().Location + "\r\n");
  // Rohbytes der Standardeingabe (ohne Dekodierung, damit ein BOM sichtbar bleibt); das Textlog zeigt jedes Byte als Latin-1-Zeichen
  var ms = new MemoryStream(); using (var si = Console.OpenStandardInput()) si.CopyTo(ms);
  byte[] raw = ms.ToArray();
  using (var fs = new FileStream(Path.Combine(dir, name + ".stdin.bin"), FileMode.Append)) fs.Write(raw, 0, raw.Length);
  File.AppendAllText(Path.Combine(dir, name + ".stdin.log"), System.Text.Encoding.GetEncoding(28591).GetString(raw) + "\r\n---\r\n");
  string key = name;
  if (name == "repadmin" && a.Length > 0) key = name + "." + a[0].Trim('/').ToLower();
  if (name == "dcdiag") { foreach (var x in a) if (x.StartsWith("/test:")) key = name + "." + x.Substring(6); }
  string sl = Environment.GetEnvironmentVariable("SM_STUB_SLEEP_" + name.ToUpper()); if (sl != null) System.Threading.Thread.Sleep(int.Parse(sl));
  string f = Path.Combine(dir, key + ".out");
  if (File.Exists(f)) Console.Out.Write(File.ReadAllText(f));
  string ex = Environment.GetEnvironmentVariable("SM_STUB_EXIT_" + name.ToUpper());
  return ex == null ? 0 : int.Parse(ex);
} }
'@
$base = Join-Path $stubDir 'stubbase.exe'
Add-Type -TypeDefinition $src -OutputAssembly $base -OutputType ConsoleApplication
foreach ($n in 'repadmin', 'dcdiag', 'ntdsutil') { Copy-Item $base (Join-Path $stubDir "$n.exe") }
$media = Join-Path $work 'media'; New-Item -ItemType Directory -Force (Join-Path $media 'support\adprep') | Out-Null
Copy-Item $base (Join-Path $media 'support\adprep\adprep.exe')
Copy-Item $base (Join-Path $media 'support\adprep\adprepcore.dll')
[IO.File]::WriteAllText((Join-Path $media 'support\adprep\sch91.ldf'), "dn: CN=Schema`r`nchangetype: modify`r`n")
New-Item -ItemType Directory -Force (Join-Path $media 'support\adprep\en-US') | Out-Null
[IO.File]::WriteAllText((Join-Path $media 'support\adprep\en-US\adprep.exe.mui'), 'mui')
$script:SmAdCdRomRoots = @($media)      # Test: die Attrappe gilt als Laufwerk vom Typ CD-ROM
$env:SM_STUB_DIR = $stubDir
$script:SmAdToolPaths = @{ repadmin = (Join-Path $stubDir 'repadmin.exe'); dcdiag = (Join-Path $stubDir 'dcdiag.exe'); ntdsutil = (Join-Path $stubDir 'ntdsutil.exe') }
function SetStub([string]$Name, [string]$Text) { [IO.File]::WriteAllText((Join-Path $stubDir "$Name.out"), $Text) }
function ClearStub([string]$Name) { Remove-Item -LiteralPath (Join-Path $stubDir "$Name.out") -Force -ErrorAction SilentlyContinue }
function ResetStubLogs { Get-ChildItem $stubDir | Where-Object { $_.Extension -in '.log', '.bin' } | Remove-Item -Force }
function StubArgs([string]$Name) { $f = Join-Path $stubDir "$Name.args.log"; if (Test-Path $f) { @(Get-Content -LiteralPath $f) } else { @() } }
function StubBytes([string]$Name) { $f = Join-Path $stubDir "$Name.stdin.bin"; if (Test-Path $f) { , [IO.File]::ReadAllBytes($f) } else { , [byte[]]@() } }
function StubIn([string]$Name) { $f = Join-Path $stubDir "$Name.stdin.log"; if (Test-Path $f) { Get-Content -LiteralPath $f -Raw } else { '' } }
$goodSummary = @'
Replication Summary Start Time: 2026-11-22 10:00:00

Beginning data collection for replication summary, this may take awhile:
  .....

Source DSA          largest delta    fails/total %%   error
 DC01                       05m:12s    0 /   4    0
 DC02                       07m:01s    0 /   4    0

Destination DSA     largest delta    fails/total %%   error
 DC01                       07m:01s    0 /   4    0
 DC02                       05m:12s    0 /   4    0
'@
$badSummary = $goodSummary.Replace(' DC02                       07m:01s    0 /   4    0', ' DC02                       07m:01s    2 /   4   50  (1722) The RPC server is unavailable.')
$goodCsv = 'showrepl_COLUMNS,"Destination DSA Site","Destination DSA","Naming Context","Source DSA Site","Source DSA","Transport Type","Number of Failures","Last Failure Time","Last Failure Status","Last Success Time","Last Success Status"' + "`r`n" + 'showrepl_INFO,"Default-First-Site-Name","DC01","DC=contoso,DC=local","Default-First-Site-Name","DC02","RPC","0","0","0","2026-11-22 09:59:00","0"'
$badCsv = $goodCsv.Replace('"RPC","0","0","0"', '"RPC","3","2026-11-22 09:00:00","1722"')
function GoodRepl { SetStub 'repadmin.replsummary' $goodSummary; SetStub 'repadmin.showrepl' $goodCsv; foreach ($t in $script:SmAdDcdiagTests) { ClearStub "dcdiag.$t" } }
GoodRepl

$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:SmDnsStateSidsOverride = @($userSid)     # Test: Besitzer und Zugriff nur fuer den Testbenutzer (statt Administratoren und SYSTEM)
$dataRoot = Join-Path $work 'data'
$script:SmAdDataRoot = $dataRoot
$local = $env:COMPUTERNAME; $localFqdn = "$local.contoso.local"
$origReach = ${function:Test-SmAdHostReachable}
$origSigned = ${function:Test-SmAdMicrosoftSigned}

$script:S = $null
function ResetState {
    $script:S = @{
        Admin = $true; Reach = @{}; Signed = $true; OrigName = 'adprep.exe'; SignedCalls = (New-Object System.Collections.ArrayList); UserEnabled = $false; UserGroups = @(); PingCalls = 0; FlapAfter = 0; Only = $null; ReadOnly = $false; Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518')
        Pdc = 'dc-old.contoso.local'; Rid = 'dc-old.contoso.local'; Infra = 'dc-old.contoso.local'; Schema = 'dc-old.contoso.local'; Naming = 'dc-old.contoso.local'
        ForestMode = 'Windows2016Forest'; DomainMode = 'Windows2016Domain'; SchemaQueue = $null; SchemaVersion = 91
        Dcs = @(
            [pscustomobject]@{ HostName = $localFqdn; Site = 'Default-First-Site-Name'; OperatingSystem = 'Windows Server 2025 Datacenter'; IsGlobalCatalog = $true; IsReadOnly = $false }
            [pscustomobject]@{ HostName = 'dc-old.contoso.local'; Site = 'Default-First-Site-Name'; OperatingSystem = 'Windows Server 2025 Standard'; IsGlobalCatalog = $true; IsReadOnly = $false }
        )
        Moves = New-Object System.Collections.ArrayList; Modes = New-Object System.Collections.ArrayList
    }
    $script:S.Reach['dc-old.contoso.local'] = $true
}
ResetState
function Test-SmAdIsAdmin { $script:S.Admin }
function Get-SmAdTokenSids { @($script:S.Sids) }
function Test-SmAdHostReachable { param([string]$HostName) if ($HostName -notmatch '^[A-Za-z0-9.\-]{1,255}$') { throw "Ungueltiger Servername: $HostName" }; [bool]$script:S.Reach[$HostName] }
function Test-SmAdMicrosoftSigned { param([string]$Path, [string[]]$CommonNames) [void]$script:S.SignedCalls.Add(('{0}|{1}' -f (Split-Path -Leaf $Path), ($CommonNames -join ','))); $script:S.Signed }
function Get-SmAdOriginalFileName { param([string]$Path) $script:S.OrigName }
function Test-SmAdPing { param([string]$HostName) $script:S.PingCalls++; ([bool]$script:S.Reach[$HostName] -and (-not $script:S.Only -or $script:S.Only -eq 'ping')) -or ($script:S.FlapAfter -and $script:S.PingCalls -ge $script:S.FlapAfter) }
function Test-SmAdTcpPort { param([string]$HostName, [int]$Port, [int]$TimeoutMs) ([bool]$script:S.Reach[$HostName] -and (-not $script:S.Only -or $script:S.Only -eq $Port)) -or ($script:S.FlapAfter -and $script:S.PingCalls -ge $script:S.FlapAfter) }
$script:SmAdSeizeProbeIntervalSec = 0
function Get-ADForest { [pscustomobject]@{ Name = 'contoso.local'; ForestMode = $script:S.ForestMode; SchemaMaster = $script:S.Schema; DomainNamingMaster = $script:S.Naming; RootDomain = 'contoso.local'; Domains = @('contoso.local') } }
function Get-ADDomain { param([string]$Identity) [pscustomobject]@{ DNSRoot = 'contoso.local'; DomainMode = $script:S.DomainMode; PDCEmulator = $script:S.Pdc; RIDMaster = $script:S.Rid; InfrastructureMaster = $script:S.Infra; DomainSID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3' } } }
function Get-ADDomainController { param([string]$Identity, [string]$Filter, [string]$Server)
    if ($Identity) { $dc = $script:S.Dcs | Where-Object { $_.HostName -like "$Identity.*" -or $_.HostName -eq $Identity } | Select-Object -First 1; if ($dc) { $dc.IsReadOnly = $script:S.ReadOnly -and $Identity -eq $local; return $dc } throw "DC nicht gefunden: $Identity" }
    $script:S.Dcs }
function Get-ADRootDSE { param([string]$Server) [pscustomobject]@{ schemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=local' } }
function Get-ADObject { param([string]$Identity, [string[]]$Properties, [string]$Server)
    $v = $script:S.SchemaVersion; if ($script:S.SchemaQueue -and $script:S.SchemaQueue.Count) { $v = $script:S.SchemaQueue[0]; $script:S.SchemaQueue = @($script:S.SchemaQueue | Select-Object -Skip 1) }
    [pscustomobject]@{ objectVersion = $v } }
function Get-ADUser { param([string]$Identity, [string[]]$Properties) if ($Identity -eq 'svc-dsrm') { [pscustomobject]@{ Enabled = $script:S.UserEnabled; tokenGroups = @($script:S.UserGroups | ForEach-Object { [pscustomobject]@{ Value = $_ } }) } } else { throw 'Konto nicht gefunden' } }
# laut Doku: -Identity (ADDirectoryServer), -OperationMasterRole (ADOperationMasterRole[]), -Force (Seize), -PassThru, -Server, -Credential, -AuthType, -WhatIf, -Confirm
function Move-ADDirectoryServerOperationMasterRole {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory, Position = 0)][object]$Identity, [Parameter(Mandatory, Position = 1)][ValidateSet('PDCEmulator', 'RIDMaster', 'InfrastructureMaster', 'SchemaMaster', 'DomainNamingMaster', '0', '1', '2', '3', '4')][string[]]$OperationMasterRole,
        [switch]$Force, [switch]$PassThru, [string]$Server, [pscredential]$Credential, [ValidateSet('Negotiate', 'Basic')][string]$AuthType)
    [void]$script:S.Moves.Add([pscustomobject]@{ Identity = $Identity; Roles = @($OperationMasterRole); Force = [bool]$Force; Bound = @($PSBoundParameters.Keys) })
    foreach ($r in $OperationMasterRole) { switch ($r) { 'PDCEmulator' { $script:S.Pdc = $Identity.HostName } 'RIDMaster' { $script:S.Rid = $Identity.HostName } 'InfrastructureMaster' { $script:S.Infra = $Identity.HostName } 'SchemaMaster' { $script:S.Schema = $Identity.HostName } 'DomainNamingMaster' { $script:S.Naming = $Identity.HostName } } }
}
function Set-ADDomainMode {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory, Position = 0)][object]$Identity, [Parameter(Mandatory, Position = 2)][ValidateSet('Windows2000Domain', 'Windows2003InterimDomain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain', 'Windows2012R2Domain', 'Windows2016Domain', 'Windows2025Domain', 'UnknownDomain')][string]$DomainMode,
        [switch]$PassThru, [string]$Server, [pscredential]$Credential, [string]$AuthType)
    [void]$script:S.Modes.Add([pscustomobject]@{ Kind = 'Domain'; Mode = $DomainMode; Server = $Server; Confirm = $ConfirmPreference }); $script:S.DomainMode = $DomainMode
}
function Set-ADForestMode {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory, Position = 0)][object]$Identity, [Parameter(Mandatory, Position = 2)][ValidateSet('Windows2000Forest', 'Windows2003InterimForest', 'Windows2003Forest', 'Windows2008Forest', 'Windows2008R2Forest', 'Windows2012Forest', 'Windows2012R2Forest', 'Windows2016Forest', 'Windows2025Forest', 'UnknownForest')][string]$ForestMode,
        [switch]$PassThru, [string]$Server, [pscredential]$Credential, [string]$AuthType)
    [void]$script:S.Modes.Add([pscustomobject]@{ Kind = 'Forest'; Mode = $ForestMode; Server = $Server }); $script:S.ForestMode = $ForestMode
}
function AuditText { $f = Join-Path $dataRoot 'AD\Protokoll.log'; if (Test-Path $f) { Get-Content -LiteralPath $f -Raw } else { '' } }

# ---------------------------------------------------------------- 4. Uebersicht, Bericht
$ov = Get-SmAdOverview
Check 'Uebersicht: Ebenen, Schema-Version 91 = 2025, 2 DCs, 5 FSMO-Rollen, Replikation ok' ($ov.Forest.SchemaVersion -eq 91 -and $ov.Forest.SchemaName -eq 'Windows Server 2025' -and $ov.DomainControllers.Count -eq 2 -and $ov.Fsmo.Count -eq 5 -and $ov.Replication.Ok -and $ov.Forest.Mode -eq 'Windows2016Forest')
Check 'Uebersicht: dcdiag-Tests ausgewaehlt und einzeln aufgerufen (/q /test:X)' ($ov.Dcdiag.Count -eq $script:SmAdDcdiagTests.Count -and ((StubArgs 'dcdiag') -contains '/q|/test:Replications'))
Check 'Uebersicht: repadmin /replsummary und /showrepl * /csv aufgerufen' ((StubArgs 'repadmin') -contains '/replsummary' -and (StubArgs 'repadmin') -contains '/showrepl|*|/csv')
$rep = New-SmAdReport -Overview $ov
Check 'Bericht: Datei im gehaerteten AD-Ordner, Name auf der Whitelist' ($rep.StartsWith((Join-Path $dataRoot 'AD')) -and (Split-Path -Leaf $rep) -match $script:SmAdReportPattern)
$rd = Read-SmAdReport -Path $rep
Check 'Bericht: lesen und anzeigen (Namen, Schema 91 = 2025, FSMO, Replikation)' ($rd.Forest.Name -eq 'contoso.local' -and (Format-SmAdReportText $rd) -match 'Windows Server 2025' -and (Format-SmAdReportText $rd) -match 'dc-old.contoso.local' -and (Format-SmAdReportText $rd) -match 'ohne Fehler' -and $rd.DomainControllers.Count -eq 2)
Check 'Bericht: keine Geheimnisse (kein Kennwort, kein Link)' ((Get-Content -LiteralPath $rep -Raw) -notmatch '(?i)passw|kennwort|sharepoint|secret')
$bigFile = Join-Path $work 'gross.json'; [IO.File]::WriteAllBytes($bigFile, (New-Object byte[] (5MB)))
Check 'Bericht: Datei ueber dem Groessenlimit wird nicht gelesen' (ThrowsLike { Read-SmAdReport -Path $bigFile } 'zu gross')
$junk = Join-Path $work 'kaputt.json'; [IO.File]::WriteAllText($junk, '{ nicht json')
Check 'Bericht: kaputtes JSON und fremde Datei abgelehnt' ((Throws { Read-SmAdReport -Path $junk }) -and (Throws { $j2 = Join-Path $work 'fremd.json'; [IO.File]::WriteAllText($j2, '{"Schema":1,"Kind":"Anderes"}'); Read-SmAdReport -Path $j2 }))
$evil = Get-Content -LiteralPath $rep -Raw | ConvertFrom-Json
$evil.Computer = ('X' * 1000) + [char]7 + 'Ende'; $evil.Forest.Name = "=cmd|' /C calc'!A0" + [char]0
$evilPath = Join-Path $work 'evil.json'; [IO.File]::WriteAllText($evilPath, ($evil | ConvertTo-Json -Depth 8))
$er = Read-SmAdReport -Path $evilPath
Check 'Bericht: Texte aus der Datei werden gekuerzt und von Steuerzeichen befreit, nichts wird ausgefuehrt' ($er.Computer.Length -le 310 -and $er.Computer -notmatch '[\x00-\x08]' -and $er.Forest.Name -notmatch '\x00')
$script:ExportCalls = @()
function Export-SmTable { param($Rows, [string]$Path) $script:ExportCalls += , @{ Rows = @($Rows); Path = $Path } }   # gemockt
Export-SmAdDcTable -Report $rd -Path (Join-Path $work 'dcs.csv')
Check 'Export: Tabelle der DCs geht an Export-SmTable -Rows -Path (gemockt)' ($script:ExportCalls.Count -eq 1 -and $script:ExportCalls[0].Rows.Count -eq 2 -and $script:ExportCalls[0].Path -like '*dcs.csv' -and $script:ExportCalls[0].Rows[0].PSObject.Properties.Name -contains 'Betriebssystem')

$wd = New-SmAdWorkDir
Check 'Berater: Arbeitsordner fuer Berichte liegt in LOCALAPPDATA, nicht in %TEMP%' ($wd -like (Join-Path $env:LOCALAPPDATA 'ServerMigration\Ad-*') -and $wd -notlike (Join-Path $env:TEMP '*'))
Remove-Item -LiteralPath $wd -Recurse -Force
Check 'Quelltext: keine Dateien in %TEMP% fuer AD (weder Berater noch Server)' (((Get-Content -LiteralPath (Join-Path $repo 'Modules\SmAd.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw)) -notmatch '\$env:TEMP')

# ---------------------------------------------------------------- 5. Protokoll und gehaerteter Ordner
$aud = AuditText
if ($elevated) { Check 'Ordner gehaertet: nur der erlaubte Eintrag in der Zugriffsliste (Protect-SmDnsStateDir)' (@(Test-SmDnsStateDirAcl -Path (Join-Path $dataRoot 'AD') -AllowedSids @($userSid)).Count -eq 0) }
$jRoot = Join-Path $work 'jroot'; New-Item -ItemType Directory $jRoot | Out-Null
$jTarget = Join-Path $work 'jtarget'; New-Item -ItemType Directory $jTarget | Out-Null
$null = & cmd.exe /c mklink /J (Join-Path $jRoot 'AD') $jTarget 2>&1
$script:SmAdDataRoot = $jRoot
Check 'Ordner: eine Junction als AD-Ordner bricht ab, es wird nichts hineingeschrieben' ((ThrowsLike { Get-SmAdFolder } 'Verknuepfung') -and -not (Get-ChildItem $jTarget -Force))
$script:SmAdDataRoot = $dataRoot

# ---------------------------------------------------------------- 6. FSMO uebertragen
ResetState; ResetStubLogs; GoodRepl
$pre = Test-SmAdFsmoPrecheck -Roles @('PDCEmulator', 'RIDMaster')
Check 'FSMO Vorpruefung: alles in Ordnung (Admin, beschreibbar, Inhaber erreichbar, Replikation, dcdiag, Rechte)' ($pre.Ok -and $pre.ToMove.Count -eq 2 -and ($pre.Checks | Where-Object { $_.Blocking -and -not $_.Ok }).Count -eq 0)
Check 'FSMO: ohne Bestaetigung keine Uebertragung, aber eine Protokollzeile "fehlgeschlagen"' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') } 'bestaetigt') -and $script:S.Moves.Count -eq 0 -and (AuditText) -match 'FSMO uebertragen \| .*fehlgeschlagen')
SetStub 'repadmin.replsummary' $badSummary
Check 'FSMO: Replikationsfehler (/replsummary) -> keine Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
GoodRepl; SetStub 'repadmin.showrepl' $badCsv
Check 'FSMO: Replikationsfehler (/showrepl /csv) -> keine Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
GoodRepl; SetStub 'repadmin.replsummary' 'Ausgabe ohne Tabelle'
Check 'FSMO: nicht lesbare repadmin-Ausgabe zaehlt als Fehler, nicht als in Ordnung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
GoodRepl; SetStub 'dcdiag.KnowsOfRoleHolders' 'Fehler: der Rolleninhaber ist nicht erreichbar'
Check 'FSMO: dcdiag meldet einen Fehler -> keine Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
GoodRepl; $script:S.Reach['dc-old.contoso.local'] = $false
Check 'FSMO: Inhaber nicht erreichbar -> keine normale Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
$script:S.Reach['dc-old.contoso.local'] = $true; $script:S.ReadOnly = $true
Check 'FSMO: dieser Server ist ein RODC -> keine Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
$script:S.ReadOnly = $false; $script:S.Admin = $false
Check 'FSMO: Fenster nicht als Administrator -> keine Uebertragung' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
$script:S.Admin = $true; $script:S.Sids = @('S-1-5-21-1-2-3-512')
Check 'FSMO: Schemamaster braucht Schema Admins, Namensmaster Enterprise Admins' ((ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('SchemaMaster') -Confirmed } 'Vorpruefung') -and (ThrowsLike { Invoke-SmAdFsmoTransfer -Roles @('DomainNamingMaster') -Confirmed } 'Vorpruefung') -and $script:S.Moves.Count -eq 0)
$script:S.Sids = @()
Check 'FSMO: ohne Domain Admins keine Uebertragung (PDC)' ((Throws { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed }) -and $script:S.Moves.Count -eq 0)
$script:S.Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518')
$res = Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster', 'SchemaMaster', 'DomainNamingMaster') -Confirmed
$mv = $script:S.Moves[0]
Check 'FSMO: Uebertragung mit Identity = dieser DC, allen fuenf Rollen und OHNE -Force (keine Seizure)' ($script:S.Moves.Count -eq 1 -and $mv.Identity.HostName -eq $localFqdn -and $mv.Roles.Count -eq 5 -and -not $mv.Force -and $mv.Bound -notcontains 'Force')
Check 'FSMO: Rollen vorher beim alten DC, nachher hier (Nachpruefung), Protokollzeile "erfolgreich"' ($res.Before.PDCEmulator -eq 'dc-old.contoso.local' -and $res.After.PDCEmulator -eq $localFqdn -and $res.After.SchemaMaster -eq $localFqdn -and (AuditText) -match 'FSMO uebertragen \| .*erfolgreich')
$script:S.Moves.Clear()
Check 'FSMO: liegen alle Rollen schon hier, gibt es nichts zu uebertragen' ((Throws { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed }) -and $script:S.Moves.Count -eq 0)

# ---------------------------------------------------------------- 7. Seize
ResetState; ResetStubLogs; GoodRepl
Check 'Seize: Inhaber erreichbar -> verweigert, nichts veraendert' ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved } 'erreichbar') -and $script:S.Moves.Count -eq 0)
$script:S.Reach['dc-old.contoso.local'] = $false
Check 'Seize: ohne Bestaetigung nichts' ((Throws { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' }) -and $script:S.Moves.Count -eq 0)
Check 'Seize: falsch getippter Rollenname (auch falsche Gross-/Kleinschreibung) nichts' ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'ridmaster' -Confirmed } 'getippte') -and (Throws { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'PDCEmulator' -Confirmed }) -and $script:S.Moves.Count -eq 0)
$script:S.Sids = @()
Check 'Seize: ohne Rechte nichts' ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved } 'Rechte') -and $script:S.Moves.Count -eq 0)
$script:S.Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518')
Check 'Seize: unbekannte Rolle abgelehnt' ((Throws { Invoke-SmAdFsmoSeize -Role 'Quatsch' -TypedRole 'Quatsch' -Confirmed }) -and $script:S.Moves.Count -eq 0)
$sz = Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved
$mv = $script:S.Moves[0]
Check 'Seize: Inhaber nicht erreichbar, Rolle getippt, bestaetigt -> Move mit -Force fuer genau diese Rolle' ($script:S.Moves.Count -eq 1 -and $mv.Force -and $mv.Roles.Count -eq 1 -and $mv.Roles[0] -eq 'RIDMaster' -and $script:S.Rid -eq $localFqdn -and $script:S.Pdc -eq 'dc-old.contoso.local')
Check 'Seize: Protokollzeile nennt Rolle und "erfolgreich", Hinweis zum alten DC' ((AuditText) -match 'FSMO Seize \| RIDMaster -> .*erfolgreich' -and $sz.Detail -match 'nie wieder ans Netz')
Check 'Seize: Rolle liegt schon hier -> nichts' (Throws { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved })

# ---- Seize: Inhaber dreimal pruefen, Haken "dauerhaft entfernt", letzte Replikation
ResetState; ResetStubLogs; GoodRepl
$script:S.Reach['dc-old.contoso.local'] = $false
Check 'Seize: ohne -OwnerPermanentlyRemoved nichts (und der Inhaber wird gar nicht erst geprueft)' ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed } 'dauerhaft entfernt') -and $script:S.Moves.Count -eq 0 -and $script:S.PingCalls -eq 0)
$script:S.PingCalls = 0; $script:S.FlapAfter = 2
Check 'Seize: antwortet der Inhaber erst bei der zweiten Pruefung, wird verweigert (alle drei Versuche zaehlen)' ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved } 'erreichbar') -and $script:S.Moves.Count -eq 0)
$script:S.FlapAfter = 0
foreach ($only in 'ping', 389, 135) {
    $script:S.Reach['dc-old.contoso.local'] = $true; $script:S.Only = $only
    Check "Seize: antwortet nur $only -> der Inhaber gilt als erreichbar, nichts veraendert" ((ThrowsLike { Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved } 'erreichbar') -and $script:S.Moves.Count -eq 0)
}
$script:S.Only = $null; $script:S.Reach['dc-old.contoso.local'] = $false
$csvOld = 'showrepl_COLUMNS,"Destination DSA Site","Destination DSA","Naming Context","Source DSA Site","Source DSA","Transport Type","Number of Failures","Last Failure Time","Last Failure Status","Last Success Time","Last Success Status"' + "`r`n" +
    'showrepl_INFO,"Default-First-Site-Name","DC01","DC=contoso,DC=local","Default-First-Site-Name","DC-OLD","RPC","5","2026-11-21 02:00:00","1722","2026-11-20 08:15:00","0"' + "`r`n" +
    'showrepl_INFO,"Default-First-Site-Name","DC01","DC=contoso,DC=local","Default-First-Site-Name","DC-OLD","RPC","5","2026-11-21 02:00:00","1722","2026-11-19 07:00:00","0"'
SetStub 'repadmin.showrepl' $csvOld
$script:S.PingCalls = 0
$sz = Invoke-SmAdFsmoSeize -Role 'RIDMaster' -TypedRole 'RIDMaster' -Confirmed -OwnerPermanentlyRemoved
Check 'Seize: drei Pruefungen (Ping, LDAP, RPC je Versuch), dann Move mit -Force; Rolle uebernommen' ($script:S.PingCalls -eq 3 -and $script:S.Moves.Count -eq 1 -and $script:S.Moves[0].Force -and $script:S.Rid -eq $localFqdn)
Check 'Seize: letzte erfolgreiche Replikation des Inhabers wird angezeigt und protokolliert' ($sz.LastReplication -eq '2026-11-20 08:15' -and $sz.Detail -match '2026-11-20 08:15' -and (AuditText) -match 'FSMO Seize \| RIDMaster -> .*erfolgreich \| .*2026-11-20 08:15')
Check 'Seize: Replikation unbekannter Server -> "nicht ermittelbar"' ((Get-SmAdLastReplication -HostName 'dc-gibtsnicht.contoso.local') -eq 'nicht ermittelbar')
GoodRepl
$script:SmAdSeizeProbeIntervalSec = 1
$sw = [Diagnostics.Stopwatch]::StartNew(); $pr = Test-SmAdHolderProbe -HostName 'dc-old.contoso.local'; $sw.Stop()
Check 'Seize: die Pruefungen liegen im Abstand (hier 1 s, in der Praxis 10 s): 3 Versuche brauchen mindestens 2 Abstaende' ($pr.Rows.Count -eq 3 -and $sw.Elapsed.TotalSeconds -ge 1.9)
$script:SmAdSeizeProbeIntervalSec = 0
Check 'Seize: Standardabstand ist 10 s, Standardversuche 3 (Quelltext)' (((Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw) -match '\$script:SmAdSeizeProbeIntervalSec = 10') -and ((Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw) -match '\[int\]\$Attempts = 3'))
$srcAd = Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw
Check 'Seize: die Oberflaeche setzt -OwnerPermanentlyRemoved nur aus dem Haken (ChkAdSeizeGone) und schaltet den Knopf nur mit Haken frei' (($srcAd -match 'OwnerPermanentlyRemoved:\$P\.Gone') -and ($srcAd -match 'Gone = \[bool\]\$u\.ChkAdSeizeGone\.IsChecked') -and ($srcAd -match '\[bool\]\$u\.ChkAdSeizeGone\.IsChecked -and \$u\.TxtAdSeizeConfirm') -and ((Get-Content -LiteralPath (Join-Path $repo 'UI\AdServer.xaml') -Raw) -match 'dauerhaft entfernt und kommt nie wieder ans Netz'))

# ---------------------------------------------------------------- 8. Protokoll: Schreibfehler werden gezeigt
$errRoot = Join-Path $work 'errdata'
$script:SmAdDataRoot = $errRoot
[void](Get-SmAdFolder)
New-Item -ItemType Directory (Join-Path $errRoot 'AD\Protokoll.log') | Out-Null     # die Protokolldatei ist ein Ordner: Schreiben schlaegt fehl
ResetState
$msg = ''; try { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') } catch { $msg = $_.Exception.Message }
Check 'Protokoll: ein Schreibfehler beim Fehlerfall wird in der Meldung genannt (nicht still geschluckt)' ($msg -match 'bestaetigt' -and $msg -match 'Protokoll konnte nicht geschrieben')
$msg = ''; try { Invoke-SmAdFsmoTransfer -Roles @('PDCEmulator') -Confirmed } catch { $msg = $_.Exception.Message }
Check 'Protokoll: ein Schreibfehler nach erfolgreicher Aktion wird als Fehler gemeldet' ($msg -match 'ausgefuehrt, aber das Protokoll konnte nicht geschrieben')
$script:SmAdDataRoot = $dataRoot

# ---------------------------------------------------------------- 9. DSRM-Kennwort (nur ueber stdin)
ResetState; ResetStubLogs; GoodRepl
$testPw = 'Gegen-Test-Kennwort-7531!'
$sec = ConvertTo-SecureString $testPw -AsPlainText -Force
$sec2 = ConvertTo-SecureString $testPw -AsPlainText -Force
SetStub 'ntdsutil' "Password has been set successfully.`r`n"
$null = Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed
Check 'DSRM Variante A: ntdsutil "set dsrm password" "sync from domain account <konto>" q q, kein Kennwort beteiligt' ((StubArgs 'ntdsutil') -contains 'set dsrm password|sync from domain account svc-dsrm|q|q' -and (StubIn 'ntdsutil').Trim() -eq '---')
Check 'DSRM Variante A: ohne Bestaetigung, mit Anfuehrungszeichen im Konto, unbekanntes Konto -> kein Aufruf' ((Throws { Invoke-SmAdDsrmSync -Account 'svc-dsrm' }) -and (Throws { Invoke-SmAdDsrmSync -Account 'a" "b' -Confirmed }) -and (Throws { Invoke-SmAdDsrmSync -Account 'gibtsnicht' -Confirmed }) -and (StubArgs 'ntdsutil').Count -eq 1)
ResetStubLogs
Check 'DSRM Variante B: Komplexitaet (zu kurz, zu einfach, ok)' ((-not (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'Kurz1!' -AsPlainText -Force)).Ok) -and (-not (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'nurkleinbuchstaben' -AsPlainText -Force)).Ok) -and (Test-SmAdPasswordComplexity $sec).Ok)
Check 'DSRM Variante B: zwei verschiedene Eingaben -> kein Aufruf' ((Throws { Invoke-SmAdDsrmReset -Password $sec -Confirm (ConvertTo-SecureString 'Anderes-Kennwort-9999!' -AsPlainText -Force) -Confirmed }) -and (StubArgs 'ntdsutil').Count -eq 0)
Check 'DSRM Variante B: zu einfaches Kennwort und fehlende Bestaetigung -> kein Aufruf' ((Throws { $w = ConvertTo-SecureString 'abc' -AsPlainText -Force; Invoke-SmAdDsrmReset -Password $w -Confirm $w -Confirmed }) -and (Throws { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 }) -and (StubArgs 'ntdsutil').Count -eq 0)
SetStub 'ntdsutil' ("ntdsutil: set dsrm password`r`nReset DSRM Administrator Password: reset password on server NULL`r`nPlease type password for DS Restore Mode Administrator Account: $testPw`r`nConfirm new password: $testPw`r`nPassword has been set successfully.`r`n")   # Stub gibt das Kennwort wieder (schlimmster Fall)
$r1 = Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed
$argLog = (StubArgs 'ntdsutil') -join "`n"
Check 'DSRM Variante B (lokal): Argumente "set dsrm password" "reset password on server NULL" q q' ($argLog -eq 'set dsrm password|reset password on server NULL|q|q')
Check 'DSRM Variante B: das Kennwort kommt zweimal ueber die Standardeingabe an (Eingabe und Bestaetigung)' (([regex]::Matches((StubIn 'ntdsutil'), [regex]::Escape($testPw))).Count -eq 2)
Check 'GEGENTEST: das Kennwort steht NICHT in der Kommandozeile (Argumente des Stubs)' ($argLog -notmatch [regex]::Escape($testPw) -and $argLog -notmatch 'Gegen')
Check 'GEGENTEST: Rueckgabe, Protokoll und Fehlerliste enthalten das Kennwort nicht' ((($r1 | Out-String) -notmatch [regex]::Escape($testPw)) -and ((AuditText) -notmatch [regex]::Escape($testPw)) -and (($Error | Out-String) -notmatch [regex]::Escape($testPw)))
$hits = New-Object System.Collections.Generic.List[string]
$scanRoots = @($work) + @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'sm-ad-test-*' -and ($_.Name -like 'ServerMigration-*' -or $_.Name -like 'sm-*' -or $_.LastWriteTime -ge $startTime.AddSeconds(-5)) } | ForEach-Object FullName)   # ohne Ordner paralleler Testlaeufe
$scanFiles = @(Get-ChildItem -LiteralPath $env:TEMP -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $startTime.AddSeconds(-5) -and $_.Length -lt 4MB })
foreach ($root in $scanRoots) { $scanFiles += @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 4MB }) }
foreach ($f in $scanFiles) {
    if (($f.Directory.Name -eq 'stubs' -and $f.Name -in 'ntdsutil.stdin.log', 'ntdsutil.out') -or $f.Extension -in '.exe', '.dll' -or $f.Name -eq 'ntdsutil.stdin.bin') { continue }   # Mitschrift und Attrappe des Stubs selbst
    try { if ([IO.File]::ReadAllText($f.FullName) -match [regex]::Escape($testPw)) { $hits.Add($f.FullName) } } catch { }
}
Check ('GEGENTEST: keine Datei im Testordner und im Temp-Ordner enthaelt das Kennwort (ausser der Mitschrift des Stubs selbst) ' + $(if ($hits.Count) { $hits -join ', ' })) ($hits.Count -eq 0)
$script:S.Reach['dc-new2.contoso.local'] = $false; ResetStubLogs
Check 'DSRM Variante B: anderer DC, nicht erreichbar -> kein Aufruf' ((Throws { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Dc 'dc-new2.contoso.local' -Confirmed }) -and (StubArgs 'ntdsutil').Count -eq 0)
$null = Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Dc 'dc-old.contoso.local' -Confirmed
Check 'DSRM Variante B: "reset password on server <DC>" fuer einen anderen DC' ((StubArgs 'ntdsutil') -contains 'set dsrm password|reset password on server dc-old.contoso.local|q|q')
Check 'DSRM Variante B: Servername mit Anfuehrungszeichen abgelehnt' (Throws { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Dc 'dc"x' -Confirmed })
$env:SM_STUB_EXIT_NTDSUTIL = '1'
$msg = ''; try { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed } catch { $msg = $_.Exception.Message }
$env:SM_STUB_EXIT_NTDSUTIL = $null
Check 'GEGENTEST: Fehlermeldung bei Exitcode 1 enthaelt das Kennwort nicht (Ausgabe wird nicht angezeigt), Protokoll "fehlgeschlagen"' ($msg -match 'Exitcode 1' -and $msg -notmatch [regex]::Escape($testPw) -and (AuditText) -match 'DSRM-Kennwort setzen \| .*fehlgeschlagen' -and (AuditText) -notmatch [regex]::Escape($testPw))
ClearStub 'ntdsutil'

# ---- DSRM: Erfolgsmeldung, Timeout, Warnungen, Kennwortpfad ohne Pipeline und Cmdlet
$script:SmAdNtdsutilTimeoutSec = 60
function Try-Msg([scriptblock]$B) { try { & $B | Out-Null; '' } catch { $_.Exception.Message } }
ResetState; ResetStubLogs; GoodRepl
SetStub 'ntdsutil' "ntdsutil: set dsrm password`r`nReset DSRM Administrator Password: sync from domain account svc-dsrm`r`n"
$msg = Try-Msg { Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed }
Check 'DSRM Sync: Exitcode 0 aber ohne Erfolgsmeldung -> Fehler (Protokoll "fehlgeschlagen")' ($msg -match 'nicht bestaetigt' -and $msg -match 'keine Erfolgsmeldung' -and (AuditText) -match 'DSRM mit Domaenenkonto synchronisieren \| .*fehlgeschlagen')
SetStub 'ntdsutil' "Das Kennwort wurde erfolgreich festgelegt.`r`n"
$ok = Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed
Check 'DSRM Sync: deutsche Erfolgsmeldung wird erkannt' ($ok.Detail -match 'Erfolgsmeldung erkannt')
SetStub 'ntdsutil' "Password has been set successfully.`r`n"
Check 'DSRM Sync: englische Erfolgsmeldung wird erkannt' ((Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed).Detail -match 'Erfolgsmeldung erkannt')
$env:SM_STUB_EXIT_NTDSUTIL = '1'
$msg = Try-Msg { Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed }
$env:SM_STUB_EXIT_NTDSUTIL = $null
Check 'DSRM Sync: Erfolgsmeldung aber Exitcode 1 -> Fehler' ($msg -match 'Exitcode 1')
# Warnungen fuer das Konto
$script:S.UserEnabled = $false; $script:S.UserGroups = @()
$w0 = Get-SmAdDsrmAccountWarnings -Account 'svc-dsrm'
Check 'DSRM Sync: deaktiviertes Konto ohne privilegierte Gruppen -> keine Warnung' ($w0.Warnings.Count -eq 0 -and -not $w0.Enabled)
$script:S.UserEnabled = $true
$w1 = Get-SmAdDsrmAccountWarnings -Account 'svc-dsrm'
Check 'DSRM Sync: aktiviertes Konto (normale Anmeldung) -> deutliche Warnung mit Empfehlung "eigenes Konto"' (($w1.Warnings -join ' ') -match 'aktiviert' -and ($w1.Warnings -join ' ') -match 'Der Kontoname sollte auf ein eigenes Konto zeigen')
$script:S.UserEnabled = $false; $script:S.UserGroups = @('S-1-5-21-1-2-3-512', 'S-1-5-32-551')
$w2 = Get-SmAdDsrmAccountWarnings -Account 'svc-dsrm'
Check 'DSRM Sync: Mitglied von Domain Admins und Sicherungs-Operatoren (auch verschachtelt ueber tokenGroups) -> Warnung nennt die Gruppen' (($w2.Warnings -join ' ') -match 'privilegierter Gruppen' -and ($w2.Warnings -join ' ') -match 'Domain Admins' -and ($w2.Warnings -join ' ') -match 'Sicherungs-Operatoren' -and $w2.PrivilegedGroups.Count -eq 2)
$script:S.UserEnabled = $true
$null = Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed
Check 'DSRM Sync: die Warnung steht im Protokoll' ((AuditText) -match 'DSRM mit Domaenenkonto synchronisieren \| .*erfolgreich \| .*WARNUNG')
Check 'DSRM Sync: Kontoname mit Sonderzeichen oder fehlendes Konto -> Fehler' ((Throws { Get-SmAdDsrmAccountWarnings -Account 'a" b' }) -and (Throws { Get-SmAdDsrmAccountWarnings -Account 'gibtsnicht' }))
$script:S.UserEnabled = $false; $script:S.UserGroups = @()
# Variante B: Erfolgsmeldung Pflicht, Statuszeile bereinigt, Timeout
$sec = ConvertTo-SecureString $testPw -AsPlainText -Force; $sec2 = ConvertTo-SecureString $testPw -AsPlainText -Force
SetStub 'ntdsutil' "ntdsutil: set dsrm password`r`nPlease type password for DS Restore Mode Administrator Account: $testPw`r`nConfirm new password: $testPw`r`n"
$msg = Try-Msg { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed }
Check 'DSRM Variante B: Exitcode 0 ohne Erfolgsmeldung -> Fehler, Meldung ohne Kennwort, Hinweis auf Synchronisieren' ($msg -match 'nicht bestaetigt' -and $msg -match 'Synchronisieren' -and $msg -notmatch [regex]::Escape($testPw) -and (AuditText) -match 'DSRM-Kennwort setzen \| .*fehlgeschlagen' -and (AuditText) -notmatch [regex]::Escape($testPw))
SetStub 'ntdsutil' ("Fehler 0x80070005: Zugriff verweigert`r`nerror while echoing $testPw`r`n")
$msg = Try-Msg { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed }
Check 'DSRM Variante B: Statuszeile nur bereinigt (Fehlerkennung ja, Zeile mit dem Kennwort nie)' ($msg -match '0x80070005' -and $msg -notmatch [regex]::Escape($testPw))
SetStub 'ntdsutil' "Das Kennwort wurde erfolgreich festgelegt.`r`nPlease type password for DS Restore Mode Administrator Account: $testPw`r`n"
$okr = Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed
Check 'DSRM Variante B: Erfolgsmeldung (deutsch) -> Erfolg, Rueckgabe und Protokoll ohne Kennwort' ($okr.Detail -match 'Erfolgsmeldung' -and (($okr | Out-String) -notmatch [regex]::Escape($testPw)) -and (AuditText) -notmatch [regex]::Escape($testPw))
SetStub 'ntdsutil' "Password has been set successfully.`r`n"
Check 'DSRM Variante B: Erfolgsmeldung (englisch) -> Erfolg' ((Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed).Detail -match 'Erfolgsmeldung')
ClearStub 'ntdsutil'
$env:SM_STUB_SLEEP_NTDSUTIL = '20000'; $script:SmAdNtdsutilTimeoutSec = 2
$sw = [Diagnostics.Stopwatch]::StartNew()
$msg = Try-Msg { Invoke-SmAdDsrmReset -Password $sec -Confirm $sec2 -Confirmed }
$sw.Stop()
$env:SM_STUB_SLEEP_NTDSUTIL = $null; $script:SmAdNtdsutilTimeoutSec = 60
Start-Sleep -Milliseconds 300
$stubPath = (Join-Path $stubDir 'ntdsutil.exe')
$left = @(Get-Process -Name ntdsutil -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq $stubPath } catch { $false } })
Check 'DSRM Variante B: haengt ntdsutil -> nach dem Timeout beendet, klare Meldung "Variante Synchronisieren nutzen", Protokoll "fehlgeschlagen"' ($msg -match 'nimmt das Kennwort hier nicht an' -and $msg -match 'Variante Synchronisieren nutzen' -and $sw.Elapsed.TotalSeconds -lt 15 -and $left.Count -eq 0 -and (AuditText) -match 'DSRM-Kennwort setzen \| .*fehlgeschlagen')
$left | ForEach-Object { try { $_.Kill() } catch { } }   # nur der eigene Stub, falls doch uebrig
Check 'DSRM: Standard-Timeout 60 s (Quelltext), Hinweis "Variante B im Labor pruefen" im Tool' (($srcAd -match 'SmAdNtdsutilTimeoutSec = 60') -and ((Get-Content -LiteralPath (Join-Path $repo 'UI\AdServer.xaml') -Raw -Encoding UTF8) -match 'Variante B muss im Labor geprüft werden'))
# Komplexitaet: Zeichenarten und Sonderfaelle
Check 'DSRM Komplexitaet (for-Schleife): Faelle' ((Test-SmAdPasswordComplexity (ConvertTo-SecureString 'Abcdefgh1234' -AsPlainText -Force)).Ok -and (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'ABCDEFGH1234!' -AsPlainText -Force)).Ok -and -not (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'abcdefghijkl' -AsPlainText -Force)).Ok -and -not (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'Abcdefg1234' -AsPlainText -Force)).Ok -and -not (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'Abcdefgh12"4' -AsPlainText -Force)).Ok -and -not (Test-SmAdPasswordComplexity (ConvertTo-SecureString "Abcdefgh12'4" -AsPlainText -Force)).Ok -and (Test-SmAdPasswordComplexity (ConvertTo-SecureString 'abcdefgh12!?' -AsPlainText -Force)).Ok)
Check 'Hilfsfunktion Kennwort im Text: gefunden, nicht gefunden, zu kurz' ((Test-SmAdSecretInText -Secret $sec -Text "x $testPw y") -and -not (Test-SmAdSecretInText -Secret $sec -Text 'nichts hier') -and -not (Test-SmAdSecretInText -Secret $sec -Text 'kurz'))
# Quelltext: Kennwortpfad ohne Pipeline und ohne Cmdlet
$astAd = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'server\SmAdServer.ps1'), [ref]$null, [ref]$null)
function FnAst([string]$Name) { $astAd.Find({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $Name }, $true) }
foreach ($fn in 'Test-SmAdPasswordComplexity', 'Test-SmAdSecureEqual', 'Test-SmAdSecretInText') {
    $f = FnAst $fn
    $cmds = @($f.FindAll({ param($a) $a -is [Management.Automation.Language.CommandAst] }, $true))
    $pipes = @($f.FindAll({ param($a) $a -is [Management.Automation.Language.PipelineAst] -and $a.PipelineElements.Count -gt 1 }, $true))
    $txt = $f.Extent.Text
    Check "Kennwortpfad $fn : kein Cmdlet-Aufruf, keine Pipeline, kein -match/-like/-replace/-split/-in/-contains, keine Umwandlung in Text" ($f -and $cmds.Count -eq 0 -and $pipes.Count -eq 0 -and $txt -notmatch '(?i)-(match|notmatch|like|notlike|replace|split|in|notin|contains|notcontains)\b' -and $txt -notmatch '(?i)PtrToString|ConvertFrom-SecureString|GetNetworkCredential|\[string\]\s*\$(chars|ca|cb|plain|clear)|\.ToString\(')
}
foreach ($fn in 'Invoke-SmAdProcess', 'Invoke-SmAdDsrmReset', 'Get-SmAdNtdsutilResult', 'Test-SmAdPasswordComplexity', 'Test-SmAdSecureEqual', 'Test-SmAdSecretInText') {
    $f = FnAst $fn
    $bad = @($f.FindAll({ param($a) $a -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.FindAll({ param($v) $v -is [Management.Automation.Language.VariableExpressionAst] -and $v.VariablePath.UserPath -in 'chars', 'bstr', 'ca', 'cb', 'plain', 'clear' }, $true) })
    Check "Kennwortpfad $fn : Klartext (Zeichenfeld/BSTR) wird an kein Cmdlet gebunden; nur SecureString" ($f -and $bad.Count -eq 0 -and $f.Extent.Text -notmatch '(?i)PtrToString|ConvertFrom-SecureString|GetNetworkCredential')
}
$allCmd = @($astAd.FindAll({ param($a) $a -is [Management.Automation.Language.CommandAst] }, $true) | Where-Object {
        $cmd = $_
        $argText = (@($cmd.CommandElements | Where-Object { $_ -isnot [Management.Automation.Language.ScriptBlockExpressionAst] } | ForEach-Object { $_.Extent.Text }) -join ' ')
        $argText -match '(?i)\$(Password|Confirm|Secret|p1|p2)' -and $cmd.GetCommandName() -notin 'Test-SmAdPasswordComplexity', 'Test-SmAdSecureEqual', 'Test-SmAdSecretInText', 'Invoke-SmAdProcess', 'Invoke-SmAdDsrmReset', 'Get-SmAdNtdsutilResult' -and $cmd.Extent.Text -notmatch '^&' })
Check ('Kennwortpfad im ganzen Quelltext: SecureString geht nur an die genannten Funktionen, sonst an kein Cmdlet ' + (($allCmd | ForEach-Object { $_.Extent.Text.Substring(0, [math]::Min(50, $_.Extent.Text.Length)) }) -join ' | ')) ($allCmd.Count -eq 0)
# SecureStrings der Oberflaeche werden freigegeben (auch im Fehlerfall)
Check 'Oberflaeche: $p1 und $p2 werden per Dispose freigegeben (Hintergrundauftrag am Ende, sonst im finally) und der Auftrag ruft die Aufraeumung vor der Fehlerbehandlung' (($srcAd -match '\{ \$p1\.Dispose\(\); \$p2\.Dispose\(\) \}') -and ($srcAd -match 'finally \{\s*if \(-not \$handedOver\) \{ \$p1\.Dispose\(\); \$p2\.Dispose\(\) \}') -and ($srcAd -match 'if \(\$job\.Cleanup\) \{ try \{ & \$job\.Cleanup \} catch \{ \} \}[^\r\n]*\s+if \(\$err\)'))

# ---------------------------------------------------------------- 10. Funktionsebenen anheben (doppelte Bestaetigung)
ResetState; ResetStubLogs; GoodRepl
Check 'Ebene: ein DC mit 2016 -> Forest 2025 blockiert, Set-ADForestMode nicht aufgerufen' (($script:S.Dcs[1].OperatingSystem = 'Windows Server 2016 Standard') -and (ThrowsLike { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'contoso.local' -Confirmed } 'Vorpruefung') -and $script:S.Modes.Count -eq 0)
$script:S.Dcs[1].OperatingSystem = 'Windows Server 2025 Standard'; $script:S.DomainMode = 'Windows2025Domain'
Check 'Ebene: ohne Bestaetigung, ohne/mit falschem getippten Namen keine Aktion' ((Throws { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'contoso.local' }) -and (ThrowsLike { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -Confirmed } 'getippte') -and (ThrowsLike { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'fabrikam.com' -Confirmed } 'getippte') -and $script:S.Modes.Count -eq 0)
SetStub 'repadmin.replsummary' $badSummary
Check 'Ebene: Replikationsfehler blockiert' ((ThrowsLike { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'contoso.local' -Confirmed } 'Vorpruefung') -and $script:S.Modes.Count -eq 0)
GoodRepl; $script:S.Sids = @('S-1-5-21-1-2-3-512')
Check 'Ebene: Forest braucht Enterprise Admins' ((ThrowsLike { Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'contoso.local' -Confirmed } 'Rechte') -and $script:S.Modes.Count -eq 0)
$script:S.Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518')
$x = Invoke-SmAdRaiseLevel -Scope Forest -Target 10 -TypedName 'CONTOSO.local' -Confirmed
$m = $script:S.Modes[0]
Check 'Ebene: Set-ADForestMode -ForestMode Windows2025Forest -Server <Schemamaster>, ohne Rueckfrage (Confirm false)' ($script:S.Modes.Count -eq 1 -and $m.Kind -eq 'Forest' -and $m.Mode -eq 'Windows2025Forest' -and $m.Server -eq 'dc-old.contoso.local')
Check 'Ebene: Nachpruefung und Protokollzeile (von 2016 auf 2025)' ($x.After -eq 10 -and $x.Before -eq 7 -and (AuditText) -match 'Funktionsebene anheben \(Forest\) \| .*erfolgreich' -and (AuditText) -match 'von Windows Server 2016 auf Windows Server 2025')
$script:S.DomainMode = 'Windows2012R2Domain'; $script:S.Modes.Clear()
$x = Invoke-SmAdRaiseLevel -Scope Domain -Target 7 -TypedName 'contoso.local' -Confirmed
Check 'Ebene: Set-ADDomainMode -DomainMode Windows2016Domain -Server <PDC-Emulator>' ($script:S.Modes.Count -eq 1 -and $script:S.Modes[0].Kind -eq 'Domain' -and $script:S.Modes[0].Mode -eq 'Windows2016Domain' -and $script:S.Modes[0].Server -eq 'dc-old.contoso.local' -and $x.After -eq 7)

# ---------------------------------------------------------------- 11. adprep (nur Installationsmedium, geprueft in gehaerteter Kopie)
ResetState; ResetStubLogs; GoodRepl
$script:S.Schema = $localFqdn; $script:S.Infra = $localFqdn
$adDir = Join-Path $dataRoot 'AD'
function CopyDirs { @(Get-ChildItem -LiteralPath $adDir -Directory -Filter 'adprep-*' -ErrorAction SilentlyContinue) }
$mi = Get-SmAdAdprepMedia -MediaPath $media
Check 'adprep: Medium (Laufwerk vom Typ CD-ROM) erkannt, support\adprep\adprep.exe, Version wird angezeigt' ($mi.Path -like '*support\adprep\adprep.exe' -and $mi.Version -and $mi.Root)
Check 'adprep: Pfad mit Anfuehrungszeichen, relativ, Unterordner oder Ordner ohne CD-ROM abgelehnt' ((Throws { Get-SmAdAdprepMedia -MediaPath ($media + '" /x') }) -and (Throws { Get-SmAdAdprepMedia -MediaPath '..\media' }) -and (Throws { Get-SmAdAdprepMedia -MediaPath $work }) -and (Throws { Get-SmAdAdprepMedia -MediaPath (Join-Path $media 'support') }))
$script:SmAdCdRomRoots = $null
Check 'adprep: echte Laufwerksliste: UNC, Festplatte C:\ und beliebiger Ordner abgelehnt (nur CD-ROM-Laufwerk)' ((ThrowsLike { Get-SmAdAdprepMedia -MediaPath '\\server\share\iso' } 'Installationsmedium') -and (ThrowsLike { Get-SmAdAdprepMedia -MediaPath 'C:\' } 'CD-ROM|Installationsmedium') -and (ThrowsLike { Get-SmAdAdprepMedia -MediaPath $media } 'Installationsmedium') -and -not (@(Get-SmAdCdRomRoots) -contains 'C:\'))
$script:SmAdCdRomRoots = @($media)
Check 'adprep: ohne Bestaetigung nichts' ((Throws { Invoke-SmAdAdprep -MediaPath $media -Phase Forest }) -and (StubArgs 'adprep').Count -eq 0)
Check 'adprep: UNC-Pfad als Quelle -> nichts gestartet, nichts kopiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath '\\server\share' -Phase Forest -Confirmed } 'Vorpruefung') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
$script:S.Schema = 'dc-old.contoso.local'
Check 'adprep /forestprep: nicht auf dem Schemamaster -> blockiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Vorpruefung') -and (StubArgs 'adprep').Count -eq 0)
$script:S.Schema = $localFqdn; $script:S.Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519')
Check 'adprep /forestprep: ohne Schema Admins -> blockiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Vorpruefung') -and (StubArgs 'adprep').Count -eq 0)
$script:S.Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518')
SetStub 'repadmin.replsummary' $badSummary
Check 'adprep: Replikationsfehler -> blockiert VOR dem Kopieren (kein adprep-Ordner angelegt)' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Vorpruefung') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
GoodRepl
$script:S.Signed = $false
Check 'adprep: adprep.exe ohne gueltige Microsoft-Signatur -> in der Kopie blockiert, nichts gestartet, Kopie geloescht' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Pruefung der Kopie.*Signatur') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
$script:S.Signed = $true; $script:S.OrigName = 'evil.exe'
Check 'adprep: VersionInfo.OriginalFilename ist nicht adprep.exe -> blockiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'urspruengliche Dateiname') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
$script:S.OrigName = 'adprep.exe'
# andere signierbare Datei (dll) nicht von Microsoft -> blockiert; adprep.exe selbst ist ok
function Test-SmAdMicrosoftSigned { param([string]$Path, [string[]]$CommonNames) if ($Path -like '*adprepcore.dll') { $false } else { $script:S.Signed } }
Check 'adprep: eine andere signierbare Datei (dll) ohne Microsoft-Signatur -> blockiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'adprepcore.dll') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
function Test-SmAdMicrosoftSigned { param([string]$Path, [string[]]$CommonNames) [void]$script:S.SignedCalls.Add(('{0}|{1}' -f (Split-Path -Leaf $Path), ($CommonNames -join ','))); $script:S.Signed }
$script:S.SignedCalls = New-Object System.Collections.ArrayList
# Kopie weicht von der Quelle ab (Austausch zwischen Kopieren und Pruefen) -> blockiert
$origCopyTree = ${function:Copy-SmAdAdprepTree}
$script:CorruptCopy = $false
function Copy-SmAdAdprepTree { param([string]$Source, [string]$Dest) $r = @(& $origCopyTree -Source $Source -Dest $Dest); if ($script:CorruptCopy) { $r[0].SourceHash = ("0" * 64) }; $r }
$script:CorruptCopy = $true
Check 'adprep: Kopie weicht vom Hash der Quelle ab -> blockiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'weicht von der Quelle ab') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
$script:CorruptCopy = $false
# Verknuepfung (Junction) im Quellordner -> abgebrochen
$junction = Join-Path $media 'support\adprep\evil'
$null = & cmd.exe /c mklink /J "`"$junction`"" "`"$work`"" 2>&1
if (Test-Path -LiteralPath $junction) {
    Check 'adprep: Verknuepfung (Junction) im Quellordner -> abgebrochen, nichts kopiert' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Verknuepfung') -and (StubArgs 'adprep').Count -eq 0 -and (CopyDirs).Count -eq 0)
    $null = & cmd.exe /c rmdir "`"$junction`"" 2>&1
}
else { Write-Host 'INFO Junction konnte nicht angelegt werden, Test uebersprungen' -ForegroundColor Yellow }
GoodRepl; $script:S.SchemaQueue = @(88, 91); ResetStubLogs
SetStub 'adprep' "Adprep successfully updated the forest-wide information.`r`n"
$a = Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed
Check 'adprep /forestprep: Aufruf mit genau /forestprep, Rueckfrage mit C beantwortet' ((StubArgs 'adprep') -contains '/forestprep' -and (StubIn 'adprep') -match '(?m)^C\s*$')
$ranFrom = (Get-Content -LiteralPath (Join-Path $stubDir 'adprep.path.log') -Raw).Trim()
Check 'adprep: gestartet wird nur die Kopie unter AD\adprep-<GUID>, nicht das Medium' ($ranFrom -match '\\AD\\adprep-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\adprep\.exe$' -and $ranFrom -notlike "$media*")
Check 'adprep: danach ist die Kopie aufgeraeumt' ((CopyDirs).Count -eq 0)
Check 'adprep: Schema-Version vorher 88, nachher 91, Ausgabe in Datei und Protokoll' ($a.Before -eq 88 -and $a.After -eq 91 -and (Test-Path -LiteralPath $a.LogFile) -and (Get-Content -LiteralPath $a.LogFile -Raw) -match 'forest-wide' -and (AuditText) -match 'adprep /forestprep \| .*erfolgreich \| Schema-Version 88 -> 91')
$ldfHash = (Get-FileHash -LiteralPath (Join-Path $media 'support\adprep\sch91.ldf') -Algorithm SHA256).Hash
Check 'adprep: SHA256 der .ldf-Datei wird protokolliert (nicht signierbar) und in der Rueckgabe gezeigt' ((AuditText) -match ('adprep Datei \| sch91\.ldf \| sha256 \| ' + $ldfHash + ' \(nicht signierbar\)') -and (@($a.Files | Where-Object { $_.Rel -eq 'sch91.ldf' -and $_.Sha256 -eq $ldfHash -and $null -eq $_.Signed }).Count -eq 1) -and (Format-SmAdAdprepFiles ([pscustomobject]@{ Files = $a.Files })) -match 'Nur ein originales Microsoft-ISO verwenden')
Check 'adprep: auch Unterordner-Dateien (en-US\...) kopiert und mit Hash protokolliert, exe/dll mit Signaturpruefung (adprep.exe nur CN Microsoft Windows)' ((AuditText) -match 'adprep Datei \| en-US\\adprep\.exe\.mui \| sha256' -and ($script:S.SignedCalls -contains 'adprep.exe|Microsoft Windows') -and ($script:S.SignedCalls -contains 'adprepcore.dll|Microsoft Windows,Microsoft Corporation'))
$a2 = Invoke-SmAdAdprep -MediaPath $media -Phase Domain -Confirmed
Check 'adprep /domainprep: Aufruf mit /domainprep auf dem Infrastrukturmaster' ((StubArgs 'adprep') -contains '/domainprep')
$script:S.Infra = 'dc-old.contoso.local'
Check 'adprep /domainprep: nicht auf dem Infrastrukturmaster -> blockiert' (ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Domain -Confirmed } 'Vorpruefung')
$script:S.Infra = $localFqdn; $env:SM_STUB_EXIT_ADPREP = '1'; ResetStubLogs
Check 'adprep: Exitcode 1 -> Fehler und Protokollzeile "fehlgeschlagen", Kopie trotzdem aufgeraeumt' ((ThrowsLike { Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed } 'Exitcode 1') -and (AuditText) -match 'adprep /forestprep \| .*fehlgeschlagen' -and (CopyDirs).Count -eq 0)
$env:SM_STUB_EXIT_ADPREP = $null
# Dateien der Kopie bleiben bis zum Ende offen (FileShare.Read): kein Schreiben, kein Loeschen, kein Umbenennen, Lesen geht
$lock = @{}
$null = Invoke-SmAdWithAdprepCopy -MediaRoot $media -Body {
    param($ck, $dir)
    $f = Join-Path $dir 'sch91.ldf'
    $lock.Write = $false; $lock.Delete = $false; $lock.Rename = $false; $lock.Read = $false
    try { $s = [IO.File]::Open($f, 'Open', 'ReadWrite', 'ReadWrite'); $s.Dispose(); $lock.Write = $true } catch { }
    try { [IO.File]::Delete($f); $lock.Delete = (-not (Test-Path -LiteralPath $f)) } catch { }
    try { Rename-Item -LiteralPath (Join-Path $dir 'adprep.exe') -NewName 'x.exe' -ErrorAction Stop; $lock.Rename = $true } catch { }
    try { $s = [IO.File]::Open($f, 'Open', 'Read', 'Read'); $s.Dispose(); $lock.Read = $true } catch { }
    $lock.Dir = $dir
}
Check 'adprep: die Dateien der Kopie sind mit FileShare.Read gehalten (Schreiben, Loeschen, Umbenennen scheitern, Lesen geht)' (-not $lock.Write -and -not $lock.Delete -and -not $lock.Rename -and $lock.Read)
Check 'adprep: nach dem Ende sind die Handles frei und die Kopie geloescht' (-not (Test-Path -LiteralPath $lock.Dir) -and (CopyDirs).Count -eq 0)
# Probe-Kopie der Vorpruefung (Schaltflaeche Pruefen) zeigt Hashes und loescht
$pc = Test-SmAdAdprepPrecheck -MediaPath $media -Phase Forest -VerifyCopy
Check 'adprep: Vorpruefung mit Probe-Kopie liefert Dateiliste mit SHA256, loescht die Kopie, Hinweis auf Original-ISO' ($pc.Ok -and $pc.Copy.Files.Count -ge 4 -and (CopyDirs).Count -eq 0 -and (Format-SmAdChecks $pc.Checks) -match 'originales Microsoft-ISO')
# ---- Signatur-Pruefung selbst (echt, nicht gemockt)
Check 'DN: exakt geparst (CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US)' (Test-SmAdSignerSubject -Subject 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' -CommonNames @('Microsoft Windows'))
Check 'DN: Gegentests (falscher CN, O nur als Teil, zweites O, O im Anfuehrungszeichen-CN, mehrwertig, Kleinschreibung, leer)' (
    -not (Test-SmAdSignerSubject -Subject 'CN=Evil, O=Microsoft Corporation') -and
    -not (Test-SmAdSignerSubject -Subject 'CN=Microsoft Windows, O=Microsoft Corporation Evil') -and
    -not (Test-SmAdSignerSubject -Subject 'CN=Microsoft Windows, O=Evil, O=Microsoft Corporation') -and
    -not (Test-SmAdSignerSubject -Subject 'CN="Microsoft Windows, O=Microsoft Corporation"') -and
    -not (Test-SmAdSignerSubject -Subject 'CN=Microsoft Windows+O=Microsoft Corporation') -and
    -not (Test-SmAdSignerSubject -Subject 'CN=Microsoft Windows, OU=O=Microsoft Corporation') -and
    -not (Test-SmAdSignerSubject -Subject 'cn=microsoft windows, o=microsoft corporation') -and
    -not (Test-SmAdSignerSubject -Subject '') -and -not (Test-SmAdSignerSubject -Subject 'Quatsch') -and
    (Test-SmAdSignerSubject -Subject 'CN=Microsoft Corporation, O=Microsoft Corporation' -CommonNames @('Microsoft Windows', 'Microsoft Corporation')) -and
    -not (Test-SmAdSignerSubject -Subject 'CN=Microsoft Corporation, O=Microsoft Corporation' -CommonNames @('Microsoft Windows')))
Check 'Microsoft-Wurzeln: 40-stellige Thumbprints, Eintraege der lokalen Wurzelzertifikate "Microsoft Root Certificate Authority 20xx" sind in der Liste' ((@($script:SmAdMicrosoftRoots.Keys | Where-Object { $_ -notmatch '^[0-9A-F]{40}$' }).Count -eq 0) -and (@(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match '^CN=Microsoft Root Certificate Authority 20(10|11),' } | Where-Object { -not $script:SmAdMicrosoftRoots.ContainsKey($_.Thumbprint.ToUpperInvariant()) }).Count -eq 0))
Check 'Signatur echt: unsignierte Datei (Stub) -> nicht Microsoft-signiert' (-not (& $origSigned -Path $base))
$sysExe = Join-Path ([Environment]::GetFolderPath('System')) 'whoami.exe'
$sysInfo = Get-SmAdSignatureInfo -Path $sysExe
if ($sysInfo.Status -eq 'Valid') {
    Check ('Signatur echt: Windows-Programm (whoami.exe) -> Signer Microsoft Windows / Microsoft Corporation, Kette in Microsoft-Wurzel ' + $sysInfo.RootThumbprint) ((& $origSigned -Path $sysExe) -and -not (& $origSigned -Path $sysExe -CommonNames @('Anderer Name')))
}
else { Write-Host 'INFO whoami.exe nicht gueltig signiert gelesen, echter Signaturtest uebersprungen' -ForegroundColor Yellow }

# ---------------------------------------------------------------- 12. Allgemein: Modul fehlt, Erreichbarkeit, Protokoll ohne Geheimnisse
if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    $saved = ${function:Get-ADForest}; Remove-Item function:Get-ADForest
    $m2 = ''; try { Assert-SmAdModule } catch { $m2 = $_.Exception.Message }
    Set-Item function:Get-ADForest $saved
    Check 'AD-Modul fehlt: klare Meldung' ($m2 -match 'ActiveDirectory fehlt' -and $m2 -match 'RSAT')
}
else { Write-Host 'INFO AD-Modul vorhanden, Test "Modul fehlt" uebersprungen' -ForegroundColor Yellow }
Check 'Erreichbarkeit: ungueltiger Servername wird abgelehnt, localhost ist erreichbar' ((Throws { & $origReach -HostName 'a"b' }) -and (& $origReach -HostName 'localhost'))
Check 'Protokollzeilen: Zeit, Server, Benutzer, Aktion, Ziel, Ergebnis' ((AuditText) -match "\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \| $([regex]::Escape($env:COMPUTERNAME)) \| .+ \| FSMO Seize \| ")
Check 'Quelltext: Kennwort nie als Argument oder in Protokoll (keine Verkettung von Password in Arguments/Write-SmAdAudit)' ((Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw) -notmatch '(?i)Arguments\s*=\s*[^\r\n]*\$Password|Write-SmAdAudit[^\r\n]*\$Password|-Detail[^\r\n]*\$Password')
Check 'Quelltext: nur Protect-SmDnsStateDir fuer Ordner, keine eigene ACL-Kopie' (((Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw) -match 'Protect-SmDnsStateDir') -and ((Get-Content -LiteralPath (Join-Path $repo 'server\SmAdServer.ps1') -Raw) -notmatch 'SetAccessRuleProtection'))

# ---------------------------------------------------------------- 13. Fenster
foreach ($mode in 'Light', 'Dark') {
    foreach ($entry in @(@('Berater-Tool', 'Start-ServerMigration.ps1'), @('Server-Fenster', 'server\Start-SmServer.ps1'))) {
        $o = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $repo $entry[1]) -ParseOnly -Theme $mode 2>&1 | Out-String
        Check ("$($entry[0]) -ParseOnly ($mode) mit Seite Active Directory: $($o.Trim())") ($o.Trim() -eq 'PARSE OK')
    }
}
# ---------------------------------------------------------------- 12. Standardeingabe ohne BOM (Fehler: [Console]::InputEncoding mit UTF-8-BOM landete vor dem Text)
function HasBom([byte[]]$B) { $B.Length -ge 3 -and $B[0] -eq 0xEF -and $B[1] -eq 0xBB -and $B[2] -eq 0xBF }
function HexOf([byte[]]$B) { ($B | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' }
$oem = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
$umPw = 'Gegen-Test-K' + [char]0xE4 + 'se-7531!'
$umSec = ConvertTo-SecureString $umPw -AsPlainText -Force; $umSec2 = ConvertTo-SecureString $umPw -AsPlainText -Force
$expUm = $oem.GetBytes($umPw + "`r`n" + $umPw + "`r`n")
$origInEnc = $null; try { $origInEnc = [Console]::InputEncoding } catch { }
foreach ($mode in 'UTF8-BOM', 'Standard') {
    $applied = $true
    if ($mode -eq 'UTF8-BOM') { try { [Console]::InputEncoding = New-Object Text.UTF8Encoding($true) } catch { $applied = $false; Write-Host 'INFO Konsolen-Eingabekodierung nicht setzbar (keine Konsole)' -ForegroundColor Yellow } }
    try {
        if ($mode -eq 'UTF8-BOM' -and $applied) {
            Check 'BOM-Test: Vorbedingung, die Konsolen-Eingabekodierung hat wirklich eine Praeambel' (([Console]::InputEncoding.GetPreamble()).Length -eq 3)
        }
        ResetState; ResetStubLogs; GoodRepl
        SetStub 'ntdsutil' "Password has been set successfully.`r`n"
        $null = Invoke-SmAdDsrmSync -Account 'svc-dsrm' -Confirmed
        $bs = StubBytes 'ntdsutil'
        Check "BOM-Test [$mode]: ntdsutil Variante A (Sync) bekommt keine Bytes, kein BOM" ($bs.Length -eq 0)
        ResetStubLogs
        $null = Invoke-SmAdDsrmReset -Password $umSec -Confirm $umSec2 -Confirmed
        $bs = StubBytes 'ntdsutil'
        Check "BOM-Test [$mode]: ntdsutil Variante B (Kennwort) beginnt ohne BOM" (-not (HasBom $bs))
        Check "BOM-Test [$mode]: Kennwort mit Umlaut kommt zweimal als genau die OEM-Bytes (CP $($oem.CodePage)) an: $(HexOf $bs)" ((HexOf $bs) -eq (HexOf $expUm))
        $script:S.Schema = $localFqdn; $script:S.Infra = $localFqdn
        GoodRepl; $script:S.SchemaQueue = @(88, 91); ResetStubLogs
        SetStub 'adprep' "Adprep successfully updated the forest-wide information.`r`n"
        $null = Invoke-SmAdAdprep -MediaPath $media -Phase Forest -Confirmed
        $bs = StubBytes 'adprep'
        Check "BOM-Test [$mode]: adprep bekommt genau 'C' + Zeilenende, kein BOM: $(HexOf $bs)" ((HexOf $bs) -eq (HexOf $oem.GetBytes("C`r`n")))
    }
    finally { if ($mode -eq 'UTF8-BOM' -and $applied -and $origInEnc) { try { [Console]::InputEncoding = $origInEnc } catch { } } }
}
$bomSrc = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\server\SmAdServer.ps1') -Raw)
Check 'BOM-Test: Invoke-SmAdProcess schreibt nicht ueber StandardInput.Write/WriteLine (nur BaseStream)' ($bomSrc -notmatch '(?m)^[^#
]*StandardInput\.Write')
$script:SmAdCdRomRoots = @($media)
ClearStub 'ntdsutil'; ClearStub 'adprep'; ResetStubLogs
$pkgNames = $script:SmServerFiles
if (Get-Command New-SmServerPackage -ErrorAction SilentlyContinue) { }
$script:SmAdCdRomRoots = $null
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Active Directory: $script:fails Fehler"
exit $script:fails
