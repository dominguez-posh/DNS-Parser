#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer den Assistenten im Server-Fenster (server\SmAssistent.ps1, UI\ServerStart.xaml): Rollen erkennen, Schritte und Navigation,
    Vormerken (Whitelist, Ordner, SHA256), Sammeln ohne Hochladen (DNS, DHCP, AD mit nachgebauten Cmdlets), Hochladen gegen einen nachgebauten
    SharePoint (Teile, Fortschritt je Datei, veraenderte Datei wird nicht hochgeladen, ein Fehler stoppt die anderen nicht), Pruefsummen-Text,
    Oberflaeche (Namen, keine Symbolzeichen, Fenster mit Schrittzeilen und Dateiliste), und die Fehler der Klasse "leerer Wert aus echtem Cmdlet"
    bei DHCP, Print und AD.
    Wird von tests\Test-ServerMigration.ps1 aufgerufen (mit -Share und -Store des nachgebauten SharePoints) und liefert die Zahl der Fehler zurueck.
    Allein (ohne SharePoint, der Upload-Teil entfaellt): powershell.exe -NoProfile -STA -File tests\Test-Assistent.ps1
    Keine echten Server, keine echten Tenants. Beispieldaten nur mit contoso.local.
#>
[CmdletBinding()]
param([string]$Repo, [string]$Work, $Share, $Store)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
if (-not $Repo) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
if (-not $Work) { $Work = Join-Path $env:TEMP ('sm-assist-' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Force $Work | Out-Null }
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

. (Join-Path $Repo 'Modules\SmTausch.ps1')
. (Join-Path $Repo 'Modules\SmUi.ps1')
. (Join-Path $Repo 'server\SmDnsServer.ps1')
. (Join-Path $Repo 'Modules\SmDhcp.ps1')
. (Join-Path $Repo 'server\SmDhcpServer.ps1')
. (Join-Path $Repo 'Modules\SmPrint.ps1')
. (Join-Path $Repo 'server\SmPrintServer.ps1')
. (Join-Path $Repo 'Modules\SmAd.ps1')
. (Join-Path $Repo 'server\SmAdServer.ps1')
. (Join-Path $Repo 'server\SmAssistent.ps1')
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:SmDnsStateSidsOverride = @('S-1-5-32-544', 'S-1-5-18', $mySid)   # der Testlauf selbst darf in die gehaerteten Ordner schreiben
$root = Join-Path $Work 'as-root'
function Set-TestEnv { $script:SmAsDataRoot = $root; $script:SmPrintDataRoot = $root; $script:SmAdDataRoot = $root; $script:SmDhcpAuditPath = Join-Path $root 'dhcp-audit.log' }   # nach jedem erneuten Laden der Module (setzt die Werte zurueck)
Set-TestEnv
function U([int[]]$Codes) { -join ($Codes | ForEach-Object { [char]$_ }) }

# ---------------------------------------------------------------- 1. Dateien
foreach ($f in 'server\SmAssistent.ps1', 'UI\ServerStart.xaml') {
    $b = [IO.File]::ReadAllBytes((Join-Path $Repo $f))
    Check "Kodierung UTF-8 mit BOM (Umlaute): $f" ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
$pak = Get-Content -LiteralPath (Join-Path $Repo 'Modules\SmPaket.ps1') -Raw
Check 'Server-Paket enthaelt server/SmAssistent.ps1 und UI/ServerStart.xaml (sonst fehlen sie auf dem Kundenserver)' ($pak.Contains("'server/SmAssistent.ps1'") -and $pak.Contains("'UI/ServerStart.xaml'"))

# ---------------------------------------------------------------- 2. Rollen erkennen
function Get-SmAsServiceNames { $script:MockSvc }
function Get-SmPrintRoleInstalled { $script:MockPrint }
$script:MockSvc = @('DNS', 'DHCPServer', 'NTDS'); $script:MockPrint = $true
$r = Get-SmAsRoles
Check 'Rollen: DNS, DHCP, Druckserver, DC erkannt' ($r.Dns -and $r.Dhcp -and $r.Print -and $r.Ad)
$script:MockSvc = @('DNS'); $script:MockPrint = $false
$r = Get-SmAsRoles
Check 'Rollen: nur DNS (der Spooler allein macht keinen Druckserver, NTDS fehlt = kein DC)' ($r.Dns -and -not $r.Dhcp -and -not $r.Print -and -not $r.Ad)
$script:MockSvc = @('Spooler'); $script:MockPrint = $false
Check 'Rollen: nichts installiert' (-not (Get-SmAsRoles).Dns -and -not (Get-SmAsRoles).Dhcp -and -not (Get-SmAsRoles).Ad)
function Get-SmPrintRoleInstalled { throw 'kein Windows-Feature-Modul' }
$script:MockSvc = @('DHCPServer')
$r = Get-SmAsRoles
Check 'Rollen: ein Fehler bei der Druck-Erkennung zaehlt als nicht installiert, die anderen bleiben' ($r.Dhcp -and -not $r.Print)
Remove-Item Function:\Get-SmAsServiceNames, Function:\Get-SmPrintRoleInstalled
Check 'Rollen: Aufruf mit den echten Cmdlets wirft nicht und liefert vier Werte' ($(try { $x = Get-SmAsRoles; ($x.PSObject.Properties.Name -join ',') -eq 'Dns,Dhcp,Print,Ad' } catch { $false }))
. (Join-Path $Repo 'server\SmPrintServer.ps1')   # Get-SmPrintRoleInstalled wieder echt
Set-TestEnv

# ---------------------------------------------------------------- 3. Schritte und Navigation
$st = New-SmAsState
Check 'Schritte: Reihenfolge Check, Dns, Dhcp, Print, Ad, Upload, alle offen, Start bei Check' ((@($st.Steps.Keys) -join ',') -eq 'Check,Dns,Dhcp,Print,Ad,Upload' -and -not (@($st.Steps.Values | Where-Object State -ne 'Open').Count) -and $st.Current -eq 'Check')
Set-SmAsRoles -State $st -Roles ([pscustomobject]@{ Dns = $true; Dhcp = $false; Print = $true; Ad = $false })
Check 'Rollen setzen: DHCP und AD nicht installiert, DNS und Print offen' ($st.Steps['Dhcp'].State -eq 'NotInstalled' -and $st.Steps['Ad'].State -eq 'NotInstalled' -and $st.Steps['Dns'].State -eq 'Open' -and $st.Steps['Print'].State -eq 'Open' -and $st.Steps['Check'].State -eq 'Open')
Check 'Navigation: Weiter ueberspringt nicht installierte Schritte (Check, Dns, Print, Upload)' ((Get-SmAsNavTarget -State $st -Direction Next -From 'Check') -eq 'Dns' -and (Get-SmAsNavTarget -State $st -Direction Next -From 'Dns') -eq 'Print' -and (Get-SmAsNavTarget -State $st -Direction Next -From 'Print') -eq 'Upload' -and $null -eq (Get-SmAsNavTarget -State $st -Direction Next -From 'Upload'))
Check 'Navigation: Zurueck ueberspringt ebenso, vor dem ersten Schritt gibt es keinen' ((Get-SmAsNavTarget -State $st -Direction Back -From 'Upload') -eq 'Print' -and (Get-SmAsNavTarget -State $st -Direction Back -From 'Print') -eq 'Dns' -and $null -eq (Get-SmAsNavTarget -State $st -Direction Back -From 'Check'))
$st.Current = 'Dns'
$nx = Skip-SmAsStep -State $st
Check 'Ueberspringen: Schritt wird "Skipped", der naechste ist Print' ($st.Steps['Dns'].State -eq 'Skipped' -and $nx -eq 'Print')
Set-SmAsStepState -State $st -Key 'Print' -Value Done -Detail 'x'
$st.Current = 'Print'
[void](Skip-SmAsStep -State $st)
Check 'Ueberspringen: ein erledigter Schritt bleibt erledigt' ($st.Steps['Print'].State -eq 'Done')
$st.Current = 'Upload'
Check 'Ueberspringen: der Upload-Schritt laesst sich nicht ueberspringen' ($null -eq (Skip-SmAsStep -State $st) -and $st.Steps['Upload'].State -eq 'Open')
Set-SmAsStepState -State $st -Key 'Check' -Value Running; $st.Current = 'Check'
Check 'Ueberspringen: ein laufender Schritt wirft' (Throws { Skip-SmAsStep -State $st })
Check 'Zustaende: Texte offen, laeuft, erledigt, uebersprungen, Fehler, nicht installiert' ((@('Open', 'Running', 'Done', 'Skipped', 'Error', 'NotInstalled') | ForEach-Object { Get-SmAsStateText $_ }) -join ',' -eq ('offen,l' + (U 228) + 'uft,erledigt,' + (U 252) + 'bersprungen,Fehler,nicht installiert') -and (Throws { Get-SmAsStateText 'Quatsch' }))
Set-SmAsRoles -State $st -Roles ([pscustomobject]@{ Dns = $true; Dhcp = $true; Print = $true; Ad = $true })
Check 'Rollen setzen: eine nachtraeglich installierte Rolle macht den Schritt wieder offen' ($st.Steps['Dhcp'].State -eq 'Open' -and $st.Steps['Ad'].State -eq 'Open')
Check 'Zustand setzen: unbekannter Schritt wirft' (Throws { Set-SmAsStepState -State $st -Key 'Nix' -Value Done })

# ---------------------------------------------------------------- 4. Schritt 1: Server pruefen
function Test-SmAdmin { $script:IsAdmin }
$script:IsAdmin = $true
$ck = Get-SmAsCheck -ShareConnected $true -Roles ([pscustomobject]@{ Dns = $true; Dhcp = $false; Print = $false; Ad = $false }) -FreeBytes 50GB
Check 'Pruefung: Admin, Rollen, Tauschordner, Platz (vier Punkte), alles ok' (@($ck.Items).Count -eq 4 -and $ck.Ok -and (@($ck.Items.Name) -join ',') -eq 'Administrator,Rollen,Tauschordner,Freier Platz' -and $ck.Items[1].Text -match 'DNS')
$script:IsAdmin = $false
$ck = Get-SmAsCheck -ShareConnected $false -Roles ([pscustomobject]@{ Dns = $false; Dhcp = $false; Print = $false; Ad = $false }) -FreeBytes 100MB
Check 'Pruefung: ohne Admin, ohne Rollen, ohne Tauschordner und mit wenig Platz sind alle vier Punkte nicht ok' ($ck.Ok -eq $false -and @($ck.Items | Where-Object { -not $_.Ok }).Count -eq 4)
$script:IsAdmin = $true
$ck = Get-SmAsCheck -ShareConnected $true -Roles ([pscustomobject]@{ Dns = $true; Dhcp = $false; Print = $false; Ad = $false })
Check 'Pruefung: freier Platz wird ohne Vorgabe vom Laufwerk gelesen (Text mit Groesse)' ($ck.Items[3].Text -match 'frei')

# ---------------------------------------------------------------- 5. Vormerken
$printDir = Join-Path $root 'Print'; $adDir = Join-Path $root 'AD'
New-Item -ItemType Directory -Force $printDir, $adDir | Out-Null
$st = New-SmAsState
$stage = New-SmAsStageDir
Check 'Sammelordner: unter ProgramData\ServerMigration\Assistent\Sammlung-<GUID>, gehaertet' ($stage -match '\\Assistent\\Sammlung-[0-9a-f]{32}$' -and $stage.StartsWith([IO.Path]::GetFullPath($root)) -and @(Test-SmDnsStateDirAcl -Path $stage).Count -eq 0)
Check 'Sammelordner: nie unter %TEMP%' (-not $stage.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase))
$st.StageDir = $stage
$f1 = Join-Path $stage 'SM-DNS-SRV01-20261122-100000.zip'; [IO.File]::WriteAllBytes($f1, [byte[]](1..200))
$it = Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $f1
Check 'Vormerken: Name, Groesse, SHA256 (stimmt mit Get-FileHash), ausgewaehlt' ($it.Name -eq 'SM-DNS-SRV01-20261122-100000.zip' -and $it.Length -eq 200 -and $it.Sha256 -eq (Get-FileHash -LiteralPath $f1 -Algorithm SHA256).Hash -and $it.Selected -and $st.Staged.Count -eq 1)
$f2 = Join-Path $printDir 'Print-Export-SRV01-20261122-100000.printerExport'; [IO.File]::WriteAllBytes($f2, [byte[]](5..99))
$f3 = Join-Path $adDir 'AD-Bericht-SRV01-20261122-100000.json'; [IO.File]::WriteAllText($f3, '{"Schema":1}')
[void](Add-SmAsStaged -State $st -Source 'PrintExport' -Kind 'PrintExport' -Path $f2); [void](Add-SmAsStaged -State $st -Source 'Ad' -Kind 'AdReport' -Path $f3)
Check 'Vormerken: Dateien aus Print und AD gehen auch (gehaertete Ordner)' ($st.Staged.Count -eq 3)
$outside = Join-Path $Work 'ausserhalb.zip'; [IO.File]::WriteAllBytes($outside, [byte[]](1..9))
Check 'Vormerken: Datei ausserhalb der erlaubten Ordner wird abgelehnt' (Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $outside })
Check 'Vormerken: Unterordner eines erlaubten Ordners wird abgelehnt' (Throws { New-Item -ItemType Directory -Force (Join-Path $stage 'sub') | Out-Null; [IO.File]::WriteAllBytes((Join-Path $stage 'sub\a.zip'), [byte[]](1..9)); Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path (Join-Path $stage 'sub\a.zip') })
$bad = Join-Path $stage 'mit leerzeichen.zip'; [IO.File]::WriteAllBytes($bad, [byte[]](1..9))
$bad2 = Join-Path $stage 'a;b.zip'; [IO.File]::WriteAllBytes($bad2, [byte[]](1..9))
Check 'Vormerken: Name mit Leerzeichen oder Sonderzeichen wird abgelehnt (Whitelist)' ((Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $bad }) -and (Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $bad2 }))
$empty = Join-Path $stage 'leer.zip'; [IO.File]::WriteAllBytes($empty, [byte[]]@())
Check 'Vormerken: leere und fehlende Datei werden abgelehnt' ((Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $empty }) -and (Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path (Join-Path $stage 'gibtsnicht.zip') }))
$junc = Join-Path $stage 'verknuepft.zip'
$jt = Join-Path $Work 'junction-ziel'; New-Item -ItemType Directory -Force $jt | Out-Null
$jr = & cmd.exe /c mklink /J "$junc" "$jt" 2>&1
Check 'Vormerken: ein Ordner (Verknuepfung) statt Datei wird abgelehnt' ((Throws { Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $junc }))
Check 'Vormerken: gleicher Name ersetzt den Eintrag (keine Doppelten)' ($(
        [IO.File]::WriteAllBytes($f1, [byte[]](9..40)); [void](Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $f1)
        $st.Staged.Count -eq 3 -and @($st.Staged | Where-Object Name -eq 'SM-DNS-SRV01-20261122-100000.zip').Count -eq 1 -and @($st.Staged | Where-Object Name -eq 'SM-DNS-SRV01-20261122-100000.zip')[0].Length -eq 32))
Clear-SmAsStaged -State $st -Source 'Dns'
Check 'Neu sammeln: Eintrag eines Schritts entfernt, Datei im Sammelordner geloescht' ($st.Staged.Count -eq 2 -and -not (Test-Path -LiteralPath $f1))

# ---------------------------------------------------------------- 5b. Ausgabedateien: CreateNew, Besitzer und ACL (Sicherheits-Checkliste 13), feste Namensmuster
$vd = New-SmAsStageDir
$ok1 = Join-Path $vd 'SM-DNS-SRV01-20261122-100000-0123456789ab.zip'; [IO.File]::WriteAllBytes($ok1, [byte[]](1..50))
$stv = New-SmAsState; $stv.StageDir = $vd
Check 'Vormerken: Datei mit eigenem Besitzer und gehaerteter ACL wird vorgemerkt (Gegenprobe)' ($(try { [void](Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'DnsLogs' -Path $ok1); $stv.Staged.Count -eq 1 } catch { $false }))
# fremde ACE: eine vorher angelegte Datei, auf der ein anderes Konto (Jeder) Zugriff hat
$foreignAce = Join-Path $vd 'SM-DNS-SRV01-20261122-100001-fremdace.zip'; [IO.File]::WriteAllBytes($foreignAce, [byte[]](1..50))
$fa = [IO.File]::GetAccessControl($foreignAce); $fa.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'Write', 'Allow'))); [IO.File]::SetAccessControl($foreignAce, $fa)
$errAce = ''; try { [void](Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'DnsLogs' -Path $foreignAce) } catch { $errAce = $_.Exception.Message }
Check 'GEGENTEST Vormerken: Datei mit fremder ACE (Jeder darf schreiben) wird nicht vorgemerkt' ($errAce -match 'nicht sicher' -and $errAce -match 'Zugriffsliste' -and -not @($stv.Staged | Where-Object Name -match 'fremdace').Count)
# fremder Besitzer: erlaubte Konten ohne den Testbenutzer und ohne Administratoren
$keepSids = $script:SmDnsStateSidsOverride; $script:SmDnsStateSidsOverride = @('S-1-5-18')
$errOwn = ''; try { [void](Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'DnsLogs' -Path $ok1) } catch { $errOwn = $_.Exception.Message }
$script:SmDnsStateSidsOverride = $keepSids
Check 'GEGENTEST Vormerken: Datei mit fremdem Besitzer wird nicht vorgemerkt' ($errOwn -match 'nicht sicher' -and $errOwn -match 'Besitzer')
$itCheck = $stv.Staged[0]
$script:SmDnsStateSidsOverride = @('S-1-5-18')
$resOwn = @(Publish-SmAsItems -Share ([pscustomobject]@{}) -Items @($itCheck) -Roots @(Get-SmAsAllowedRoots -StageDir $vd))
$script:SmDnsStateSidsOverride = $keepSids
Check 'GEGENTEST Hochladen: eine inzwischen fremde Datei wird nicht hochgeladen' ($resOwn.Count -eq 1 -and -not $resOwn[0].Ok -and $resOwn[0].Error -match 'nicht sicher')
Check 'Test-SmSecureFile: fehlende Datei und Ordner statt Datei werden gemeldet' (@(Test-SmSecureFile -Path (Join-Path $vd 'gibtsnicht.zip')).Count -eq 1 -and @(Test-SmSecureFile -Path $vd).Count -eq 1)
# Namensmuster je Art
$pe = Join-Path $printDir 'Print-Export-SRV01-20261122-100000-0123456789ab.printerExport'; [IO.File]::WriteAllBytes($pe, [byte[]](1..9))
Check 'Vormerken: Name passt nur zur eigenen Art (Print-Export als DnsLogs, unbekannte Art, fremdes Muster werden abgelehnt)' ((Throws { Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'DnsLogs' -Path $pe }) -and (Throws { Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'Unbekannt' -Path $ok1 }) -and (Throws { $x = Join-Path $vd 'beliebig.zip'; [IO.File]::WriteAllBytes($x, [byte[]](1..9)); Add-SmAsStaged -State $stv -Source 'Dns' -Kind 'DnsLogs' -Path $x }) -and (Add-SmAsStaged -State $stv -Source 'PrintExport' -Kind 'PrintExport' -Path $pe).Name -like 'Print-Export-*')
# CreateNew
$cn = Join-Path $vd 'vorher.json'; [IO.File]::WriteAllText($cn, 'ORIGINAL')
Check 'CreateNew: Write-SmNewText ueberschreibt eine vorhandene Datei nie (wirft, Inhalt unveraendert)' ((Throws { Write-SmNewText -Path $cn -Text 'NEU' }) -and ([IO.File]::ReadAllText($cn) -eq 'ORIGINAL'))
$np = New-SmUniquePath -Folder $vd -Name 'Print-Inventur-X-20261122-100000.json'
$np2 = New-SmUniquePath -Folder $vd -Name 'Print-Inventur-X-20261122-100000.json'
Check 'CreateNew: neuer Name mit GUID-Anteil vor der Endung, jedes Mal ein anderer, die Datei gibt es noch nicht' ((Split-Path -Leaf $np) -match '^Print-Inventur-X-20261122-100000-[0-9a-f]{12}\.json$' -and $np -ne $np2 -and -not (Test-Path -LiteralPath $np))
Write-SmNewText -Path $np -Text 'x'
Check 'CreateNew: die neue Datei gehoert dem Testbenutzer oder den Administratoren und hat keine fremde ACE' (@(Test-SmSecureFile -Path $np).Count -eq 0)
$ov = [ordered]@{ Created = 'x'; Computer = 'SRV01'; Forest = [ordered]@{ Name = 'contoso.local' }; DomainLevels = @() }
$r1 = New-SmAdReport -Overview $ov; $r2 = New-SmAdReport -Overview $ov
Check 'AD-Bericht: jedes Mal eine neue Datei mit GUID-Anteil (nie eine vorhandene ueberschrieben), Name passt zum Muster der Art AdReport' ($r1 -ne $r2 -and (Test-Path -LiteralPath $r1) -and (Test-Path -LiteralPath $r2) -and (Split-Path -Leaf $r1) -match $script:SmAsNamePatterns['AdReport'] -and (Split-Path -Leaf $r1) -match '-[0-9a-f]{12}\.json$')
Remove-SmAsStageDir -Dir $vd

# Lokale Dateien dieser Sitzung loeschen
$cs = New-SmAsState; $cs.StageDir = New-SmAsStageDir
$cf1 = Join-Path $cs.StageDir 'SM-DNS-SRV01-20261122-110000-aaaaaaaaaaaa.zip'; [IO.File]::WriteAllBytes($cf1, [byte[]](1..30))
$cf2 = Join-Path $printDir 'Print-Inventur-SRV01-20261122-110000-bbbbbbbbbbbb.json'; [IO.File]::WriteAllText($cf2, '{"a":1}')
$cf3 = Join-Path $adDir 'AD-Bericht-SRV01-20261122-110000-cccccccccccc.json'; [IO.File]::WriteAllText($cf3, '{"a":1}')
$cfOther = Join-Path $printDir 'Print-Export-NICHT-VON-DIESER-SITZUNG.printerExport'; [IO.File]::WriteAllBytes($cfOther, [byte[]](1..9))
[void](Add-SmAsStaged -State $cs -Source 'Dns' -Kind 'DnsLogs' -Path $cf1); [void](Add-SmAsStaged -State $cs -Source 'PrintExport' -Kind 'PrintInventory' -Path $cf2); [void](Add-SmAsStaged -State $cs -Source 'Ad' -Kind 'AdReport' -Path $cf3)
Clear-SmAsStaged -State $cs -Source 'Ad'   # Neu sammeln: aus der Liste, aber die Datei in AD bleibt liegen
$stageBefore = $cs.StageDir
$rc = Remove-SmAsSessionFiles -State $cs
Check 'Lokale Dateien loeschen: Sammelordner samt Datei, Print- und AD-Datei dieser Sitzung (auch die nicht mehr vorgemerkte) sind weg' ($rc.Removed -eq 3 -and -not (Test-Path -LiteralPath $stageBefore) -and -not (Test-Path -LiteralPath $cf2) -and -not (Test-Path -LiteralPath $cf3) -and $rc.Failed.Count -eq 0 -and -not $cs.StageDir -and $cs.Staged.Count -eq 0)
Check 'Lokale Dateien loeschen: eine Datei, die nicht aus dieser Sitzung stammt, bleibt unberuehrt' (Test-Path -LiteralPath $cfOther)
Check 'Lokale Dateien loeschen: zweiter Aufruf ohne Dateien wirft nicht und meldet nichts' ($(try { $r0 = Remove-SmAsSessionFiles -State $cs; $r0.Removed -eq 0 -and $r0.Failed.Count -eq 0 } catch { $false }))
# nicht loeschbar (offen gehalten): Meldung statt stiller Fehler, Datei bleibt vermerkt
$cs2 = New-SmAsState; $cs2.StageDir = New-SmAsStageDir
$cf4 = Join-Path $printDir 'Print-Inventur-SRV01-20261122-110001-dddddddddddd.json'; [IO.File]::WriteAllText($cf4, '{"a":1}')
[void](Add-SmAsStaged -State $cs2 -Source 'PrintExport' -Kind 'PrintInventory' -Path $cf4)
$lock = New-Object IO.FileStream($cf4, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
try { $rc2 = Remove-SmAsSessionFiles -State $cs2 } finally { $lock.Dispose() }
Check 'Lokale Dateien loeschen: eine gesperrte Datei wird gemeldet (Failed nennt den Namen) und bleibt vermerkt, der Rest ist geloescht' ($rc2.Failed.Count -ge 1 -and ($rc2.Failed -join ' ') -match 'Print-Inventur-SRV01' -and $cs2.Created.Count -eq 1 -and (Test-Path -LiteralPath $cf4))
$rc3 = Remove-SmAsSessionFiles -State $cs2
Check 'Lokale Dateien loeschen: nach dem Freigeben klappt der zweite Versuch' ($rc3.Removed -eq 1 -and $rc3.Failed.Count -eq 0 -and -not (Test-Path -LiteralPath $cf4))
Remove-Item -LiteralPath $cfOther -Force

# Schliessen: zuerst Auftrag beenden, dann loeschen, Fehler im Protokoll
$keepAs = $script:SmAs
$closeLog = New-Object System.Collections.ArrayList
$cs3 = New-SmAsState; $cs3.StageDir = New-SmAsStageDir
$cf5 = Join-Path $cs3.StageDir 'SM-DNS-SRV01-20261122-110002-eeeeeeeeeeee.zip'; [IO.File]::WriteAllBytes($cf5, [byte[]](1..30))
$rsJ = [runspacefactory]::CreateRunspace(); $rsJ.Open(); $psJ = [powershell]::Create(); $psJ.Runspace = $rsJ
[void]$psJ.AddScript('Start-Sleep -Seconds 60'); $hJ = $psJ.BeginInvoke()
$timerStub = [pscustomobject]@{ Stopped = $false }; $timerStub | Add-Member -MemberType ScriptMethod -Name Stop -Value { $this.Stopped = $true }
$script:SmAs = @{ State = $cs3; Log = { param($m) [void]$closeLog.Add($m) }; Job = @{ Ps = $psJ; Rs = $rsJ; Handle = $hJ; Timer = $timerStub } }
$lockC = New-Object IO.FileStream($cf5, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
$stageC = $cs3.StageDir
Close-SmAssistantPage
Check 'Schliessen: laufender Auftrag wird beendet (Timer aus, Runspace gestoppt), Job-Verweis geloescht' ($timerStub.Stopped -and $hJ.IsCompleted -and -not $script:SmAs.Job)
Check 'Schliessen: Sammelordner nicht loeschbar (Datei offen) -> Meldung im Protokoll, kein Absturz, Ordner bleibt vermerkt' ((($closeLog -join '|') -match 'nicht vollst') -and $cs3.StageDir -eq $stageC)
$lockC.Dispose(); $closeLog.Clear()
Close-SmAssistantPage
Check 'Schliessen: zweiter Versuch loescht den Sammelordner, kein Protokolleintrag' (-not (Test-Path -LiteralPath $stageC) -and -not $cs3.StageDir -and $closeLog.Count -eq 0)
$script:SmAs = @{ State = (New-SmAsState); Log = { param($m) }; Job = $null }
Check 'Schliessen: ohne Sammelordner und ohne Auftrag kein Fehler' ($(try { Close-SmAssistantPage; $true } catch { $false }))
$script:SmAs = $null; Check 'Schliessen: ohne Sitzung kein Fehler' ($(try { Close-SmAssistantPage; $true } catch { $false }))
$script:SmAs = $keepAs

# Systemordner: nicht aus %windir%/%SystemRoot% (Umgebungsvariablen sind fuer Sicherheitsentscheidungen nicht verlaesslich)
$sysDir = [Environment]::GetFolderPath('System')
$keepWin = $env:windir; $keepRoot = $env:SystemRoot
$env:windir = 'C:\evil'; $env:SystemRoot = 'C:\evil'
$script:SmPrintBrmPath = $null; $script:SmWevtutilPath = $null; $script:SmAdToolPaths = @{}
$pBrm = Get-SmPrintBrmPath; $pWev = Get-SmWevtutilPath; $pRep = Get-SmAdToolPath -Name repadmin; $pNtds = Get-SmAdToolPath -Name ntdsutil; $pDns = Get-SmDnsAllowedDir
$env:windir = $keepWin; $env:SystemRoot = $keepRoot
Check 'Systemordner: DNS-Ordner, PrintBrm, wevtutil, repadmin und ntdsutil kommen aus GetFolderPath(System), auch wenn %windir% und %SystemRoot% veraendert sind' ($pDns -eq (Join-Path $sysDir 'dns') -and $pBrm -eq (Join-Path $sysDir 'spool\tools\PrintBrm.exe') -and $pWev -eq (Join-Path $sysDir 'wevtutil.exe') -and $pRep -eq (Join-Path $sysDir 'repadmin.exe') -and $pNtds -eq (Join-Path $sysDir 'ntdsutil.exe') -and $pBrm -notmatch 'evil')
Check 'Systemordner: Standardpfad der DNS-Logdatei = System32\dns\dns.log aus GetFolderPath, nicht aus %windir%' ($script:SmDnsDefaultPath -eq (Join-Path $sysDir 'dns\dns.log'))
$envUse = @(Get-ChildItem -LiteralPath $Repo -Recurse -File -Include *.ps1 | Where-Object { $_.FullName -notlike '*\tests\*' -and $_.FullName -notlike '*\.git\*' } | Select-String -Pattern 'env:windir|env:SystemRoot' | Where-Object { ($_.Line -replace '#.*$', '') -match 'env:windir|env:SystemRoot' })
Check 'Systemordner: kein Code im Repo (ausser Tests) liest $env:windir oder $env:SystemRoot' ($envUse.Count -eq 0) (($envUse | ForEach-Object { $_.Path + ':' + $_.LineNumber }) -join '; ')

# Anzeige und Quelltext
Check 'Format-SmAsHash: Auslassungszeichen ist U+2026 (kein Zeichenmuell), gekuerzt auf 8 + Zeichen + 4' ((Format-SmAsHash ('A' * 64)) -eq ('AAAAAAAA' + [string][char]0x2026 + 'AAAA') -and (Format-SmAsHash 'ABC') -eq 'ABC')
$asRaw = Get-Content -LiteralPath (Join-Path $Repo 'server\SmAssistent.ps1') -Raw -Encoding UTF8
Check 'SmAssistent.ps1: kein doppelt kodierter Text (UTF-8 als ANSI gelesen und wieder gespeichert)' ($asRaw -notmatch '[\u00C2\u00C3\u00E2][\u0080-\u00BF\u0152\u0153\u0160\u0161\u0178\u017D\u017E\u0192\u02C6\u02DC\u2013\u2014\u2018-\u201E\u2020-\u2022\u2026\u2030\u2039\u203A\u20AC\u2122]')
$asSrc = $asRaw
Check 'Print-Schritt: Pseudonym-Auswahl und Schluessel werden an Invoke-SmPrintCollect uebergeben (Zufallsschluessel, HMAC, Rechnernamen optional)' ($asSrc -match 'Invoke-SmPrintCollect -Days \$P\.Days -Pseudonymize:\$P\.Pseudo -PseudonymizeClients:\$P\.PseudoC -Key \$P\.Key' -and $asSrc -match 'New-SmPseudonymKey' -and $asSrc -match 'ChkAsPrintPseudoClient')
Clear-SmAsStaged -State $st -Source 'PrintExport'
Check 'Neu sammeln: Dateien in Print bleiben liegen (nur die Liste wird leer)' (Test-Path -LiteralPath $f2)
Check 'Sammelordner loeschen: nur Sammlung-<GUID> direkt unter Assistent' ($(
        Remove-SmAsStageDir -Dir $Work; Remove-SmAsStageDir -Dir (Join-Path $root 'Assistent'); Remove-SmAsStageDir -Dir $printDir
        $ok1 = (Test-Path -LiteralPath $Work) -and (Test-Path -LiteralPath $printDir) -and (Test-Path -LiteralPath (Join-Path $root 'Assistent'))
        Remove-SmAsStageDir -Dir $stage
        $ok1 -and -not (Test-Path -LiteralPath $stage)))
$old = New-SmAsStageDir; $new = New-SmAsStageDir
(Get-Item -LiteralPath $old).LastWriteTime = (Get-Date).AddHours(-30)
$foreign = Join-Path (Join-Path $root 'Assistent') 'fremd'; New-Item -ItemType Directory -Force $foreign | Out-Null; (Get-Item -LiteralPath $foreign).LastWriteTime = (Get-Date).AddHours(-30)
Check 'Verwaiste Sammelordner: nur der alte mit passendem Namen wird geloescht, der neue und fremde bleiben' ($(
        $n = Clear-SmAsOrphans
        $n -eq 1 -and -not (Test-Path -LiteralPath $old) -and (Test-Path -LiteralPath $new) -and (Test-Path -LiteralPath $foreign)))
Remove-SmAsStageDir -Dir $new

# ---------------------------------------------------------------- 6. Sammeln ohne Hochladen
$st = New-SmAsState; $stage = New-SmAsStageDir; $st.StageDir = $stage
# DNS: Logdatei im (nachgebauten) DNS-Ordner, ZIP mit meta.json im Sammelordner, nichts hochgeladen
$dnsDir = Join-Path $Work 'as-dns'; New-Item -ItemType Directory -Force $dnsDir | Out-Null
$script:SmDnsAllowedDirOverride = $dnsDir
$log = Join-Path $dnsDir 'dns.log'
[IO.File]::WriteAllText($log, ("DNS Server log file creation at 22.11.2026 10:00:00`r`n" + ('22.11.2026 10:00:01 0F30 PACKET  000001A2B3C4D5E6 UDP Rcv 10.0.0.5  0001   Q [0001   D   NOERROR] A      (3)www(7)contoso(5)local(0)' + "`r`n") * 50), [Text.Encoding]::ASCII)
$script:Uploaded = 0
function Send-SmShareFile { param($Share, $Path) $script:Uploaded++ }
$pkg = Invoke-SmAsDnsCollect -StageDir $stage -LogPath $log
Check 'DNS sammeln: ZIP im Sammelordner (SM-DNS-*.zip), Name erlaubt, nichts hochgeladen' ($pkg.Path.StartsWith($stage) -and $pkg.Name -match '^SM-DNS-[\w\-]+\.zip$' -and $pkg.Length -gt 0 -and $script:Uploaded -eq 0)
$zip = [IO.Compression.ZipFile]::OpenRead($pkg.Path)
try { $entries = @($zip.Entries | ForEach-Object Name) } finally { $zip.Dispose() }
Check 'DNS sammeln: ZIP enthaelt dns.log und meta.json' ($entries -contains 'dns.log' -and $entries -contains 'meta.json')
# leerer LogFilePath (Windows-Standard): der Assistent sammelt dieselbe Datei
$keepDefault = $script:SmDnsDefaultPath; $script:SmDnsDefaultPath = $log
$pkg2 = Invoke-SmAsDnsCollect -StageDir $stage -LogPath ''
Check 'DNS sammeln: leerer Pfad = Windows-Standard, es wird gesammelt (Fehler aus dem Live-Test)' ($pkg2.Length -gt 0 -and (Test-Path -LiteralPath $pkg2.Path))
$script:SmDnsDefaultPath = $keepDefault
Check 'DNS sammeln: Pfad ausserhalb von System32\dns wird abgelehnt' (Throws { Invoke-SmAsDnsCollect -StageDir $stage -LogPath (Join-Path $Work 'dns.log') })
$it = Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $pkg.Path
Check 'DNS vormerken: ZIP aus dem Sammelordner mit SHA256' ($it.Sha256 -eq (Get-FileHash -LiteralPath $pkg.Path -Algorithm SHA256).Hash)
$script:SmDnsAllowedDirOverride = $null
# DHCP: Export (nachgebaut) schreibt XML, JSON und ZIP; nach dem Sammeln bleibt nur die ZIP
$script:DhcpPre = $true
function Test-SmDhcpPrecheck { param($Mode) [pscustomobject]@{ Ok = $script:DhcpPre; Items = @([pscustomobject]@{ Ok = $script:DhcpPre; Blocking = $true; Text = 'Dienst DHCPServer fehlt' }) } }
function New-SmDhcpExport {
    param($WorkDir, [scriptblock]$Log, [switch]$NoLeases)
    [IO.File]::WriteAllText((Join-Path $WorkDir 'dhcp-export.xml'), '<DHCPServer/>'); [IO.File]::WriteAllText((Join-Path $WorkDir 'dhcp-summary.json'), '{}')
    $zp = Join-Path $WorkDir 'DHCP-Export-SRV01-20261122-100000.zip'
    $z = [IO.Compression.ZipFile]::Open($zp, 'Create'); try { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, (Join-Path $WorkDir 'dhcp-export.xml'), 'dhcp-export.xml') } finally { $z.Dispose() }
    $script:DhcpNoLeases = [bool]$NoLeases
    [pscustomobject]@{ Path = $zp; Name = 'DHCP-Export-SRV01-20261122-100000.zip'; Length = (Get-Item $zp).Length; Summary = [pscustomobject]@{ Scopes4 = @(1, 2); Scopes6 = @() } }
}
$dh = Invoke-SmAsDhcpCollect -StageDir $stage -NoLeases
Check 'DHCP sammeln: nur die ZIP bleibt im Sammelordner (XML mit Leases und JSON werden geloescht), -NoLeases kommt an, nichts hochgeladen' ((Test-Path -LiteralPath $dh.Path) -and -not (Test-Path -LiteralPath (Join-Path $stage 'dhcp-export.xml')) -and -not (Test-Path -LiteralPath (Join-Path $stage 'dhcp-summary.json')) -and $script:DhcpNoLeases -and $script:Uploaded -eq 0)
Check 'DHCP sammeln: Protokollzeile (Audit) ohne Geheimnisse' ((Get-Content -LiteralPath $script:SmDhcpAuditPath -Raw) -match 'Assistent, vorgemerkt')
$script:DhcpPre = $false
Check 'DHCP sammeln: ohne bestandene Vorpruefung (Rolle fehlt) wird nichts exportiert' (Throws { Invoke-SmAsDhcpCollect -StageDir $stage })
Remove-Item Function:\Test-SmDhcpPrecheck, Function:\New-SmDhcpExport
. (Join-Path $Repo 'server\SmDhcpServer.ps1')
Set-TestEnv
# AD: Bericht (nachgebaut) im AD-Ordner
function Get-SmAdOverview { [ordered]@{ Schema = 1; Kind = 'AD-Bericht' } }
function New-SmAdReport { param($Overview) $p = Join-Path $adDir 'AD-Bericht-SRV01-20261122-110000.json'; [IO.File]::WriteAllText($p, '{"Schema":1,"Kind":"AD-Bericht"}'); $p }
$ad = Invoke-SmAsAdCollect
Check 'AD sammeln: Bericht im AD-Ordner, vormerkbar' ((Test-Path -LiteralPath $ad.Path) -and (Add-SmAsStaged -State $st -Source 'Ad' -Kind 'AdReport' -Path $ad.Path).Name -eq $ad.Name)
Remove-Item Function:\Get-SmAdOverview, Function:\New-SmAdReport, Function:\Send-SmShareFile
. (Join-Path $Repo 'Modules\SmTausch.ps1'); . (Join-Path $Repo 'server\SmAdServer.ps1'); Set-TestEnv

# ---------------------------------------------------------------- 7. Hochladen gegen den nachgebauten SharePoint
if ($Share -and $Store) {
    $st = New-SmAsState; $stage = New-SmAsStageDir; $st.StageDir = $stage
    $small = Join-Path $stage 'SM-DNS-klein.zip'; [IO.File]::WriteAllText($small, ('k' * 5000))
    $big = Join-Path $stage 'DHCP-Export-gross.zip'; $rnd = New-Object byte[] (64KB * 3 + 777); (New-Object Random 7).NextBytes($rnd); [IO.File]::WriteAllBytes($big, $rnd)
    $tamper = Join-Path $printDir 'Print-Export-TEST.printerExport'; [IO.File]::WriteAllBytes($tamper, [byte[]](1..120))
    $itSmall = Add-SmAsStaged -State $st -Source 'Dns' -Kind 'DnsLogs' -Path $small
    $itBig = Add-SmAsStaged -State $st -Source 'Dhcp' -Kind 'DhcpExport' -Path $big
    $itTamper = Add-SmAsStaged -State $st -Source 'PrintExport' -Kind 'PrintExport' -Path $tamper
    [IO.File]::WriteAllBytes($tamper, [byte[]](200..250))   # nach dem Vormerken veraendert
    $prog = New-Object System.Collections.ArrayList; $logs = New-Object System.Collections.ArrayList
    $roots = Get-SmAsAllowedRoots -StageDir $st.StageDir
    $res = @(Publish-SmAsItems -Share $Share -Items @($st.Staged | Sort-Object { $_.Name -ne 'Print-Export-TEST.printerExport' }) -Roots $roots -ChunkSize 64KB `
            -Progress { param($i, $n, $name, $sent, $total) [void]$prog.Add(('{0}/{1}/{2}/{3}/{4}' -f $i, $n, $name, $sent, $total)) } -Log { param($m) [void]$logs.Add($m) })
    Check 'Upload: je Datei ein Ergebnis, in der Reihenfolge der Liste' ($res.Count -eq 3 -and $res[0].Name -eq 'Print-Export-TEST.printerExport')
    Check 'Upload: veraenderte Datei wird NICHT hochgeladen (SHA256 passt nicht zum Vormerken), Fehlertext nennt es' (-not $res[0].Ok -and $res[0].Error -match 'ge.ndert' -and -not $Store.ContainsKey('Print-Export-TEST.printerExport'))
    $rs = $res | Where-Object Name -eq 'SM-DNS-klein.zip'; $rb = $res | Where-Object Name -eq 'DHCP-Export-gross.zip'
    Check 'Upload: der Fehler der ersten Datei stoppt die anderen nicht, beide sind hochgeladen' ($rs.Ok -and $rb.Ok -and $Store.ContainsKey('SM-DNS-klein.zip') -and $Store.ContainsKey('DHCP-Export-gross.zip'))
    Check 'Upload: Inhalt im Tauschordner gleich der lokalen Datei (SHA256), auch die grosse in Teilen' ((Get-SmSha256Bytes -Bytes $Store['DHCP-Export-gross.zip']) -eq $itBig.Sha256 -and (Get-SmSha256Bytes -Bytes $Store['SM-DNS-klein.zip']) -eq $itSmall.Sha256 -and $rb.Length -eq $rnd.Length)
    Check 'Upload: Ergebnis traegt die vorgemerkte SHA256 und die Groesse' ($rb.Sha256 -eq $itBig.Sha256 -and $rs.Length -eq 5000)
    $bigProg = @($prog | Where-Object { $_ -like '*DHCP-Export-gross.zip*' })
    Check 'Upload: Fortschritt je Datei (Index, Anzahl, Name, gesendet, gesamt), die grosse in 4 Teilen bis 100 Prozent' ($bigProg.Count -eq 4 -and $bigProg[-1] -match "/3/DHCP-Export-gross.zip/$($rnd.Length)/$($rnd.Length)$" -and @($prog | Where-Object { $_ -like '*SM-DNS-klein.zip*' }).Count -ge 1 -and ($prog[0] -notlike '*Print-Export*'))
    Check 'Upload: Protokollzeilen fuer Hochladen, Fehler und Ergebnis, ohne Link' (($logs -join '|') -match 'Lade hoch \(' -and ($logs -join '|') -match 'Fehler bei Print-Export-TEST' -and ($logs -join '|') -notmatch 'sharepoint|http')
    Check 'Upload: Dateien sind danach nicht mehr gesperrt (Handle freigegeben)' ($(try { Remove-Item -LiteralPath $small -Force; $true } catch { $false }))
    $sum = Format-SmAsSummary -Results $res
    Check 'Zusammenfassung: Anzahl, Namen mit Groesse und gekuerzter SHA256, Fehler mit Grund' ($sum -match '2 von 3 Dateien' -and $sum -match 'DHCP-Export-gross.zip' -and $sum -match 'FEHLER Print-Export-TEST' -and $sum -match ($itBig.Sha256.Substring(0, 8)))
    $cs = Format-SmAsChecksums -Results $res
    Check 'Pruefsummen-Text: nur die hochgeladenen Dateien, vollstaendige SHA256, je Zeile Bezeichnung: Wert' (($cs -split "`r`n").Count -eq 2 -and $cs -match ('DHCP-Export-gross.zip: ' + $itBig.Sha256) -and $cs -notmatch 'Print-Export')
    $resPrint = @([pscustomobject]@{ Name = 'Print-Export-A.printerExport'; Kind = 'PrintExport'; Ok = $true; Sha256 = ('A' * 64) }, [pscustomobject]@{ Name = 'Print-Inventur-A.json'; Kind = 'PrintInventory'; Ok = $true; Sha256 = ('B' * 64) })
    $csp = Format-SmAsChecksums -Results $resPrint
    Check 'Pruefsummen-Text: Print als "Export:" und "Inventur:" (so liest ihn die Seite Print am neuen Server, Get-SmPastedSha)' ($csp -eq ("Export: " + ('A' * 64) + "`r`nInventur: " + ('B' * 64)) -and (Get-SmPastedSha $csp 'Export') -match ('^' + ('A' * 64)) -and (Get-SmPastedSha $csp 'Inventur') -match ('^' + ('B' * 64)))
    # Echter Ausgabetext des Assistenten als Eingabe fuer DHCP und Print
    $shD = ('1234567890ABCDEF' * 4); $shE = ('A' * 64); $shI = ('B' * 64); $shN = ('C' * 64)
    $resAll = @([pscustomobject]@{ Name = 'DHCP-Export-SRV01-20260101-120000.zip'; Kind = 'DhcpExport'; Ok = $true; Sha256 = $shD }, [pscustomobject]@{ Name = 'Print-Export-A.printerExport'; Kind = 'PrintExport'; Ok = $true; Sha256 = $shE }, [pscustomobject]@{ Name = 'Print-Inventur-A.json'; Kind = 'PrintInventory'; Ok = $true; Sha256 = $shI }, [pscustomobject]@{ Name = 'DNS-Logs-A.zip'; Kind = 'DnsLogs'; Ok = $true; Sha256 = $shN })
    $csAll = Format-SmAsChecksums -Results $resAll
    Check 'DHCP-Feld: Ausgabetext des Assistenten (alle Zeilen) trifft die DHCP-Pruefsumme, Print-Zeilen werden nicht genommen' ((Test-SmDhcpShaMatch -Expected $shD -Entered $csAll) -and -not (Test-SmDhcpShaMatch -Expected $shE -Entered $csAll) -and -not (Test-SmDhcpShaMatch -Expected $shN -Entered $csAll))
    Check 'DHCP-Feld: nur die DHCP-Zeile, eine Zeile mit anderem Namen und die reine Pruefsumme' ((Test-SmDhcpShaMatch -Expected $shD -Entered ('DHCP-Export-SRV01-20260101-120000.zip: ' + $shD)) -and (Test-SmDhcpShaMatch -Expected $shD -Entered ('Irgendwas: ' + $shD.ToLower())) -and (Test-SmDhcpShaMatch -Expected $shD -Entered $shD))
    Check 'DHCP-Feld: mehrere Summen ohne eindeutige DHCP-Zeile ist kein Treffer und mehrdeutig, auch mit zwei DHCP-Zeilen' (-not (Test-SmDhcpShaMatch -Expected $shE -Entered ("Export: $shE`r`nInventur: $shI")) -and (Test-SmDhcpShaAmbiguous ("Export: $shE`r`nInventur: $shI")) -and (Test-SmDhcpShaAmbiguous ("DHCP-A.zip: $shD`r`nDHCP-B.zip: $shE")) -and -not (Test-SmDhcpShaAmbiguous $csAll) -and -not (Test-SmDhcpShaAmbiguous $shD) -and -not (Test-SmDhcpShaAmbiguous ''))
    Check 'DHCP-Feld: falsche oder zu lange Summe in der DHCP-Zeile ist kein Treffer' (-not (Test-SmDhcpShaMatch -Expected $shD -Entered ('DHCP-Export-X.zip: ' + $shE)) -and -not (Test-SmDhcpShaMatch -Expected $shD -Entered ('DHCP-Export-X.zip: ' + $shD + '0')))
    Check 'Print-Felder: derselbe Ausgabetext (mit DHCP- und DNS-Zeile) liefert Export und Inventur, Zeilennamen passen' ((Test-SmShaMatch -Entered (Get-SmPastedSha $csAll 'Export') -Actual $shE) -and (Test-SmShaMatch -Entered (Get-SmPastedSha $csAll 'Inventur') -Actual $shI))
    Check 'Upload: ohne Dateien wirft eine klare Meldung' (Throws { Publish-SmAsItems -Share $Share -Items @() -Roots $roots })
    $outsideItem = [pscustomobject]@{ Name = 'ausserhalb.zip'; Source = 'Dns'; Kind = 'DnsLogs'; Length = 9; Sha256 = ('0' * 64); Path = $outside }
    $ro = @(Publish-SmAsItems -Share $Share -Items @($outsideItem) -Roots $roots)
    Check 'Upload: ein Pfad ausserhalb der erlaubten Ordner wird nicht hochgeladen (Pfad wird beim Hochladen erneut geprueft)' ($ro.Count -eq 1 -and -not $ro[0].Ok -and $ro[0].Error -match 'erlaubten Ordner' -and -not $Store.ContainsKey('ausserhalb.zip'))
    Remove-SmAsStageDir -Dir $stage
}
else { Write-Host 'INFO kein SharePoint-Nachbau uebergeben: Upload-Pruefungen entfallen (laufen in tests\Test-ServerMigration.ps1)' -ForegroundColor Yellow }

# ---------------------------------------------------------------- 8. Oberflaeche: XAML, Namen, keine Symbolzeichen
$xamlPath = Join-Path $Repo 'UI\ServerStart.xaml'
$xtext = [IO.File]::ReadAllText($xamlPath, [Text.Encoding]::UTF8)
Check 'ServerStart.xaml laesst sich als XML lesen' ($(try { [xml]$null = $xtext; $true } catch { $false }))
Check 'ServerStart.xaml: keine Symbolzeichen (Segoe Fluent Icons, &#xE...), keine Emojis, kein Tag-Symbol, kein BandGlyph, kein IsReadOnly' ($xtext -notmatch '&#x[Ee][0-9A-Fa-f]{3};' -and $xtext -notmatch '[\uE000-\uF8FF]' -and $xtext -notmatch '[\uD83C-\uD83E][\uDC00-\uDFFF]' -and $xtext -notmatch 'IconFont|BandGlyph|Tag="' -and $xtext -notmatch 'IsReadOnly')
$asPs = Get-Content -LiteralPath (Join-Path $Repo 'server\SmAssistent.ps1') -Raw -Encoding UTF8
Check 'SmAssistent.ps1: keine Symbolzeichen aus Segoe Fluent Icons und keine Emojis im Code' ($asPs -notmatch '[\uE000-\uF8FF]' -and $asPs -notmatch '[\uD83C-\uD83E][\uDC00-\uDFFF]' -and $asPs -notmatch '0xE[0-9A-F]{3}\b')
Check 'Oberflaeche: nichts aus dem Assistenten aendert AD, DHCP oder Print (keine Import-, Autorisierungs-, FSMO-, Deaktivieren-Aufrufe)' ($asPs -notmatch '(Invoke-SmDhcpImport|Invoke-SmDhcpAuthorize|Invoke-SmDhcpDeactivate|Invoke-SmPrintImport|Invoke-SmAdFsmo|Invoke-SmAdRaiseLevel|Invoke-SmAdAdprep|Invoke-SmAdDsrm|Enable-SmPrintLog|Disable-SmPrintLog|Disable-SmDnsLogging)')
Check 'Oberflaeche: einzige aendernde Aktion ist das DNS-Logging einschalten, mit Bestaetigung vorher' ((([regex]::Matches($asPs, 'Enable-SmDnsLogging')).Count -eq 1) -and ($asPs -match "Confirm-SmAs \`$msg 'DNS-Logging einschalten'"))
$names = @(Get-SmAssistantUiNames)
$page = Get-SmAssistantPageXaml -Root $Repo
$pxml = [xml]$page
$have = @(([regex]::Matches($page, 'x:Name="([^"]+)"')) | ForEach-Object { $_.Groups[1].Value })
Check ('Oberflaeche: alle ' + $names.Count + ' erwarteten Namen sind in der Seite (mit den erzeugten Schrittzeilen) vorhanden') (@($names | Where-Object { $have -notcontains $_ }).Count -eq 0)
Check 'Oberflaeche: Namen sind eindeutig, keiner kollidiert mit den Seiten DNS, DHCP, Print, AD' ((@($have | Group-Object | Where-Object Count -gt 1).Count -eq 0) -and $(
        $others = @(); foreach ($f in 'DnsServer', 'DhcpServer', 'PrintServer', 'AdServer') { $others += @(([regex]::Matches([IO.File]::ReadAllText((Join-Path $Repo "UI\$f.xaml")), 'x:Name="([^"]+)"')) | ForEach-Object { $_.Groups[1].Value }) }
        @($have | Where-Object { $others -contains $_ -and $_ -notmatch '^(BtnLog|TxtLog|BoxLog|ScrLog|PnlLog)' }).Count -eq 0))
Check 'Oberflaeche: je Schritt eine Zeile und ein Panel (Check, Dns, Dhcp, Print, Ad, Upload)' (@('Check', 'Dns', 'Dhcp', 'Print', 'Ad', 'Upload' | Where-Object { $have -contains "BdgAs$_" -and $have -contains "BtnAsGo$_" -and $have -contains "PnlAs$_" -and $have -contains "TxtAsState$_" }).Count -eq 6)
Check 'Oberflaeche: Platzhalter ersetzt (kein <!--SCHRITTE-->, kein <!--PROTOKOLL-->), Protokollkarte vorhanden' ($page -notmatch '<!--(SCHRITTE|PROTOKOLL)-->' -and $have -contains 'PnlLog')
Check 'DNS-Seite: Vorbelegung Pfad leer-sicher (Standard) und Groesse 500 (dezimale MB)' ($script:SmDnsDefaultMaxMB -eq 500 -and $script:SmDnsDefaultPath -match 'System32\\dns\\dns\.log$')

# Fenster mit der Startseite bauen und den Assistenten ansehen (eigener Prozess: WPF, STA)
$probe = Join-Path $Work 'assist-probe.ps1'
$pl = @'
$ErrorActionPreference = 'Stop'
$env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force
$root = '__REPO__'
. (Join-Path $root 'Modules\SmTheme.ps1'); . (Join-Path $root 'Modules\SmShell.ps1'); . (Join-Path $root 'Modules\SmUi.ps1'); . (Join-Path $root 'Modules\SmTausch.ps1')
. (Join-Path $root 'server\SmDnsServer.ps1'); . (Join-Path $root 'Modules\SmDhcp.ps1'); . (Join-Path $root 'server\SmDhcpServer.ps1'); . (Join-Path $root 'Modules\SmPrint.ps1'); . (Join-Path $root 'server\SmPrintServer.ps1')
. (Join-Path $root 'Modules\SmAd.ps1'); . (Join-Path $root 'server\SmAdServer.ps1'); . (Join-Path $root 'server\SmAssistent.ps1')
$mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:SmDnsStateSidsOverride = @('S-1-5-32-544', 'S-1-5-18', $mySid)
$script:SmAsDataRoot = '__WORK__\probe-root'; $script:SmPrintDataRoot = $script:SmAsDataRoot; $script:SmAdDataRoot = $script:SmAsDataRoot
$w = New-SmWindow -Root $root -Title t -Pages @(@{ Key = 'Start'; Title = 'Dieser Server'; Glyph = 0xE977; Xaml = (Get-SmAssistantPageXaml -Root $root) }) -Theme __THEME__
$ui = $w.Ui
Initialize-SmLog -Ui $ui
Initialize-SmCodeBoxes -Ui $ui
Test-SmWindowNames (Get-SmAssistantUiNames)
$script:Logs = New-Object System.Collections.ArrayList
Initialize-SmAssistantPage -Ui $ui -JobModules @('x') -GetShare { $null } -AddLog { param($m) [void]$script:Logs.Add($m) }
$c = $script:SmAs
function Out($k, $v) { '{0}={1}' -f $k, $v }
Out 'START_PANELS' (@('Check', 'Dns', 'Dhcp', 'Print', 'Ad', 'Upload' | ForEach-Object { '{0}:{1}' -f $_, $ui["PnlAs$_"].Visibility }) -join ',')
Out 'START_BACK' $ui.BtnAsBack.IsEnabled
Out 'START_NEXT' $ui.BtnAsNext.IsEnabled
Set-SmAsRoles -State $c.State -Roles ([pscustomobject]@{ Dns = $true; Dhcp = $false; Print = $false; Ad = $false })
Set-SmAsStepState -State $c.State -Key 'Check' -Value Done
Update-SmAsView
Out 'STATES' (@('Check', 'Dns', 'Dhcp', 'Print', 'Ad', 'Upload' | ForEach-Object { '{0}:{1}' -f $_, $ui["TxtAsState$_"].Text }) -join ',')
Out 'GO_ENABLED' (@('Check', 'Dns', 'Dhcp', 'Print', 'Ad', 'Upload' | ForEach-Object { '{0}:{1}' -f $_, $ui["BtnAsGo$_"].IsEnabled }) -join ',')
Out 'DIMMED' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $ui.BdgAsDhcp.Opacity))
$c.DnsStatus = [pscustomobject]@{ LoggingOn = $true; LogExists = $true }
Show-SmAsStep 'Dns'
Out 'DNS_VISIBLE' $ui.PnlAsDns.Visibility
Out 'CHECK_HIDDEN' $ui.PnlAsCheck.Visibility
Show-SmAsStep 'Dhcp'
Out 'NOT_INSTALLED_STAYS' $c.State.Current
$ui.BtnAsNext.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
Out 'NEXT_FROM_DNS' $c.State.Current
Out 'NEXT_SKIP_VISIBLE' ('{0}/{1}' -f $ui.BtnAsNext.Visibility, $ui.BtnAsSkip.Visibility)
$ui.BtnAsBack.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
Out 'BACK' $c.State.Current
$ui.BtnAsSkip.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
Out 'AFTER_SKIP' ('{0}/{1}' -f $c.State.Current, $c.State.Steps['Dns'].State)
$pd = Join-Path $script:SmAsDataRoot 'Print'; New-Item -ItemType Directory -Force $pd | Out-Null
$f = Join-Path $pd 'Print-Inventur-TEST.json'; [IO.File]::WriteAllText($f, '{"x":1}')
$c.State.StageDir = New-SmAsStageDir
[void](Add-SmAsStaged -State $c.State -Source 'PrintExport' -Kind 'PrintInventory' -Path $f)
Update-SmAsFileList
Out 'ROWS' $ui.PnlAsFiles.Children.Count
Out 'EMPTY_HINT' $ui.TxtAsFilesEmpty.Visibility
$row = $ui.PnlAsFiles.Children[0]
Out 'ROW_NAME' $row.FindName('Nm').Text
Out 'ROW_SHA' $row.FindName('Sha').Text
Out 'ROW_TIP' $row.FindName('Sha').ToolTip.Length
Out 'ROW_CHECKED' $row.FindName('Chk').IsChecked
$row.FindName('Chk').IsChecked = $false
Update-SmAsFileList
Out 'CHECK_KEPT' $ui.PnlAsFiles.Children[0].FindName('Chk').IsChecked
Out 'UPLOAD_NO_SHARE' $(Start-SmAsUpload; $ui.TxtAsUploadState.Text)
Show-SmAsStep 'Upload'
Out 'UPLOAD_NEXT_HIDDEN' ('{0}/{1}' -f $ui.BtnAsNext.Visibility, $ui.BtnAsSkip.Visibility)
Close-SmAssistantPage
Out 'STAGE_REMOVED' (-not (Test-Path -LiteralPath (Join-Path $script:SmAsDataRoot 'Assistent\x')) -and $null -eq $c.State.StageDir)
Out 'DONE' 'ok'
'@
$plBase = $pl.Replace('__REPO__', $Repo.Replace("'", "''")).Replace('__WORK__', $Work.Replace("'", "''"))
foreach ($theme in 'Light', 'Dark') {
    [IO.File]::WriteAllText($probe, $plBase.Replace('__THEME__', $theme), (New-Object Text.UTF8Encoding $true))
    $probeOut = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File $probe 2>&1 | Out-String
    $kv = @{}; foreach ($l in ($probeOut -split "`r?`n")) { if ($l -match '^([A-Z_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] } }
    $tag = "Fenster ($theme)"
    if ($theme -eq 'Dark' -and $kv['DONE'] -ne 'ok') { Write-Host $probeOut }
    if ($theme -eq 'Light' -and $kv['DONE'] -ne 'ok') { Write-Host $probeOut }
    Check "$tag baut mit Startseite, Namen vollstaendig, Assistent verdrahtet" ($kv['DONE'] -eq 'ok')
    if ($theme -ne 'Light') { continue }
    Check "$tag Start: nur Schritt 1 sichtbar, Zurueck aus, Weiter an" ($kv['START_PANELS'] -eq 'Check:Visible,Dns:Collapsed,Dhcp:Collapsed,Print:Collapsed,Ad:Collapsed,Upload:Collapsed' -and $kv['START_BACK'] -eq 'False' -and $kv['START_NEXT'] -eq 'True')
    Check "$tag Zustaende der Schrittzeilen: erledigt, offen, nicht installiert" ($kv['STATES'] -eq ('Check:erledigt,Dns:offen,Dhcp:nicht installiert,Print:nicht installiert,Ad:nicht installiert,Upload:offen') -and $kv['GO_ENABLED'] -match 'Dhcp:False' -and $kv['GO_ENABLED'] -match 'Dns:True' -and $kv['DIMMED'] -eq '0.5')
    Check "$tag Schritt DNS zeigt nur sein Panel, ein nicht installierter Schritt laesst sich nicht anwaehlen" ($kv['DNS_VISIBLE'] -eq 'Visible' -and $kv['CHECK_HIDDEN'] -eq 'Collapsed' -and $kv['NOT_INSTALLED_STAYS'] -eq 'Dns')
    Check "$tag Weiter geht von DNS direkt zum Upload (DHCP, Print, AD entfallen), dort sind Weiter und Ueberspringen weg" ($kv['NEXT_FROM_DNS'] -eq 'Upload' -and $kv['NEXT_SKIP_VISIBLE'] -eq 'Collapsed/Collapsed')
    Check "$tag Zurueck geht zu DNS, Ueberspringen setzt DNS auf uebersprungen und geht zum Upload" ($kv['BACK'] -eq 'Dns' -and $kv['AFTER_SKIP'] -eq 'Upload/Skipped')
    Check "$tag Dateiliste: eine Zeile mit Name, SHA256-Chip (gekuerzt, voller Wert im Tooltip), Haken; Haken bleibt beim Neuaufbau" ($kv['ROWS'] -eq '1' -and $kv['EMPTY_HINT'] -eq 'Collapsed' -and $kv['ROW_NAME'] -eq 'Print-Inventur-TEST.json' -and $kv['ROW_SHA'] -match '^[0-9A-F]{8}.{1,4}[0-9A-F]{4}$' -and $kv['ROW_TIP'] -eq ([string]::Format('SHA256 (vollst{0}ndig): ', [char]0xE4).Length + 64).ToString() -and $kv['ROW_CHECKED'] -eq 'True' -and $kv['CHECK_KEPT'] -eq 'False')
    Check "$tag Upload ohne Tauschordner: klare Meldung statt Fehler; Weiter/Ueberspringen beim Upload-Schritt weg; Sammelordner beim Schliessen entfernt" ($kv['UPLOAD_NO_SHARE'] -match 'Kein Tauschordner' -and $kv['UPLOAD_NEXT_HIDDEN'] -eq 'Collapsed/Collapsed' -and $kv['STAGE_REMOVED'] -eq 'True')
}

# ---------------------------------------------------------------- 9. Fehlerklasse "leerer Wert aus echtem Cmdlet" bei DHCP, Print, AD
# DHCP: Bereich ohne Start-/Endadresse/Maske/Zustand (Felder fehlen), Reservierung ohne Namen, Lease ohne ClientId, Option ohne Wert
function Get-DhcpServerv4Scope { [pscustomobject]@{ ScopeId = [ipaddress]'10.0.0.0'; Name = $null; SubnetMask = $null; StartRange = $null; EndRange = $null; State = $null; LeaseDuration = $null } }
function Get-DhcpServerv4OptionValue { [pscustomobject]@{ OptionId = 3; Name = $null; Value = $null } }
function Get-DhcpServerv4Reservation { [pscustomobject]@{ IPAddress = [ipaddress]'10.0.0.5'; ClientId = $null; Name = $null } }
function Get-DhcpServerv4ExclusionRange { }
function Get-DhcpServerv4Lease { [pscustomobject]@{ IPAddress = [ipaddress]'10.0.0.9'; ClientId = $null } }
function Get-DhcpServerv4Policy { }
function Get-DhcpServerv6Scope { }
function Get-DhcpServerv4Failover { }
function Get-DhcpServerv4FilterList { }
function Get-DhcpServerv4Filter { }
function Get-DhcpServerv4DnsSetting { }
function Get-DhcpServerv4Binding { [pscustomobject]@{ InterfaceAlias = $null; IPAddress = $null; BindingState = $null } }
function Get-DhcpServerv6OptionValue { }
function Get-DhcpServerInDC { throw 'kein AD' }
$sum = $null
try { $sum = Get-SmDhcpSummary } catch { $sum = $null; Write-Host ('INFO DHCP-Zusammenfassung mit leeren Werten wirft: ' + $_.Exception.Message) }
Check 'DHCP: Zusammenfassung mit leeren Werten (Name, Maske, Bereich, Zustand, Option, Lease-Kennung leer) wirft nicht, Felder sind leere Texte statt Fehler' ($sum -and @($sum.Scopes4).Count -eq 1 -and $sum.Scopes4[0].Mask -eq '' -and $sum.Scopes4[0].Start -eq '' -and $sum.Scopes4[0].Name -eq '' -and $sum.Scopes4[0].Leases -eq 1 -and @($sum.Scopes4[0].Options).Count -eq 1 -and @($sum.Bindings).Count -eq 1)
Check 'DHCP: Zusammenfassung wird vom Berater-Tool (gleiche Pruefung) gelesen, auch mit leeren Feldern' ($(try { $jp = Join-Path $Work 'dhcp-leer.json'; $rd = Write-SmDhcpSummaryFile -Summary $sum -Path $jp; $null -ne $rd } catch { Write-Host ('INFO ' + $_.Exception.Message); $false }))
foreach ($fn in 'Get-DhcpServerv4Scope', 'Get-DhcpServerv4OptionValue', 'Get-DhcpServerv4Reservation', 'Get-DhcpServerv4ExclusionRange', 'Get-DhcpServerv4Lease', 'Get-DhcpServerv4Policy', 'Get-DhcpServerv6Scope', 'Get-DhcpServerv4Failover', 'Get-DhcpServerv4FilterList', 'Get-DhcpServerv4Filter', 'Get-DhcpServerv4DnsSetting', 'Get-DhcpServerv4Binding', 'Get-DhcpServerv6OptionValue', 'Get-DhcpServerInDC') { Remove-Item "Function:\$fn" -ErrorAction SilentlyContinue }
# Print: Inventur mit leeren Werten (Ort, Kommentar, Treiberversion, Port ohne Adresse, Hersteller)
function Get-Printer { [pscustomobject]@{ Name = 'P1'; DriverName = $null; PortName = $null; ShareName = $null; Shared = $false; Published = $false; Location = $null; Comment = $null; Type = $null } }
function Get-PrinterDriver { [pscustomobject]@{ Name = 'Drv1'; DriverVersion = $null; PrinterEnvironment = $null; MajorVersion = $null; Manufacturer = $null } }
function Get-PrinterPort { [pscustomobject]@{ Name = 'LPT1:'; Description = $null; PrinterHostAddress = $null; PortNumber = $null } }
$inv = $null
try { $inv = Get-SmPrintInventoryData } catch { Write-Host ('INFO Print-Inventur mit leeren Werten wirft: ' + $_.Exception.Message) }
Check 'Print: Inventur mit leeren Werten (Treiber, Port, Ort, Version, Hersteller leer) wirft nicht und liefert Drucker, Treiber und Ports' ($inv -and @($inv.Printers).Count -eq 1 -and @($inv.Drivers).Count -eq 1 -and @($inv.Ports).Count -eq 1)
Check 'Print: leere Treiberversion und leere Umgebung ergeben leere Texte (keine Ausnahme)' ((ConvertTo-SmDriverVersion $null) -eq '' -and (Get-SmDriverArch '') -eq '' -and (Format-SmPrintName $null) -eq '' -and (Get-SmPrintLong $null) -eq 0)
Remove-Item Function:\Get-Printer, Function:\Get-PrinterDriver, Function:\Get-PrinterPort
# AD: Bericht mit leeren Werten (Funktionsebene, Schema, Rollenhalter)
$rep = [pscustomobject]@{ Created = ''; Computer = ''; Forest = [pscustomobject]@{ Name = ''; Mode = ''; SchemaVersion = 0; SchemaName = '' }; Domain = [pscustomobject]@{ Name = ''; Mode = '' }; DomainControllers = @([pscustomobject]@{ HostName = 'dc01.contoso.local'; Domain = ''; Site = ''; OperatingSystem = ''; IsGlobalCatalog = $false; IsReadOnly = $false }); Fsmo = @([pscustomobject]@{ Role = 'PDCEmulator'; Holder = '' }); Replication = [pscustomobject]@{ Ok = $true; Failures = @() }; Dcdiag = @(); Errors = @() }
Check 'AD: Berichtstext mit leeren Werten (Ebene, Schema, Standort, Betriebssystem, Rollenhalter leer) wirft nicht, leere Ebene heisst "unbekannt"' ($(try { $tx = Format-SmAdReportText -Report $rep; $tx -match 'unbekannt' -and $tx -match 'dc01.contoso.local' } catch { $false }))
Check 'AD: ConvertTo-SmAdLevelNumber mit leer, $null und Unsinn liefert $null (keine Ausnahme)' ($null -eq (ConvertTo-SmAdLevelNumber '') -and $null -eq (ConvertTo-SmAdLevelNumber $null) -and $null -eq (ConvertTo-SmAdLevelNumber 'Quatsch'))

Write-Host ''
Write-Host "$fails Fehler in tests\Test-Assistent.ps1"
$fails
