<#
.SYNOPSIS
    Phase 6 (Active Directory), Server-Fenster: Uebersicht (nur lesend), FSMO uebertragen und uebernehmen, DSRM-Kennwort,
    Funktionsebenen anheben, Schema-Update (adprep). Laeuft auf dem NEUEN Domaenencontroller.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht Modules\SmAd.ps1, Modules\SmTausch.ps1, server\SmDnsServer.ps1 fuer Protect-SmDnsStateDir
    und fuer die Oberflaeche Modules\SmShell.ps1). Jede aendernde Aktion hat eine Vorpruefung, verlangt -Confirmed (die Oberflaeche holt vorher
    die Bestaetigung, Ebenen und Seize zusaetzlich mit getipptem Namen) und schreibt eine Protokollzeile ohne Geheimnisse, auch bei Fehlern.
    Das DSRM-Kennwort geht nur ueber die Standardeingabe von ntdsutil, nie als Argument, und steht in keiner Datei, keinem Protokoll
    und keiner Fehlermeldung. Ordner unter ProgramData werden mit Protect-SmDnsStateDir gehaertet (Besitzer und ACL nur Administratoren und SYSTEM).
    Cmdlets (Microsoft Learn): Move-ADDirectoryServerOperationMasterRole -Identity <ADDirectoryServer> -OperationMasterRole <ADOperationMasterRole[]> [-Force] [-Confirm],
    -Force = Seize (versucht erst die Uebertragung). Set-ADDomainMode -Identity -DomainMode [-Server] [-Confirm], Set-ADForestMode -Identity -ForestMode [-Server] [-Confirm].
    ntdsutil: "set dsrm password" / "reset password on server <DC|NULL>" / "sync from domain account <konto>" / q q.
    Windows PowerShell 5.1.
#>

$script:SmAdDataRoot = $null          # nur fuer Tests: anderer Wurzelordner statt ProgramData\ServerMigration
$script:SmAdToolPaths = @{}           # nur fuer Tests: Stub statt repadmin.exe, dcdiag.exe, ntdsutil.exe
$script:SmAdDcdiagTests = @('KnowsOfRoleHolders', 'Advertising', 'Replications', 'Services', 'RidManager', 'MachineAccount', 'FsmoCheck', 'NCSecDesc')
$script:SmAdRoles = @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster', 'SchemaMaster', 'DomainNamingMaster')
$script:SmAdToolTimeoutSec = 600
$script:SmAdAdprepTimeoutSec = 3600

# ---------------------------------------------------------------- Grundlagen

function Test-SmAdIsAdmin {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false }
}

function Assert-SmAdModule {
    <# Das AD-Modul muss da sein, sonst eine klare Meldung. #>
    if (-not (Get-Command Get-ADForest -ErrorAction SilentlyContinue)) { try { Import-Module ActiveDirectory -ErrorAction Stop } catch { } }
    if (-not (Get-Command Get-ADForest -ErrorAction SilentlyContinue)) {
        throw 'Das PowerShell-Modul ActiveDirectory fehlt. Es ist auf Domaenencontrollern dabei, sonst: Install-WindowsFeature RSAT-AD-PowerShell. Active Directory Aktionen sind ohne dieses Modul nicht moeglich.'
    }
}

function Get-SmAdToolPath {
    param([Parameter(Mandatory)][ValidateSet('repadmin', 'dcdiag', 'ntdsutil')][string]$Name)
    if ($script:SmAdToolPaths[$Name]) { return $script:SmAdToolPaths[$Name] }
    Join-Path $env:windir "System32\$Name.exe"
}

function Get-SmAdFolder {
    <# Ordner fuer Protokoll, Berichte und adprep-Ausgabe: unter ProgramData, gehaertet mit Protect-SmDnsStateDir (bricht bei jedem Problem ab). #>
    $root = if ($script:SmAdDataRoot) { $script:SmAdDataRoot } else { Join-Path $env:ProgramData 'ServerMigration' }
    Protect-SmDnsStateDir -Path $root
    $dir = Join-Path $root 'AD'
    Protect-SmDnsStateDir -Path $dir
    $dir
}

function Write-SmAdAudit {
    <# Protokollzeile ohne Geheimnisse. Wirft, wenn sie nicht geschrieben werden kann (nicht still schlucken). #>
    param([Parameter(Mandatory)][string]$Action, [string]$Target = '', [Parameter(Mandatory)][string]$Result, [string]$Detail = '')
    $d = ($Detail -replace '[\r\n]+', ' ').Trim()
    if ($d.Length -gt 300) { $d = $d.Substring(0, 300) + '...' }
    $user = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { '?' }
    $line = '{0:yyyy-MM-dd HH:mm:ss} | {1} | {2} | {3} | {4} | {5} | {6}' -f (Get-Date), $env:COMPUTERNAME, $user, $Action, $Target, $Result, $d
    $file = Join-Path (Get-SmAdFolder) 'Protokoll.log'
    [IO.File]::AppendAllText($file, $line + "`r`n", (New-Object Text.UTF8Encoding $false))
    $line
}

function Invoke-SmAdAudited {
    <# Fuehrt eine aendernde Aktion aus und protokolliert Erfolg oder Fehler. Schreibfehler im Protokoll werden der Meldung angefuegt. #>
    param([Parameter(Mandatory)][string]$What, [string]$Subject = '', [Parameter(Mandatory)][scriptblock]$Body)
    # Namen bewusst nicht Action/Target: der Body laeuft im dynamischen Geltungsbereich und braucht die Variablen des Aufrufers
    try { $result = & $Body }
    catch {
        $msg = $_.Exception.Message
        $logErr = $null
        try { [void](Write-SmAdAudit -Action $What -Target $Subject -Result 'fehlgeschlagen' -Detail $msg) } catch { $logErr = $_.Exception.Message }
        if ($logErr) { $msg += ' (Das Protokoll konnte nicht geschrieben werden: ' + $logErr + ')' }
        throw $msg
    }
    try { [void](Write-SmAdAudit -Action $What -Target $Subject -Result 'erfolgreich' -Detail ([string]$result.Detail)) }
    catch { throw ('Die Aktion wurde ausgefuehrt, aber das Protokoll konnte nicht geschrieben werden: ' + $_.Exception.Message) }
    $result
}

function Test-SmAdChecksPassed {
    param([Parameter(Mandatory)][object[]]$Checks)
    -not ($Checks | Where-Object { $_.Blocking -and -not $_.Ok })
}

function New-SmAdCheck {
    param([string]$Name, [bool]$Ok, [string]$Text, [bool]$Blocking = $true)
    [pscustomobject]@{ Name = $Name; Ok = $Ok; Blocking = $Blocking; Text = $Text }
}

function Format-SmAdChecks {
    param([Parameter(Mandatory)][object[]]$Checks)
    ($Checks | ForEach-Object { '{0}  {1}: {2}' -f $(if ($_.Ok) { '[ok]    ' } elseif ($_.Blocking) { '[FEHLT] ' } else { '[Hinweis]' }), $_.Name, $_.Text }) -join "`r`n"
}

# ---------------------------------------------------------------- Prozesse (repadmin, dcdiag, ntdsutil, adprep)

function Invoke-SmAdProcess {
    <#
    .SYNOPSIS
        Startet ein Programm ohne Shell. Arguments ist die ganze Kommandozeile (ohne Programmnamen) und darf nie ein Geheimnis enthalten.
        StdIn: Zeilen fuer die Standardeingabe. Secret (SecureString): wird SecretRepeat-mal als Zeile auf die Standardeingabe geschrieben,
        direkt aus einem Zeichenfeld, das danach ueberschrieben wird; es entsteht kein Klartext-String.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath, [string]$Arguments = '', [string[]]$StdIn = @(), [securestring]$Secret, [int]$SecretRepeat = 1,
        [int]$TimeoutSec = $script:SmAdToolTimeoutSec
    )
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw ('Programm nicht gefunden: ' + (Split-Path -Leaf $FilePath)) }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath; $psi.Arguments = $Arguments; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $enc = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    $psi.StandardOutputEncoding = $enc; $psi.StandardErrorEncoding = $enc
    $p = New-Object Diagnostics.Process; $p.StartInfo = $psi
    [void]$p.Start()   # diesen Prozess haben wir selbst gestartet; nur ihn beenden wir bei Zeitueberschreitung
    $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
    try {
        foreach ($l in $StdIn) { $p.StandardInput.WriteLine($l) }
        if ($Secret) {
            $bstr = [IntPtr]::Zero; $chars = $null
            try {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
                $chars = New-Object char[] $Secret.Length
                [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $chars.Length)
                for ($i = 0; $i -lt $SecretRepeat; $i++) { $p.StandardInput.Write($chars, 0, $chars.Length); $p.StandardInput.WriteLine() }
            }
            finally {
                if ($chars) { [Array]::Clear($chars, 0, $chars.Length) }
                if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            }
        }
        try { $p.StandardInput.Close() } catch { }
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; throw ('Zeitueberschreitung bei ' + (Split-Path -Leaf $FilePath)) }
        $p.WaitForExit()
        $text = $outTask.Result + $errTask.Result
        [pscustomobject]@{ ExitCode = $p.ExitCode; Lines = @($text -split "`r?`n" | Where-Object { $_.Trim() }) }
    }
    finally { $p.Dispose() }
}

# ---------------------------------------------------------------- Replikation und dcdiag

function Test-SmAdReplication {
    <# repadmin /replsummary und /showrepl * /csv. Ok nur, wenn beides lesbar ist und keine Fehler zeigt. #>
    $repadmin = Get-SmAdToolPath 'repadmin'
    $failures = New-Object System.Collections.Generic.List[string]
    $summary = @(); $readable = $true
    $s = Invoke-SmAdProcess -FilePath $repadmin -Arguments '/replsummary'
    $summary = $s.Lines
    if ($s.ExitCode -ne 0) { $failures.Add("repadmin /replsummary: Exitcode $($s.ExitCode)") }
    $rows = 0
    foreach ($line in $s.Lines) {
        # Zeilen der Tabellen: <DC> <Delta> <Fehler> / <Gesamt> <Prozent>
        if ($line -match '^\s*(\S+)\s+\S+\s+(\d+)\s*/\s*(\d+)\s+(\d+)') { $rows++; if ([int]$Matches[2] -gt 0) { $failures.Add(('{0}: {1} von {2} Replikationen fehlgeschlagen' -f $Matches[1], $Matches[2], $Matches[3])) } }
    }
    if (-not $rows) { $readable = $false }
    $c = Invoke-SmAdProcess -FilePath $repadmin -Arguments '/showrepl * /csv'
    if ($c.ExitCode -ne 0) { $failures.Add("repadmin /showrepl: Exitcode $($c.ExitCode)") }
    $hdr = @($c.Lines | Where-Object { $_ -match 'Number of Failures' } | Select-Object -First 1)
    if ($hdr.Count) {
        $names = @($hdr[0] -split ',' | ForEach-Object { $_.Trim('"') })
        $ix = [array]::IndexOf($names, 'Number of Failures')
        foreach ($line in ($c.Lines | Where-Object { $_ -notmatch 'Number of Failures' })) {
            $f = @(([regex]'("([^"]*)"|[^,]*)(,|$)').Matches($line) | ForEach-Object { $_.Groups[1].Value.Trim('"') })
            if ($ix -ge 0 -and $f.Count -gt $ix -and $f[$ix] -match '^\d+$' -and [int]$f[$ix] -gt 0) { $failures.Add(('Replikation {0} nach {1}: {2} Fehler' -f $f[[array]::IndexOf($names, 'Source DSA')], $f[[array]::IndexOf($names, 'Destination DSA')], $f[$ix])) }
        }
    }
    else { $readable = $false }
    [pscustomobject]@{ Ok = ($readable -and -not $failures.Count); Readable = $readable; Failures = @($failures | Select-Object -First 100); Summary = @($summary | Select-Object -First 80) }
}

function Test-SmAdDcdiag {
    <# dcdiag /q /test:<Name>, je Test einzeln (die Doku kennt /test nur einfach). /q druckt nur Fehler: jede Ausgabe oder Exitcode ungleich 0 ist ein Fehler. #>
    param([string[]]$Tests = $script:SmAdDcdiagTests, [switch]$Dns)
    $dcdiag = Get-SmAdToolPath 'dcdiag'
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in $Tests) {
        if ($t -notmatch '^[A-Za-z]{3,40}$') { throw "Ungueltiger dcdiag-Test: $t" }
        $r = Invoke-SmAdProcess -FilePath $dcdiag -Arguments "/q /test:$t"
        $out.Add([pscustomobject]@{ Name = $t; Ok = ($r.ExitCode -eq 0 -and -not $r.Lines.Count); Lines = @($r.Lines | Select-Object -First 30) })
    }
    if ($Dns) {
        $r = Invoke-SmAdProcess -FilePath $dcdiag -Arguments '/q /test:DNS /DnsRecordRegistration'
        $out.Add([pscustomobject]@{ Name = 'DNS-Registrierung'; Ok = ($r.ExitCode -eq 0 -and -not $r.Lines.Count); Lines = @($r.Lines | Select-Object -First 30) })
    }
    $out.ToArray()
}

# ---------------------------------------------------------------- Lesen

function Get-SmAdSchemaVersion {
    param([string]$Server)
    $srv = if ($Server) { @{ Server = $Server } } else { @{} }
    $nc = (Get-ADRootDSE @srv).schemaNamingContext
    [int](Get-ADObject -Identity $nc -Properties objectVersion @srv).objectVersion
}

function Get-SmAdFsmoMap {
    <# Rolle -> Inhaber (FQDN) und der Kontext. #>
    Assert-SmAdModule
    $forest = Get-ADForest; $domain = Get-ADDomain
    $map = [ordered]@{
        PDCEmulator = [string]$domain.PDCEmulator; RIDMaster = [string]$domain.RIDMaster; InfrastructureMaster = [string]$domain.InfrastructureMaster
        SchemaMaster = [string]$forest.SchemaMaster; DomainNamingMaster = [string]$forest.DomainNamingMaster
    }
    [pscustomobject]@{ Map = $map; Forest = $forest; Domain = $domain }
}

function Test-SmAdIsLocalHost {
    param([string]$Name)
    if (-not $Name) { return $false }
    $short = ($Name -split '\.')[0]
    $short -ieq $env:COMPUTERNAME
}

function Get-SmAdOverview {
    <# Alles nur lesend. Fehler einzelner Teile landen in Errors, der Rest wird trotzdem geliefert. #>
    param([switch]$IncludeDns)
    Assert-SmAdModule
    $errors = New-Object System.Collections.Generic.List[string]
    $ctx = Get-SmAdFsmoMap
    $forest = $ctx.Forest; $domain = $ctx.Domain
    $schemaVersion = 0
    try { $schemaVersion = Get-SmAdSchemaVersion } catch { $errors.Add('Schema-Version nicht lesbar: ' + $_.Exception.Message) }
    $dcs = New-Object System.Collections.Generic.List[object]; $domainLevels = @{}
    foreach ($d in @($forest.Domains)) {
        try {
            $dm = Get-ADDomain -Identity $d
            $domainLevels[[string]$d] = [string]$dm.DomainMode
            foreach ($dc in @(Get-ADDomainController -Filter * -Server $d)) {
                $dcs.Add([pscustomobject]@{ HostName = [string]$dc.HostName; Domain = [string]$d; Site = [string]$dc.Site; OperatingSystem = [string]$dc.OperatingSystem; IsGlobalCatalog = [bool]$dc.IsGlobalCatalog; IsReadOnly = [bool]$dc.IsReadOnly })
            }
        }
        catch { $errors.Add(('Domaene {0} nicht lesbar: {1}' -f $d, $_.Exception.Message)) }
    }
    $repl = $null; $dcdiag = @()
    try { $repl = Test-SmAdReplication } catch { $errors.Add('Replikation nicht pruefbar: ' + $_.Exception.Message) }
    try { $dcdiag = @(Test-SmAdDcdiag -Dns:$IncludeDns) } catch { $errors.Add('dcdiag nicht ausfuehrbar: ' + $_.Exception.Message) }
    [ordered]@{
        Schema = $script:SmAdReportSchema; Kind = 'AD-Bericht'; Created = (Get-Date).ToString('s'); Computer = $env:COMPUTERNAME
        Forest = [ordered]@{ Name = [string]$forest.Name; Mode = [string]$forest.ForestMode; SchemaVersion = $schemaVersion; SchemaName = (Get-SmAdSchemaName $schemaVersion) }
        Domain = [ordered]@{ Name = [string]$domain.DNSRoot; Mode = [string]$domain.DomainMode }
        DomainLevels = $domainLevels
        DomainControllers = $dcs.ToArray()
        Fsmo = @($ctx.Map.GetEnumerator() | ForEach-Object { [ordered]@{ Role = $_.Key; Holder = $_.Value } })
        Replication = [ordered]@{ Ok = [bool]($repl -and $repl.Ok); Failures = @($(if ($repl) { $repl.Failures } else { 'nicht pruefbar' })) }
        Dcdiag = @($dcdiag | ForEach-Object { [ordered]@{ Name = $_.Name; Ok = $_.Ok; Lines = @($_.Lines) } })
        Errors = $errors.ToArray()
    }
}

function New-SmAdReport {
    <# Schreibt den Bericht (JSON, ohne Geheimnisse) in den gehaerteten AD-Ordner. Liefert den Pfad. #>
    param([Parameter(Mandatory)]$Overview)
    $name = 'AD-Bericht-{0}-{1:yyyyMMdd-HHmmss}.json' -f ($env:COMPUTERNAME -replace '[^\w.\-]', '_'), (Get-Date)
    $path = Join-Path (Get-SmAdFolder) $name
    $copy = [ordered]@{}; foreach ($k in $Overview.Keys) { if ($k -ne 'DomainLevels') { $copy[$k] = $Overview[$k] } }
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $copy -Depth 8), (New-Object Text.UTF8Encoding $false))
    $path
}

# ---------------------------------------------------------------- Rechte

function Get-SmAdTokenSids {
    [string[]]@([Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value })
}

function Get-SmAdGroupSids {
    <# SIDs von Domain Admins (Domaene), Enterprise und Schema Admins (Gesamtstruktur-Stammdomaene). #>
    param([Parameter(Mandatory)]$Ctx)
    $rootSid = [string](Get-ADDomain -Identity $Ctx.Forest.RootDomain).DomainSID.Value
    @{ DomainAdmins = ([string]$Ctx.Domain.DomainSID.Value + '-512'); EnterpriseAdmins = ($rootSid + '-519'); SchemaAdmins = ($rootSid + '-518') }
}

function Test-SmAdRights {
    <# Pruefung der Gruppenmitgliedschaft im Token. Need: DomainAdmins, EnterpriseAdmins, SchemaAdmins. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string[]]$Need)
    $sids = Get-SmAdGroupSids -Ctx $Ctx; $have = @(Get-SmAdTokenSids)
    $label = @{ DomainAdmins = 'Domain Admins'; EnterpriseAdmins = 'Enterprise Admins'; SchemaAdmins = 'Schema Admins' }
    foreach ($n in ($Need | Select-Object -Unique)) { New-SmAdCheck ('Mitglied von ' + $label[$n]) ($have -contains $sids[$n]) $(if ($have -contains $sids[$n]) { 'ja' } else { 'Das angemeldete Konto ist (in diesem Anmeldevorgang) nicht Mitglied. Neu anmelden, wenn es gerade aufgenommen wurde.' }) }
}

# ---------------------------------------------------------------- Erreichbarkeit

function Test-SmAdHostReachable {
    <# Erreichbar, wenn Ping oder LDAP (389) antwortet. Nur wenn beides fehlschlaegt, gilt der Server als nicht erreichbar. #>
    param([Parameter(Mandatory)][string]$HostName)
    if ($HostName -notmatch '^[A-Za-z0-9.\-]{1,255}$') { throw "Ungueltiger Servername: $HostName" }
    try { if (Test-Connection -ComputerName $HostName -Count 2 -Quiet -ErrorAction Stop) { return $true } } catch { }
    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($HostName, 389, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(3000) -and $tcp.Connected) { $tcp.EndConnect($iar); return $true }
    }
    catch { }
    finally { $tcp.Close() }
    $false
}

# ---------------------------------------------------------------- FSMO

function Test-SmAdFsmoPrecheck {
    <# Vorpruefung fuer die Uebertragung auf DIESEN Server. #>
    param([Parameter(Mandatory)][string[]]$Roles)
    $Roles = @($Roles | Select-Object -Unique)
    foreach ($r in $Roles) { if ($script:SmAdRoles -notcontains $r) { throw "Unbekannte Rolle: $r" } }
    $checks = New-Object System.Collections.Generic.List[object]
    $checks.Add((New-SmAdCheck 'Administrator' (Test-SmAdIsAdmin) 'Das Fenster muss als Administrator laufen.'))
    Assert-SmAdModule
    $m = Get-SmAdFsmoMap
    $local = Get-ADDomainController -Identity $env:COMPUTERNAME
    $checks.Add((New-SmAdCheck 'Beschreibbarer DC' (-not [bool]$local.IsReadOnly) $(if ($local.IsReadOnly) { 'Dieser Server ist ein RODC und kann keine Rollen halten.' } else { 'Dieser Server ist ein beschreibbarer Domaenencontroller.' })))
    $need = @('DomainAdmins'); if ($Roles -contains 'SchemaMaster') { $need += 'SchemaAdmins' }; if ($Roles -contains 'DomainNamingMaster') { $need += 'EnterpriseAdmins' }
    foreach ($c in (Test-SmAdRights -Ctx $m -Need $need)) { $checks.Add($c) }
    $toMove = @()
    foreach ($r in $Roles) {
        $holder = $m.Map[$r]
        if (Test-SmAdIsLocalHost $holder) { $checks.Add((New-SmAdCheck "$r liegt schon hier" $true $holder $false)); continue }
        $toMove += $r
        $reach = Test-SmAdHostReachable -HostName $holder
        $checks.Add((New-SmAdCheck "Inhaber von $r erreichbar" $reach $(if ($reach) { $holder } else { "$holder antwortet nicht. Bei dauerhaft ausgefallenem Server gibt es den getrennten Schritt Seize." })))
    }
    $checks.Add((New-SmAdCheck 'Etwas zu uebertragen' ($toMove.Count -gt 0) $(if ($toMove.Count) { $toMove -join ', ' } else { 'Alle gewaehlten Rollen liegen schon hier.' })))
    $repl = Test-SmAdReplication
    $checks.Add((New-SmAdCheck 'Replikation ohne Fehler' $repl.Ok $(if ($repl.Ok) { 'repadmin meldet keine Fehler' } elseif (-not $repl.Readable) { 'repadmin-Ausgabe nicht lesbar' } else { $repl.Failures -join '; ' })))
    $dd = @(Test-SmAdDcdiag)
    $bad = @($dd | Where-Object { -not $_.Ok })
    $checks.Add((New-SmAdCheck 'dcdiag ohne Fehler' (-not $bad.Count) $(if ($bad.Count) { 'Fehler in: ' + (($bad | ForEach-Object Name) -join ', ') } else { ($dd.Count.ToString() + ' Tests bestanden') })))
    if ($Roles -contains 'InfrastructureMaster' -and [bool]$local.IsGlobalCatalog) {
        $allGc = -not (@(Get-ADDomainController -Filter * | Where-Object { -not $_.IsGlobalCatalog }).Count)
        if (@($m.Forest.Domains).Count -gt 1 -and -not $allGc) { $checks.Add((New-SmAdCheck 'Infrastrukturmaster und Globaler Katalog' $false 'Dieser Server ist ein Globaler Katalog, aber nicht alle DCs sind es. In einer Gesamtstruktur mit mehreren Domaenen sollte der Infrastrukturmaster kein GC sein.' $false)) }
    }
    [pscustomobject]@{ Checks = $checks.ToArray(); Ok = (Test-SmAdChecksPassed $checks.ToArray()); ToMove = $toMove; Map = $m.Map }
}

function Invoke-SmAdFsmoTransfer {
    <# Uebertraegt die Rollen auf diesen Server (ohne -Force, also eine echte Uebertragung). #>
    param([Parameter(Mandatory)][string[]]$Roles, [switch]$Confirmed)
    $target = ($Roles -join ',') + ' -> ' + $env:COMPUTERNAME
    Invoke-SmAdAudited -What 'FSMO uebertragen' -Subject $target -Body {
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        $pre = Test-SmAdFsmoPrecheck -Roles $Roles
        if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden, nichts geaendert: ' + ((@($pre.Checks | Where-Object { $_.Blocking -and -not $_.Ok } | ForEach-Object { $_.Name })) -join '; ')) }
        $dc = Get-ADDomainController -Identity $env:COMPUTERNAME
        Move-ADDirectoryServerOperationMasterRole -Identity $dc -OperationMasterRole $pre.ToMove -Confirm:$false
        $after = (Get-SmAdFsmoMap).Map
        $missing = @($pre.ToMove | Where-Object { -not (Test-SmAdIsLocalHost $after[$_]) })
        if ($missing.Count) { throw ('Nachpruefung: diese Rollen liegen noch nicht hier: ' + ($missing -join ', ')) }
        [pscustomobject]@{ Moved = $pre.ToMove; Before = $pre.Map; After = $after; Detail = ('uebertragen: ' + ($pre.ToMove -join ', ')) }
    }
}

function Invoke-SmAdFsmoSeize {
    <# Seize einer einzelnen Rolle. Nur wenn der Inhaber nicht erreichbar ist und der Rollenname getippt wurde. #>
    param([Parameter(Mandatory)][string]$Role, [string]$TypedRole, [switch]$Confirmed)
    Invoke-SmAdAudited -What 'FSMO Seize' -Subject ($Role + ' -> ' + $env:COMPUTERNAME) -Body {
        if ($script:SmAdRoles -cnotcontains $Role) { throw "Unbekannte Rolle: $Role" }
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        if ($TypedRole -cne $Role) { throw 'Der getippte Rollenname stimmt nicht, nichts geaendert.' }
        if (-not (Test-SmAdIsAdmin)) { throw 'Das Fenster laeuft nicht als Administrator.' }
        Assert-SmAdModule
        $m = Get-SmAdFsmoMap; $holder = $m.Map[$Role]
        if (Test-SmAdIsLocalHost $holder) { throw "$Role liegt schon auf diesem Server." }
        if (Test-SmAdHostReachable -HostName $holder) { throw "Der Inhaber $holder ist erreichbar. Seize ist dafuer nicht erlaubt: bitte normal uebertragen." }
        $local = Get-ADDomainController -Identity $env:COMPUTERNAME
        if ($local.IsReadOnly) { throw 'Dieser Server ist ein RODC.' }
        $need = @('DomainAdmins'); if ($Role -eq 'SchemaMaster') { $need += 'SchemaAdmins' }; if ($Role -eq 'DomainNamingMaster') { $need += 'EnterpriseAdmins' }
        $rights = @(Test-SmAdRights -Ctx $m -Need $need | Where-Object { -not $_.Ok })
        if ($rights.Count) { throw ('Rechte fehlen: ' + (($rights | ForEach-Object Name) -join '; ')) }
        Move-ADDirectoryServerOperationMasterRole -Identity $local -OperationMasterRole $Role -Force -Confirm:$false
        $after = (Get-SmAdFsmoMap).Map
        if (-not (Test-SmAdIsLocalHost $after[$Role])) { throw "Nachpruefung: $Role liegt nicht auf diesem Server." }
        [pscustomobject]@{ Before = $holder; Detail = "uebernommen von $holder (nicht erreichbar); der alte Server darf nie wieder ans Netz" }
    }
}

# ---------------------------------------------------------------- DSRM

function Test-SmAdPasswordComplexity {
    <# Laenge mindestens 12 und mindestens drei von vier Zeichenarten. Arbeitet auf einem Zeichenfeld, das danach geloescht wird. #>
    param([Parameter(Mandatory)][securestring]$Password)
    $problems = New-Object System.Collections.Generic.List[string]
    $bstr = [IntPtr]::Zero; $chars = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $chars = New-Object char[] $Password.Length
        [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $chars.Length)
        if ($chars.Length -lt 12) { $problems.Add('mindestens 12 Zeichen') }
        $kinds = 0
        if ($chars | Where-Object { [char]::IsUpper($_) } | Select-Object -First 1) { $kinds++ }
        if ($chars | Where-Object { [char]::IsLower($_) } | Select-Object -First 1) { $kinds++ }
        if ($chars | Where-Object { [char]::IsDigit($_) } | Select-Object -First 1) { $kinds++ }
        if ($chars | Where-Object { -not [char]::IsLetterOrDigit($_) } | Select-Object -First 1) { $kinds++ }
        if ($kinds -lt 3) { $problems.Add('mindestens drei von: Grossbuchstaben, Kleinbuchstaben, Ziffern, Sonderzeichen') }
        if ($chars | Where-Object { $_ -in [char]'"', [char]"'", [char]0 } | Select-Object -First 1) { $problems.Add('keine Anfuehrungszeichen (ntdsutil verarbeitet sie nicht richtig)') }
    }
    finally { if ($chars) { [Array]::Clear($chars, 0, $chars.Length) }; if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
    [pscustomobject]@{ Ok = (-not $problems.Count); Problems = $problems.ToArray() }
}

function Test-SmAdSecureEqual {
    param([Parameter(Mandatory)][securestring]$A, [Parameter(Mandatory)][securestring]$B)
    if ($A.Length -ne $B.Length) { return $false }
    $ba = [IntPtr]::Zero; $bb = [IntPtr]::Zero; $ca = $null; $cb = $null
    try {
        $ba = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($A); $bb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($B)
        $ca = New-Object char[] $A.Length; $cb = New-Object char[] $B.Length
        [Runtime.InteropServices.Marshal]::Copy($ba, $ca, 0, $ca.Length); [Runtime.InteropServices.Marshal]::Copy($bb, $cb, 0, $cb.Length)
        $diff = 0; for ($i = 0; $i -lt $ca.Length; $i++) { $diff = $diff -bor ([int]$ca[$i] -bxor [int]$cb[$i]) }
        $diff -eq 0
    }
    finally {
        if ($ca) { [Array]::Clear($ca, 0, $ca.Length) }; if ($cb) { [Array]::Clear($cb, 0, $cb.Length) }
        if ($ba -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ba) }; if ($bb -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bb) }
    }
}

function Invoke-SmAdDsrmSync {
    <# Variante A: ntdsutil "set dsrm password" "sync from domain account <konto>" q q. Das Tool beruehrt kein Kennwort. Wirkt nur auf diesen Server (laut Doku). #>
    param([Parameter(Mandatory)][string]$Account, [switch]$Confirmed)
    Invoke-SmAdAudited -What 'DSRM mit Domaenenkonto synchronisieren' -Subject ($env:COMPUTERNAME + ' <- ' + $Account) -Body {
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        if ($Account -notmatch '^[\w.\-]{1,64}(\\[\w.\-]{1,64})?$') { throw 'Kontoname: nur Buchstaben, Ziffern, Punkt, Bindestrich, Unterstrich (optional DOMAENE\Konto).' }
        if (-not (Test-SmAdIsAdmin)) { throw 'Das Fenster laeuft nicht als Administrator.' }
        Assert-SmAdModule
        $local = Get-ADDomainController -Identity $env:COMPUTERNAME
        if ($local.IsReadOnly) { throw 'Dieser Server ist ein RODC.' }
        $acct = ($Account -split '\\')[-1]
        $u = Get-ADUser -Identity $acct
        if (-not $u -or $u.Enabled -eq $false) { throw 'Das Konto existiert nicht oder ist deaktiviert.' }
        $r = Invoke-SmAdProcess -FilePath (Get-SmAdToolPath 'ntdsutil') -Arguments ('"set dsrm password" "sync from domain account {0}" q q' -f $Account)
        if ($r.ExitCode -ne 0) { throw ('ntdsutil meldete einen Fehler (Exitcode {0}): {1}' -f $r.ExitCode, (($r.Lines | Select-Object -First 3) -join ' | ')) }
        [pscustomobject]@{ Detail = 'ntdsutil ohne Fehler (Exitcode 0), Kennwort wurde nicht angefasst'; Lines = $r.Lines }
    }
}

function Invoke-SmAdDsrmReset {
    <# Variante B: neues Kennwort. Dc: NULL oder leer = dieser Server, sonst Name des DC ("reset password on server <DC>"). Kennwort nur ueber die Standardeingabe. #>
    param([Parameter(Mandatory)][securestring]$Password, [Parameter(Mandatory)][securestring]$Confirm, [string]$Dc = '', [switch]$Confirmed)
    $dcName = if (-not $Dc -or $Dc -ieq 'NULL' -or (Test-SmAdIsLocalHost $Dc)) { 'NULL' } else { $Dc }
    Invoke-SmAdAudited -What 'DSRM-Kennwort setzen' -Subject ($env:COMPUTERNAME + ' -> ' + $(if ($dcName -eq 'NULL') { $env:COMPUTERNAME } else { $dcName })) -Body {
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        if ($dcName -ne 'NULL' -and $dcName -notmatch '^[A-Za-z0-9.\-]{1,255}$') { throw 'Servername: nur Buchstaben, Ziffern, Punkt und Bindestrich.' }
        if (-not (Test-SmAdIsAdmin)) { throw 'Das Fenster laeuft nicht als Administrator.' }
        if (-not (Test-SmAdSecureEqual $Password $Confirm)) { throw 'Die beiden Eingaben stimmen nicht ueberein.' }
        $cx = Test-SmAdPasswordComplexity $Password
        if (-not $cx.Ok) { throw ('Das Kennwort ist nicht komplex genug: ' + ($cx.Problems -join '; ')) }
        if ($dcName -ne 'NULL' -and -not (Test-SmAdHostReachable -HostName $dcName)) { throw "Der DC $dcName ist nicht erreichbar." }
        $r = Invoke-SmAdProcess -FilePath (Get-SmAdToolPath 'ntdsutil') -Arguments ('"set dsrm password" "reset password on server {0}" q q' -f $dcName) -Secret $Password -SecretRepeat 2
        # Die Ausgabe wird nie angezeigt oder protokolliert (sie koennte das Kennwort wiedergeben).
        if ($r.ExitCode -ne 0) { throw ('ntdsutil meldete einen Fehler (Exitcode {0}). Die Ausgabe wird aus Sicherheitsgruenden nicht angezeigt.' -f $r.ExitCode) }
        [pscustomobject]@{ Detail = 'ntdsutil ohne Fehler (Exitcode 0); Kennwort nicht protokolliert' }
    }
}

# ---------------------------------------------------------------- Funktionsebenen

function Get-SmAdLevelPlan {
    <# Sammelt die Daten und prueft per Test-SmAdLevelRaise. #>
    param([Parameter(Mandatory)][ValidateSet('Domain', 'Forest')][string]$Scope, [Parameter(Mandatory)][int]$Target)
    Assert-SmAdModule
    $forest = Get-ADForest; $domain = Get-ADDomain
    $current = ConvertTo-SmAdLevelNumber $(if ($Scope -eq 'Forest') { $forest.ForestMode } else { $domain.DomainMode })
    $dcs = @(); $levels = @{}
    foreach ($d in @($forest.Domains)) {
        if ($Scope -eq 'Domain' -and $d -ine [string]$domain.DNSRoot) { continue }
        $levels[[string]$d] = ConvertTo-SmAdLevelNumber (Get-ADDomain -Identity $d).DomainMode
        $dcs += @(Get-ADDomainController -Filter * -Server $d | ForEach-Object { [pscustomobject]@{ HostName = [string]$_.HostName; Domain = [string]$d; OperatingSystem = [string]$_.OperatingSystem } })
    }
    $repl = Test-SmAdReplication
    $res = Test-SmAdLevelRaise -Scope $Scope -Target $Target -Current ([int]$current) -DomainControllers $dcs -DomainName ([string]$domain.DNSRoot) -DomainLevels $levels -ReplicationOk $repl.Ok
    [pscustomobject]@{ Result = $res; Current = $current; ScopeName = $(if ($Scope -eq 'Forest') { [string]$forest.Name } else { [string]$domain.DNSRoot }); Forest = $forest; Domain = $domain }
}

function Invoke-SmAdRaiseLevel {
    <# Hebt die Funktionsebene an (nicht umkehrbar). Verlangt Bestaetigung und das getippte Namen der Domaene bzw. Gesamtstruktur. #>
    param([Parameter(Mandatory)][ValidateSet('Domain', 'Forest')][string]$Scope, [Parameter(Mandatory)][int]$Target, [string]$TypedName, [switch]$Confirmed)
    Invoke-SmAdAudited -What ("Funktionsebene anheben ($Scope)") -Subject ('{0} auf {1}' -f $Scope, (Get-SmAdLevelName $Target)) -Body {
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        if (-not (Test-SmAdIsAdmin)) { throw 'Das Fenster laeuft nicht als Administrator.' }
        $plan = Get-SmAdLevelPlan -Scope $Scope -Target $Target
        if ($TypedName -ine $plan.ScopeName) { throw 'Der getippte Name stimmt nicht, nichts geaendert.' }
        if (-not $plan.Result.Ok) { throw ('Vorpruefung nicht bestanden, nichts geaendert: ' + ((@($plan.Result.Checks | Where-Object { -not $_.Ok } | ForEach-Object { $_.Name })) -join '; ')) }
        $need = if ($Scope -eq 'Forest') { @('EnterpriseAdmins') } else { @('DomainAdmins') }
        $ctx = [pscustomobject]@{ Forest = $plan.Forest; Domain = $plan.Domain }
        $rights = @(Test-SmAdRights -Ctx $ctx -Need $need | Where-Object { -not $_.Ok })
        if ($rights.Count) { throw ('Rechte fehlen: ' + (($rights | ForEach-Object Name) -join '; ')) }
        $mode = Get-SmAdModeParameter -Scope $Scope -Level $Target
        if ($Scope -eq 'Forest') { Set-ADForestMode -Identity $plan.Forest -ForestMode $mode -Server ([string]$plan.Forest.SchemaMaster) -Confirm:$false }
        else { Set-ADDomainMode -Identity $plan.Domain -DomainMode $mode -Server ([string]$plan.Domain.PDCEmulator) -Confirm:$false }
        $now = ConvertTo-SmAdLevelNumber $(if ($Scope -eq 'Forest') { (Get-ADForest).ForestMode } else { (Get-ADDomain).DomainMode })
        if ($now -ne $Target) { throw ('Nachpruefung: die Ebene ist jetzt ' + (Get-SmAdLevelName $now)) }
        [pscustomobject]@{ Detail = ('von {0} auf {1}' -f (Get-SmAdLevelName $plan.Current), (Get-SmAdLevelName $now)); Before = $plan.Current; After = $now }
    }
}

# ---------------------------------------------------------------- Schema (adprep)

function Test-SmAdMicrosoftSigned {
    <# adprep.exe muss eine gueltige Microsoft-Signatur haben. #>
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation'
}

function Get-SmAdAdprepMedia {
    <# Prueft den Medienpfad und liefert adprep.exe, ihre Version und die vermutete Server-Version. #>
    param([Parameter(Mandatory)][string]$MediaPath)
    if ($MediaPath -notmatch '^(?:[A-Za-z]:\\|\\\\)[^"''<>|*?\r\n]*$') { throw 'Der Medienpfad ist nicht erlaubt (Laufwerk oder UNC-Pfad ohne Anfuehrungszeichen).' }
    $full = [IO.Path]::GetFullPath($MediaPath)
    $exe = Join-Path $full 'support\adprep\adprep.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Auf dem Medium fehlt support\adprep\adprep.exe.' }
    $fv = (Get-Item -LiteralPath $exe).VersionInfo
    $ver = [string]$fv.ProductVersion
    if (-not $ver) { $ver = [string]$fv.FileVersion }
    $srv = Get-SmAdAdprepServerName $ver
    [pscustomobject]@{ Path = $exe; Version = $ver; ServerName = $(if ($srv) { $srv.Name } else { $null }); ExpectedSchema = $(if ($srv) { $srv.Schema } else { $null }) }
}

function Test-SmAdAdprepPrecheck {
    param([Parameter(Mandatory)][string]$MediaPath, [Parameter(Mandatory)][ValidateSet('Forest', 'Domain')][string]$Phase)
    $checks = New-Object System.Collections.Generic.List[object]
    $checks.Add((New-SmAdCheck 'Administrator' (Test-SmAdIsAdmin) 'Das Fenster muss als Administrator laufen.'))
    $media = $null
    try { $media = Get-SmAdAdprepMedia -MediaPath $MediaPath; $checks.Add((New-SmAdCheck 'Installationsmedium' $true ('adprep.exe {0}{1}' -f $media.Version, $(if ($media.ServerName) { ' (vermutlich ' + $media.ServerName + ')' } else { '' })))) }
    catch { $checks.Add((New-SmAdCheck 'Installationsmedium' $false $_.Exception.Message)) }
    if ($media) { $signed = Test-SmAdMicrosoftSigned -Path $media.Path; $checks.Add((New-SmAdCheck 'adprep.exe von Microsoft signiert' $signed $(if ($signed) { 'gueltige Signatur' } else { 'Signatur fehlt oder ist ungueltig' }))) }
    Assert-SmAdModule
    $m = Get-SmAdFsmoMap
    if ($Phase -eq 'Forest') {
        $isSm = Test-SmAdIsLocalHost $m.Map.SchemaMaster
        $checks.Add((New-SmAdCheck 'Dieser Server ist der Schemamaster' $isSm $(if ($isSm) { 'ja' } else { 'Schemamaster ist ' + $m.Map.SchemaMaster + '. Rolle erst hierher uebertragen oder dort ausfuehren.' })))
        foreach ($c in (Test-SmAdRights -Ctx $m -Need @('SchemaAdmins', 'EnterpriseAdmins', 'DomainAdmins'))) { $checks.Add($c) }
    }
    else {
        $isIm = Test-SmAdIsLocalHost $m.Map.InfrastructureMaster
        $checks.Add((New-SmAdCheck 'Dieser Server ist der Infrastrukturmaster' $isIm $(if ($isIm) { 'ja' } else { 'Infrastrukturmaster ist ' + $m.Map.InfrastructureMaster })))
        foreach ($c in (Test-SmAdRights -Ctx $m -Need @('DomainAdmins'))) { $checks.Add($c) }
    }
    $repl = Test-SmAdReplication
    $checks.Add((New-SmAdCheck 'Replikation ohne Fehler' $repl.Ok $(if ($repl.Ok) { 'keine Fehler' } else { 'Replikationsfehler oder nicht pruefbar' })))
    $checks.Add((New-SmAdCheck 'Sicherung' $true 'Vor /forestprep eine aktuelle Systemstatus-Sicherung der Schemamasters und eines weiteren DCs je Domaene anlegen. Nach der Schemaerweiterung hilft nur eine Gesamtstruktur-Wiederherstellung.' $false))
    $checks.Add((New-SmAdCheck 'Hinweis' $true 'Ab Windows Server 2012 laufen /forestprep und /domainprep beim Heraufstufen eines DCs automatisch. Dieser Schritt ist nur noetig, wenn das Schema vorab erweitert werden soll.' $false))
    [pscustomobject]@{ Checks = $checks.ToArray(); Ok = (Test-SmAdChecksPassed $checks.ToArray()); Media = $media }
}

function Invoke-SmAdAdprep {
    <# /forestprep oder /domainprep vom Medium. Antwortet auf die Rueckfrage mit C. Ausgabe kommt in eine Datei im gehaerteten AD-Ordner und in die Rueckgabe. #>
    param([Parameter(Mandatory)][string]$MediaPath, [Parameter(Mandatory)][ValidateSet('Forest', 'Domain')][string]$Phase, [switch]$Confirmed)
    Invoke-SmAdAudited -What ("adprep /$($Phase.ToLower())prep") -Subject ($env:COMPUTERNAME + ' ' + $MediaPath) -Body {
        if (-not $Confirmed) { throw 'Nicht bestaetigt, nichts geaendert.' }
        $pre = Test-SmAdAdprepPrecheck -MediaPath $MediaPath -Phase $Phase
        if (-not $pre.Ok) { throw ('Vorpruefung nicht bestanden, nichts geaendert: ' + ((@($pre.Checks | Where-Object { $_.Blocking -and -not $_.Ok } | ForEach-Object { $_.Name })) -join '; ')) }
        $before = Get-SmAdSchemaVersion
        $arg = if ($Phase -eq 'Forest') { '/forestprep' } else { '/domainprep' }
        $r = Invoke-SmAdProcess -FilePath $pre.Media.Path -Arguments $arg -StdIn @('C') -TimeoutSec $script:SmAdAdprepTimeoutSec
        $logFile = Join-Path (Get-SmAdFolder) ('adprep-{0}-{1:yyyyMMdd-HHmmss}.log' -f $Phase.ToLower(), (Get-Date))
        [IO.File]::WriteAllText($logFile, (($r.Lines) -join "`r`n"), (New-Object Text.UTF8Encoding $false))
        if ($r.ExitCode -ne 0) { throw ('adprep meldete einen Fehler (Exitcode {0}); Ausgabe in {1}' -f $r.ExitCode, $logFile) }
        $after = Get-SmAdSchemaVersion
        $note = ''
        if ($Phase -eq 'Forest' -and $pre.Media.ExpectedSchema -and $after -ne $pre.Media.ExpectedSchema) { $note = ' (erwartet laut Medium: ' + $pre.Media.ExpectedSchema + ')' }
        [pscustomobject]@{ Before = $before; After = $after; Lines = $r.Lines; LogFile = $logFile; Detail = ('Schema-Version {0} -> {1}{2}' -f $before, $after, $note) }
    }
}

# ---------------------------------------------------------------- Oberflaeche

function Get-SmAdServerPageXaml {
    param([Parameter(Mandatory)][string]$Root)
    [IO.File]::ReadAllText((Join-Path $Root 'UI\AdServer.xaml'), [Text.Encoding]::UTF8)
}

function Get-SmAdServerUiNames {
    @('BoxAdAdmin', 'BoxAdModule', 'ChkAdDns', 'BtnAdOverview', 'BtnAdUpload', 'TxtAdOverview', 'TxtAdOverviewState',
        'ChkAdPdc', 'ChkAdRid', 'ChkAdInfra', 'ChkAdSchema', 'ChkAdNaming', 'BtnAdFsmoAll', 'BtnAdFsmoCheck', 'BtnAdFsmoMove', 'TxtAdFsmoOut',
        'CmbAdSeizeRole', 'TxtAdSeizeConfirm', 'BtnAdSeizeCheck', 'BtnAdSeize',
        'RbAdDsrmSync', 'RbAdDsrmPwd', 'TxtAdDsrmAccount', 'TxtAdDsrmDc', 'PwdAdDsrm1', 'PwdAdDsrm2', 'BtnAdDsrm', 'TxtAdDsrmOut',
        'CmbAdLevelScope', 'CmbAdLevelTarget', 'BtnAdLevelCheck', 'TxtAdLevelConfirm', 'BtnAdLevelRaise', 'TxtAdLevelOut',
        'TxtAdMedia', 'BtnAdMediaBrowse', 'BtnAdForestCheck', 'BtnAdForestPrep', 'BtnAdDomainCheck', 'BtnAdDomainPrep', 'TxtAdSchemaOut')
}

function Register-SmAdServerPage {
    <# Haengt die Knoepfe des AD-Bereichs ein. Die Logik steckt in den Funktionen oben, hier nur Oberflaeche und Bestaetigungen (mit Servername und Ziel). #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$AddLog, [Parameter(Mandatory)][scriptblock]$GetShare)
    $script:SmAdUi = @{ Ui = $Ui; Modules = $JobModules; Log = $AddLog; GetShare = $GetShare; Report = $null }
    $c = $script:SmAdUi
    foreach ($s in @('Domäne', 'Gesamtstruktur')) { [void]$Ui.CmbAdLevelScope.Items.Add($s) }
    $Ui.CmbAdLevelScope.SelectedIndex = 0
    foreach ($r in $script:SmAdRoles) { [void]$Ui.CmbAdSeizeRole.Items.Add($r) }
    $Ui.CmbAdSeizeRole.SelectedIndex = 0
    $Ui.RbAdDsrmSync.IsChecked = $true

    $isAdmin = Test-SmAdIsAdmin
    $hasModule = [bool](Get-Command Get-ADForest -ErrorAction SilentlyContinue) -or [bool](Get-Module -ListAvailable ActiveDirectory)
    $c.IsAdmin = $isAdmin; $c.HasModule = $hasModule
    if (-not $isAdmin) { $Ui.BoxAdAdmin.Visibility = 'Visible' }
    if (-not $hasModule) { $Ui.BoxAdModule.Visibility = 'Visible' }
    foreach ($b in 'BtnAdFsmoMove', 'BtnAdDsrm', 'BtnAdLevelRaise', 'BtnAdForestPrep', 'BtnAdDomainPrep') { if (-not $isAdmin -or -not $hasModule) { $Ui.$b.IsEnabled = $false } }

    $run = {
        # fuehrt $Script im Hintergrund aus, zeigt Ergebnis in $Out, protokolliert in der Oberflaeche
        param([string]$Title, [scriptblock]$Script, [hashtable]$Params, $Out, [scriptblock]$Done)
        $c = $script:SmAdUi
        $Out.Text = $Title + ' ...'
        $job = @{ Out = $Out; Title = $Title; Done = $Done }
        [void](Start-SmJob -Modules $c.Modules -Params $Params -Script $Script -OnDone {
                param($result, $err)
                if ($err) { $job.Out.Text = $err; & $c.Log ('AD: ' + $job.Title + ' fehlgeschlagen: ' + (($err -replace '[\r\n]+', ' ').Trim())); return }
                if ($job.Done) { & $job.Done $result[-1] }
            }.GetNewClosure())
    }
    $confirm = {
        # Bestaetigungsdialog mit Server und Ziel
        param([string]$Title, [string]$Target, [string]$Text)
        $msg = "Server, auf dem die Aktion läuft: $($env:COMPUTERNAME)`r`nZiel: $Target`r`n`r`n$Text`r`n`r`nJetzt ausführen?"
        [System.Windows.MessageBox]::Show($msg, $Title, 'YesNo', 'Warning') -eq 'Yes'
    }
    $roles = {
        $u = $script:SmAdUi.Ui
        $r = @()
        if ($u.ChkAdPdc.IsChecked) { $r += 'PDCEmulator' }; if ($u.ChkAdRid.IsChecked) { $r += 'RIDMaster' }; if ($u.ChkAdInfra.IsChecked) { $r += 'InfrastructureMaster' }
        if ($u.ChkAdSchema.IsChecked) { $r += 'SchemaMaster' }; if ($u.ChkAdNaming.IsChecked) { $r += 'DomainNamingMaster' }
        , $r
    }
    $c.Run = $run; $c.Confirm = $confirm; $c.Roles = $roles

    $Ui.BtnAdOverview.Add_Click({
            $u = $script:SmAdUi.Ui; $u.BtnAdOverview.IsEnabled = $false
            & $script:SmAdUi.Run 'Uebersicht' { param($State, $P) $o = Get-SmAdOverview -IncludeDns:$P.Dns; $path = New-SmAdReport -Overview $o; [pscustomobject]@{ Path = $path; Report = (Read-SmAdReport -Path $path) } } @{ Dns = [bool]$u.ChkAdDns.IsChecked } $u.TxtAdOverview {
                param($r)
                $cc = $script:SmAdUi; $cc.Ui.BtnAdOverview.IsEnabled = $true
                $cc.Report = $r.Path; $cc.Ui.TxtAdOverview.Text = Format-SmAdReportText -Report $r.Report
                $cc.Ui.TxtAdOverviewState.Text = 'Bericht: ' + (Split-Path -Leaf $r.Path)
                $cc.Ui.BtnAdUpload.IsEnabled = [bool](& $cc.GetShare)
                & $cc.Log ('AD: Übersicht erstellt (' + (Split-Path -Leaf $r.Path) + ')')
            }
            $u.BtnAdOverview.IsEnabled = $true
        })
    $Ui.BtnAdUpload.Add_Click({
            $cc = $script:SmAdUi; $share = & $cc.GetShare
            if (-not $share -or -not $cc.Report) { return }
            $cc.Ui.TxtAdOverviewState.Text = 'Lade hoch ...'
            [void](Start-SmJob -Modules $cc.Modules -Params @{ Share = $share; Path = $cc.Report } -Script { param($State, $P) Send-SmShareFile -Share $P.Share -Path $P.Path } -OnDone {
                    param($result, $err)
                    $cc2 = $script:SmAdUi
                    if ($err) { $cc2.Ui.TxtAdOverviewState.Text = 'Hochladen fehlgeschlagen.'; & $cc2.Log ('AD: Hochladen fehlgeschlagen: ' + $err); return }
                    $cc2.Ui.TxtAdOverviewState.Text = 'Im Tauschordner: ' + $result[-1].Name
                    & $cc2.Log ('AD: Bericht im Tauschordner: ' + $result[-1].Name)
                })
        })

    $Ui.BtnAdFsmoAll.Add_Click({ $u = $script:SmAdUi.Ui; foreach ($n in 'ChkAdPdc', 'ChkAdRid', 'ChkAdInfra', 'ChkAdSchema', 'ChkAdNaming') { $u.$n.IsChecked = $true } })
    $Ui.BtnAdFsmoCheck.Add_Click({
            $r = & $script:SmAdUi.Roles
            if (-not $r.Count) { $script:SmAdUi.Ui.TxtAdFsmoOut.Text = 'Keine Rolle gewählt.'; return }
            & $script:SmAdUi.Run 'FSMO Vorprüfung' { param($State, $P) $x = Test-SmAdFsmoPrecheck -Roles $P.Roles; [pscustomobject]@{ Text = (Format-SmAdChecks $x.Checks); Ok = $x.Ok; Map = $x.Map } } @{ Roles = $r } $script:SmAdUi.Ui.TxtAdFsmoOut {
                param($x) $script:SmAdUi.Ui.TxtAdFsmoOut.Text = ($(if ($x.Ok) { "Vorprüfung bestanden.`r`n`r`n" } else { "Vorprüfung NICHT bestanden. Es wird nichts übertragen.`r`n`r`n" }) + $x.Text + "`r`n`r`nRollen jetzt:`r`n" + ((@($x.Map.GetEnumerator() | ForEach-Object { '  {0}: {1}' -f $_.Key, $_.Value })) -join "`r`n"))
            }
        })
    $Ui.BtnAdFsmoMove.Add_Click({
            $r = & $script:SmAdUi.Roles; $u = $script:SmAdUi.Ui
            if (-not $r.Count) { $u.TxtAdFsmoOut.Text = 'Keine Rolle gewählt.'; return }
            if (-not (& $script:SmAdUi.Confirm 'FSMO-Rollen übertragen' ($r -join ', ') ('Die Rollen werden vom heutigen Inhaber auf diesen Server übertragen (kein Seize). Vorprüfung: Replikation, dcdiag, Erreichbarkeit und Rechte werden vor der Übertragung erneut geprüft.'))) { & $script:SmAdUi.Log 'AD: FSMO übertragen abgebrochen.'; return }
            & $script:SmAdUi.Run 'FSMO übertragen' { param($State, $P) Invoke-SmAdFsmoTransfer -Roles $P.Roles -Confirmed } @{ Roles = $r } $u.TxtAdFsmoOut {
                param($x) $cc = $script:SmAdUi
                $cc.Ui.TxtAdFsmoOut.Text = 'Übertragen: ' + ($x.Moved -join ', ') + "`r`n`r`nVorher:`r`n" + ((@($x.Before.GetEnumerator() | ForEach-Object { '  {0}: {1}' -f $_.Key, $_.Value })) -join "`r`n") + "`r`n`r`nNachher:`r`n" + ((@($x.After.GetEnumerator() | ForEach-Object { '  {0}: {1}' -f $_.Key, $_.Value })) -join "`r`n")
                & $cc.Log ('AD: FSMO übertragen: ' + ($x.Moved -join ', '))
            }
        })
    $Ui.TxtAdSeizeConfirm.Add_TextChanged({ $u = $script:SmAdUi.Ui; $u.BtnAdSeize.IsEnabled = ($script:SmAdUi.IsAdmin -and $script:SmAdUi.HasModule -and $u.TxtAdSeizeConfirm.Text -ceq [string]$u.CmbAdSeizeRole.SelectedItem) })
    $Ui.CmbAdSeizeRole.Add_SelectionChanged({ $u = $script:SmAdUi.Ui; $u.BtnAdSeize.IsEnabled = ($script:SmAdUi.IsAdmin -and $script:SmAdUi.HasModule -and $u.TxtAdSeizeConfirm.Text -ceq [string]$u.CmbAdSeizeRole.SelectedItem) })
    $Ui.BtnAdSeize.IsEnabled = $false
    $Ui.BtnAdSeizeCheck.Add_Click({
            $role = [string]$script:SmAdUi.Ui.CmbAdSeizeRole.SelectedItem
            & $script:SmAdUi.Run 'Seize prüfen' { param($State, $P) $m = Get-SmAdFsmoMap; $h = $m.Map[$P.Role]; [pscustomobject]@{ Holder = $h; Local = (Test-SmAdIsLocalHost $h); Reachable = $(if (Test-SmAdIsLocalHost $h) { $true } else { Test-SmAdHostReachable -HostName $h }) } } @{ Role = $role } $script:SmAdUi.Ui.TxtAdFsmoOut {
                param($x) $script:SmAdUi.Ui.TxtAdFsmoOut.Text = if ($x.Local) { 'Die Rolle liegt schon auf diesem Server.' } elseif ($x.Reachable) { "Der Inhaber $($x.Holder) ist erreichbar. Seize ist nicht erlaubt: bitte die Rolle normal übertragen." } else { "Der Inhaber $($x.Holder) ist nicht erreichbar. Seize ist möglich (nur wenn er dauerhaft ausgefallen ist)." }
            }
        })
    $Ui.BtnAdSeize.Add_Click({
            $u = $script:SmAdUi.Ui; $role = [string]$u.CmbAdSeizeRole.SelectedItem
            if (-not (& $script:SmAdUi.Confirm 'FSMO-Rolle ÜBERNEHMEN (Seize)' $role ("ACHTUNG: Der bisherige Inhaber wird nicht gefragt. Der alte Domänencontroller darf danach NIE wieder ans Netz, sonst entsteht eine zweite Rolle mit Datenverlust und Inkonsistenzen in der Gesamtstruktur. Nur ausführen, wenn der Inhaber nachweislich nicht erreichbar ist und nie wiederkommt."))) { & $script:SmAdUi.Log 'AD: Seize abgebrochen.'; return }
            & $script:SmAdUi.Run 'FSMO Seize' { param($State, $P) Invoke-SmAdFsmoSeize -Role $P.Role -TypedRole $P.Typed -Confirmed } @{ Role = $role; Typed = $u.TxtAdSeizeConfirm.Text } $u.TxtAdFsmoOut {
                param($x) $cc = $script:SmAdUi; $cc.Ui.TxtAdFsmoOut.Text = 'Rolle übernommen: ' + $x.Detail; $cc.Ui.TxtAdSeizeConfirm.Text = ''; & $cc.Log ('AD: Seize: ' + $x.Detail)
            }
        })

    $Ui.BtnAdDsrm.Add_Click({
            $u = $script:SmAdUi.Ui
            if ($u.RbAdDsrmSync.IsChecked) {
                $acct = $u.TxtAdDsrmAccount.Text.Trim()
                if (-not (& $script:SmAdUi.Confirm 'DSRM-Kennwort synchronisieren' ($env:COMPUTERNAME + ' (DSRM-Konto) mit Domänenkonto ' + $acct) 'Das DSRM-Kennwort dieses Servers wird einmalig mit dem aktuellen Kennwort des Domänenkontos gleichgesetzt. Das Tool berührt kein Kennwort.')) { & $script:SmAdUi.Log 'AD: DSRM abgebrochen.'; return }
                & $script:SmAdUi.Run 'DSRM synchronisieren' { param($State, $P) Invoke-SmAdDsrmSync -Account $P.Account -Confirmed } @{ Account = $acct } $u.TxtAdDsrmOut {
                    param($x) $cc = $script:SmAdUi; $cc.Ui.TxtAdDsrmOut.Text = $x.Detail; & $cc.Log 'AD: DSRM-Kennwort mit Domänenkonto synchronisiert.'
                }
                return
            }
            $dc = $u.TxtAdDsrmDc.Text.Trim()
            $target = if ($dc) { $dc } else { $env:COMPUTERNAME + ' (lokal)' }
            $p1 = $u.PwdAdDsrm1.SecurePassword; $p2 = $u.PwdAdDsrm2.SecurePassword
            $cx = Test-SmAdPasswordComplexity $p1
            if (-not $cx.Ok) { $u.TxtAdDsrmOut.Text = 'Das Kennwort ist nicht komplex genug: ' + ($cx.Problems -join '; '); return }
            if (-not (Test-SmAdSecureEqual $p1 $p2)) { $u.TxtAdDsrmOut.Text = 'Die beiden Eingaben stimmen nicht überein.'; return }
            if (-not (& $script:SmAdUi.Confirm 'DSRM-Kennwort setzen' $target 'Das neue DSRM-Kennwort wird nur über die Standardeingabe an ntdsutil gegeben und nirgends gespeichert oder protokolliert. Bitte merken oder im Tresor ablegen.')) { & $script:SmAdUi.Log 'AD: DSRM abgebrochen.'; return }
            & $script:SmAdUi.Run 'DSRM-Kennwort setzen' { param($State, $P) Invoke-SmAdDsrmReset -Password $P.P1 -Confirm $P.P2 -Dc $P.Dc -Confirmed } @{ P1 = $p1; P2 = $p2; Dc = $dc } $u.TxtAdDsrmOut {
                param($x) $cc = $script:SmAdUi; $cc.Ui.TxtAdDsrmOut.Text = $x.Detail; & $cc.Log 'AD: DSRM-Kennwort gesetzt (nicht protokolliert).'
            }
            $u.PwdAdDsrm1.Clear(); $u.PwdAdDsrm2.Clear()
        })

    $levelArgs = {
        $u = $script:SmAdUi.Ui
        @{ Scope = $(if ($u.CmbAdLevelScope.SelectedIndex -eq 1) { 'Forest' } else { 'Domain' }); Target = $(if ($u.CmbAdLevelTarget.SelectedItem) { [int]($u.CmbAdLevelTarget.SelectedItem.Tag) } else { 0 }) }
    }
    $fillTargets = {
        $u = $script:SmAdUi.Ui; $u.CmbAdLevelTarget.Items.Clear()
        $cur = $(if ($u.CmbAdLevelScope.SelectedIndex -eq 1) { $script:SmAdUi.ForestLevel } else { $script:SmAdUi.DomainLevel })
        if ($null -eq $cur) { $cur = 0 }
        foreach ($t in (Get-SmAdLevelTargets -Current ([int]$cur))) { $i = New-Object System.Windows.Controls.ComboBoxItem; $i.Content = Get-SmAdLevelName $t; $i.Tag = $t; [void]$u.CmbAdLevelTarget.Items.Add($i) }
        if ($u.CmbAdLevelTarget.Items.Count) { $u.CmbAdLevelTarget.SelectedIndex = 0 }
    }
    $c.LevelArgs = $levelArgs; $c.Fill = $fillTargets
    $Ui.CmbAdLevelScope.Add_SelectionChanged({ & $script:SmAdUi.Fill })
    $Ui.BtnAdLevelCheck.Add_Click({
            $u = $script:SmAdUi.Ui
            if (-not $script:SmAdUi.ForestLevel -and $null -eq $script:SmAdUi.ForestLevel) {
                # erster Klick: aktuelle Ebenen lesen und die Auswahl fuellen
                & $script:SmAdUi.Run 'Ebenen lesen' { param($State, $P) Assert-SmAdModule; [pscustomobject]@{ F = (ConvertTo-SmAdLevelNumber (Get-ADForest).ForestMode); D = (ConvertTo-SmAdLevelNumber (Get-ADDomain).DomainMode) } } @{} $u.TxtAdLevelOut {
                    param($x) $cc = $script:SmAdUi; $cc.ForestLevel = [int]$x.F; $cc.DomainLevel = [int]$x.D
                    & $script:SmAdUi.Fill
                    $cc.Ui.TxtAdLevelOut.Text = ('Aktuell: Gesamtstruktur {0}, Domäne {1}. Zielebene wählen und erneut prüfen.' -f (Get-SmAdLevelName $x.F), (Get-SmAdLevelName $x.D))
                }
                return
            }
            $a = & $script:SmAdUi.LevelArgs
            if (-not $a.Target) { $u.TxtAdLevelOut.Text = 'Keine höhere Ebene verfügbar oder keine gewählt.'; return }
            & $script:SmAdUi.Run 'Ebenen-Vorprüfung' { param($State, $P) $pl = Get-SmAdLevelPlan -Scope $P.Scope -Target $P.Target; [pscustomobject]@{ Ok = $pl.Result.Ok; Text = (Format-SmAdChecks ($pl.Result.Checks | ForEach-Object { New-SmAdCheck $_.Name $_.Ok $_.Text })); Name = $pl.ScopeName } } $a $u.TxtAdLevelOut {
                param($x) $script:SmAdUi.Ui.TxtAdLevelOut.Text = ($(if ($x.Ok) { "Vorprüfung bestanden für $($x.Name).`r`n`r`n" } else { "Vorprüfung NICHT bestanden. Es wird nichts angehoben.`r`n`r`n" }) + $x.Text + "`r`n`r`nNICHT UMKEHRBAR. Vorher eine aktuelle Systemstatus-Sicherung anlegen.")
            }
        })
    $Ui.TxtAdLevelConfirm.Add_TextChanged({ $script:SmAdUi.Ui.BtnAdLevelRaise.IsEnabled = ($script:SmAdUi.IsAdmin -and $script:SmAdUi.HasModule -and $script:SmAdUi.Ui.TxtAdLevelConfirm.Text.Trim().Length -gt 0) })
    $Ui.BtnAdLevelRaise.IsEnabled = $false
    $Ui.BtnAdLevelRaise.Add_Click({
            $u = $script:SmAdUi.Ui; $a = & $script:SmAdUi.LevelArgs
            if (-not $a.Target) { $u.TxtAdLevelOut.Text = 'Keine Zielebene gewählt.'; return }
            $scopeText = if ($a.Scope -eq 'Forest') { 'Gesamtstruktur' } else { 'Domäne' }
            if (-not (& $script:SmAdUi.Confirm "Funktionsebene anheben" ("$scopeText auf " + (Get-SmAdLevelName $a.Target)) 'Das Anheben ist NICHT UMKEHRBAR (abgesehen von wenigen Ausnahmen in der Doku). Eine aktuelle Systemstatus-Sicherung wird dringend empfohlen. Zusätzlich wurde der Name der Domäne bzw. Gesamtstruktur getippt.')) { & $script:SmAdUi.Log 'AD: Ebene anheben abgebrochen.'; return }
            $a.Typed = $u.TxtAdLevelConfirm.Text.Trim()
            & $script:SmAdUi.Run 'Funktionsebene anheben' { param($State, $P) Invoke-SmAdLevelRaiseWrapper -P $P } $a $u.TxtAdLevelOut {
                param($x) $cc = $script:SmAdUi; $cc.Ui.TxtAdLevelOut.Text = 'Angehoben: ' + $x.Detail; $cc.Ui.TxtAdLevelConfirm.Text = ''; $cc.ForestLevel = $null; $cc.DomainLevel = $null; & $cc.Log ('AD: Funktionsebene: ' + $x.Detail)
            }
        })

    $Ui.BtnAdMediaBrowse.Add_Click({
            Add-Type -AssemblyName System.Windows.Forms
            $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'Installationsmedium (Wurzel mit support\adprep) wählen'
            if ($d.ShowDialog() -eq 'OK') { $script:SmAdUi.Ui.TxtAdMedia.Text = $d.SelectedPath }
        })
    $Ui.BtnAdForestCheck.Tag = 'Forest'; $Ui.BtnAdForestPrep.Tag = 'Forest'; $Ui.BtnAdDomainCheck.Tag = 'Domain'; $Ui.BtnAdDomainPrep.Tag = 'Domain'
    foreach ($b in $Ui.BtnAdForestCheck, $Ui.BtnAdDomainCheck) {
        $b.Add_Click({
                param($sender, $e)
                $u = $script:SmAdUi.Ui; $phase = [string]$sender.Tag; $cmd = if ($phase -eq 'Forest') { '/forestprep' } else { '/domainprep' }
                & $script:SmAdUi.Run "adprep $cmd prüfen" { param($State, $P) $x = Test-SmAdAdprepPrecheck -MediaPath $P.Media -Phase $P.Phase; [pscustomobject]@{ Ok = $x.Ok; Text = (Format-SmAdChecks $x.Checks); Schema = $(try { Get-SmAdSchemaVersion } catch { 0 }) } } @{ Media = $u.TxtAdMedia.Text.Trim(); Phase = $phase } $u.TxtAdSchemaOut {
                    param($x) $script:SmAdUi.Ui.TxtAdSchemaOut.Text = ($(if ($x.Ok) { "Vorprüfung bestanden.`r`n`r`n" } else { "Vorprüfung NICHT bestanden. Es wird nichts ausgeführt.`r`n`r`n" }) + $x.Text + "`r`n`r`nSchema-Version jetzt: $($x.Schema) ($(Get-SmAdSchemaName $x.Schema))")
                }
            })
    }
    foreach ($b in $Ui.BtnAdForestPrep, $Ui.BtnAdDomainPrep) {
        $b.Add_Click({
                param($sender, $e)
                $u = $script:SmAdUi.Ui; $media = $u.TxtAdMedia.Text.Trim(); $phase = [string]$sender.Tag; $cmd = if ($phase -eq 'Forest') { '/forestprep' } else { '/domainprep' }
                if (-not (& $script:SmAdUi.Confirm "adprep $cmd" ("Medium $media, Gesamtstruktur bzw. Domäne dieses Servers") "adprep $cmd erweitert das Schema bzw. die Domäne. Die Änderung wird repliziert und lässt sich nur durch eine Gesamtstruktur-Wiederherstellung zurücknehmen. Eine aktuelle Systemstatus-Sicherung wird dringend empfohlen. Ab Windows Server 2012 macht das Heraufstufen eines DCs das automatisch.")) { & $script:SmAdUi.Log 'AD: adprep abgebrochen.'; return }
                & $script:SmAdUi.Run "adprep $cmd" { param($State, $P) Invoke-SmAdAdprep -MediaPath $P.Media -Phase $P.Phase -Confirmed } @{ Media = $media; Phase = $phase } $u.TxtAdSchemaOut {
                    param($x) $cc = $script:SmAdUi; $cc.Ui.TxtAdSchemaOut.Text = ($x.Detail + "`r`n`r`n" + (($x.Lines | Select-Object -Last 40) -join "`r`n")); & $cc.Log ('AD: adprep ' + $x.Detail)
                }
            })
    }
}

function Invoke-SmAdLevelRaiseWrapper {
    <# Hintergrundauftrag: Parameter aus der Oberflaeche an Invoke-SmAdRaiseLevel geben. #>
    param([Parameter(Mandatory)][hashtable]$P)
    Invoke-SmAdRaiseLevel -Scope $P.Scope -Target $P.Target -TypedName $P.Typed -Confirmed
}
