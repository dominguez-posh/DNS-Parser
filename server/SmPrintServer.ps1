<#
.SYNOPSIS
    Phase 5 (Print), Server-Fenster: Export und Import per PrintBrm, Inventur, Druckprotokoll (Ereignis 307) und Sammeln.
.DESCRIPTION
    Wird per Dot-Source geladen (nach Modules\SmPrint.ps1, Modules\SmTausch.ps1, Modules\SmShell.ps1).
    Jeder aendernde Schritt (Druckprotokoll ein- und ausschalten, Import) hat eine Vorpruefung, verlangt -Confirmed (die
    Oberflaeche holt vorher die Bestaetigung) und schreibt eine Protokollzeile ohne Geheimnisse.
    Alle Dateien liegen im Sicherungsordner unter ProgramData, der von Anfang an gehaertet ist: Besitzer und ACL nur
    Administratoren und SYSTEM, sonst Abbruch (Sicherheits-Checkliste Punkt 13).
    PrintBrm: -B sichert, -R stellt wieder her, -F Datei, -O FORCE ueberschreibt Vorhandenes, -P ORIG veroeffentlicht im AD,
    was urspruenglich veroeffentlicht war. Exitcode 0 = Erfolg, alles andere Fehler (Microsoft nennt keine Einzelwerte;
    Details im Ereignisprotokoll PrintBRM). Windows PowerShell 5.1.
#>

$script:SmPrintDataRoot = $null     # nur fuer Tests: anderer Wurzelordner statt ProgramData
$script:SmPrintBrmPath = $null      # nur fuer Tests: Stub statt PrintBrm.exe
$script:SmWevtutilPath = $null      # nur fuer Tests: Stub statt wevtutil.exe
$script:SmPrintBrmTimeoutSec = 7200
$script:SmPrintMaxExportBytes = 8GB
$script:SmPrintExportPattern = '^[\w.\-]+\.printerExport$'
$script:SmPrintStateFile = 'Druckprotokoll-Zustand.json'
$script:SmPrintAuditFile = 'Protokoll.log'

# ---------------------------------------------------------------- Grundlagen

function Get-SmPrintBrmPath {
    if ($script:SmPrintBrmPath) { return $script:SmPrintBrmPath }
    Join-Path $env:windir 'System32\spool\tools\PrintBrm.exe'
}

function Get-SmWevtutilPath {
    if ($script:SmWevtutilPath) { return $script:SmWevtutilPath }
    Join-Path $env:windir 'System32\wevtutil.exe'
}

function Get-SmPrintFolder {
    $root = if ($script:SmPrintDataRoot) { $script:SmPrintDataRoot } else { Get-SmDnsStateDir }   # C:\ProgramData\ServerMigration
    Join-Path $root 'Print'
}

function Get-SmFreeBytes {
    param([Parameter(Mandatory)][string]$Path)
    (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path)))).AvailableFreeSpace
}

function Get-SmPrintRoleInstalled {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $f = Get-WindowsFeature -Name Print-Server -ErrorAction SilentlyContinue
        return [bool]($f -and $f.Installed)
    }
    [bool](Get-Service -Name Spooler -ErrorAction SilentlyContinue)
}

function Join-SmNativeArgs {
    <# Argumente fuer einen Prozessaufruf; Werte mit Sonderzeichen in Anfuehrungszeichen, innere Anfuehrungszeichen verboten. #>
    param([string[]]$Arguments)
    ($Arguments | ForEach-Object {
            if ($_ -match '"') { throw 'Anfuehrungszeichen in Argumenten sind nicht erlaubt.' }
            if ($_ -match '^[\w:/.\\\-]+$' -and $_ -notmatch '\\$') { $_ } else { '"' + $_ + '"' }
        }) -join ' '
}

function Invoke-SmNative {
    <# Startet eine Datei ohne Shell, wartet (mit Zeitgrenze) und liefert ExitCode, Output und Error. #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$Arguments = @(), [int]$TimeoutSec = 600)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = Join-SmNativeArgs $Arguments
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)    # nur dieser Prozess wird beobachtet und bei Zeitueberschreitung beendet
    try {
        $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; throw ('Zeitueberschreitung nach {0} Sekunden: {1}' -f $TimeoutSec, (Split-Path -Leaf $Path)) }
        $p.WaitForExit()
        $raw = $o.Result; if ($raw.Length -gt 64KB) { $raw = $raw.Substring(0, 64KB) }
        [pscustomobject]@{ ExitCode = $p.ExitCode; Output = (Format-SmPrintText $o.Result 600); Error = (Format-SmPrintText $e.Result 600); Raw = $raw }
    }
    finally { $p.Dispose() }
}

# ---------------------------------------------------------------- Sicherungsordner (gehaertet ueber server\SmDnsServer.ps1)

function Assert-SmSecureFolder {
    <# Pruefung mit Test-SmDnsStateDirAcl (Besitzer und ACL nur Administratoren und SYSTEM, keine Verknuepfung); bei jedem Problem Abbruch. #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Sicherungsordner fehlt: $Path" }
    $bad = @(Test-SmDnsStateDirAcl -Path $Path)
    if ($bad.Count) { throw ('Der Sicherungsordner ist nicht sicher, abgebrochen: ' + ($bad -join ' ')) }
}

function Initialize-SmPrintFolder {
    <# Haertet ProgramData\ServerMigration und den Unterordner Print mit Protect-SmDnsStateDir (bei jeder Nutzung, bricht bei Problemen ab). Liefert den Pfad. #>
    $folder = Get-SmPrintFolder
    foreach ($p in (Split-Path -Parent $folder), $folder) { Protect-SmDnsStateDir -Path $p }
    $folder
}

$script:SmPrintAuditWarning = ''

function Add-SmPrintAudit {
    <# Protokollzeile (ohne Geheimnisse) in die Liste und in die Protokolldatei. Ein Schreibfehler wird nicht verschluckt: Er steht als WARNUNG in der Liste. #>
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Line, [System.Collections.IList]$Log)
    $who = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    if ($null -ne $Log) { [void]$Log.Add($Line) }
    $full = '{0:yyyy-MM-dd HH:mm:ss}  {1}  {2}' -f (Get-Date), $who, $Line
    try { [IO.File]::AppendAllText((Join-Path $Folder $script:SmPrintAuditFile), $full + "`r`n", (New-Object Text.UTF8Encoding $false)) }
    catch {
        $script:SmPrintAuditWarning = 'WARNUNG: Die Protokollzeile konnte nicht geschrieben werden (' + (Format-SmPrintText $_.Exception.Message 200) + ').'
        if ($null -ne $Log) { [void]$Log.Add($script:SmPrintAuditWarning) }
    }
}

function Stop-SmPrintFailure {
    <# Schreibt eine Protokollzeile fuer den Fehler eines aendernden Schritts (soweit der Ordner schon gesichert ist) und wirft den Fehler weiter, mit Hinweis, falls das Protokoll nicht beschreibbar war. #>
    param([Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)]$ErrorRecord)
    $msg = [string]$ErrorRecord.Exception.Message
    $script:SmPrintAuditWarning = ''
    $folder = Get-SmPrintFolder
    if (Test-Path -LiteralPath $folder -PathType Container) {
        try { if (-not @(Test-SmDnsStateDirAcl -Path $folder).Count) { Add-SmPrintAudit -Folder $folder -Line ('{0} fehlgeschlagen: {1}' -f $Action, (Format-SmPrintText $msg 300)) } else { $script:SmPrintAuditWarning = 'WARNUNG: Sicherungsordner nicht gehaertet, Fehler nicht ins Protokoll geschrieben.' } }
        catch { $script:SmPrintAuditWarning = 'WARNUNG: Protokoll nicht beschreibbar (' + (Format-SmPrintText $_.Exception.Message 200) + ').' }
    }
    if ($script:SmPrintAuditWarning) { throw ($msg + ' ' + $script:SmPrintAuditWarning) }
    throw $msg
}

function Resolve-SmPrintFile {
    <# Datei im Sicherungsordner mit erlaubtem Namen; liefert den vollen Pfad oder wirft. #>
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Name, [string]$Pattern = '^[\w.\-]+$')
    $leaf = Split-Path -Leaf $Name
    if ($leaf -ne $Name -or $leaf -notmatch $Pattern) { throw "Ungueltiger Dateiname: $Name" }
    $full = [IO.Path]::GetFullPath((Join-Path $Folder $leaf))
    if (-not $full.StartsWith([IO.Path]::GetFullPath($Folder).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Datei liegt ausserhalb des Sicherungsordners.' }
    $full
}

# ---------------------------------------------------------------- Vorpruefungen

function New-SmCheck([string]$Name, [bool]$Ok, [string]$Text, [bool]$Blocking = $true) {
    [pscustomobject]@{ Name = $Name; Ok = $Ok; Blocking = $Blocking; Text = $Text }
}

function Test-SmPrintPrecheck {
    <#
    .SYNOPSIS
        Vorpruefung fuer Export, Import oder Protokoll. Ok ist falsch, sobald ein blockierender Punkt nicht erfuellt ist.
        Import: Platz (Datei x 2 + 500 MB auf dem Systemlaufwerk), Spooler laeuft, Namenskonflikte gegen die Inventur des alten Servers.
    #>
    param([Parameter(Mandatory)][ValidateSet('Export', 'Import', 'Log')][string]$Mode, [string]$ExportFile, $OldInventory, [switch]$Force)
    $c = New-Object System.Collections.ArrayList
    [void]$c.Add((New-SmCheck 'Administrator' (Test-SmAdmin) 'Das Fenster muss als Administrator laufen.'))
    if ($Mode -ne 'Log') {
        [void]$c.Add((New-SmCheck 'Rolle Druckserver' (Get-SmPrintRoleInstalled) 'Die Rolle Druckserver (Print-Server) ist nicht installiert.'))
        $brm = Get-SmPrintBrmPath
        [void]$c.Add((New-SmCheck 'PrintBrm.exe' (Test-Path -LiteralPath $brm -PathType Leaf) ('PrintBrm.exe fehlt (erwartet: ' + $brm + ').')))
    }
    if ($Mode -eq 'Import') {
        $ok = $ExportFile -and (Test-Path -LiteralPath $ExportFile -PathType Leaf)
        [void]$c.Add((New-SmCheck 'Exportdatei' $ok 'Keine Exportdatei gewaehlt oder heruntergeladen.'))
        if ($ok) {
            $len = (Get-Item -LiteralPath $ExportFile).Length
            $need = 2 * $len + 500MB
            $free = Get-SmFreeBytes -Path $env:windir
            [void]$c.Add((New-SmCheck 'Platz' ($free -ge $need) ('Zu wenig freier Platz auf dem Systemlaufwerk: frei {0}, noetig etwa {1}.' -f (Format-SmSize $free), (Format-SmSize $need))))
        }
        $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        [void]$c.Add((New-SmCheck 'Druckspooler' ([bool]($sp -and $sp.Status -eq 'Running')) 'Der Dienst Druckspooler laeuft nicht.'))
        if ($OldInventory) {
            $have = @{}; foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue)) { $have[([string]$p.Name).ToLowerInvariant()] = $true }
            $conf = @($OldInventory.Printers | Where-Object { $have.ContainsKey($_.Name.ToLowerInvariant()) } | ForEach-Object Name)
            $txt = if (-not $conf.Count) { 'keine' } elseif ($Force) { '{0} werden ueberschrieben ({1})' -f $conf.Count, (($conf | Select-Object -First 5) -join ', ') } else { '{0} schon vorhanden, werden nicht ersetzt ({1})' -f $conf.Count, (($conf | Select-Object -First 5) -join ', ') }
            [void]$c.Add((New-SmCheck 'Namenskonflikte' $true ('Namenskonflikte: ' + $txt) $false))
        }
        else { [void]$c.Add((New-SmCheck 'Namenskonflikte' $true 'Namenskonflikte nicht pruefbar: keine Inventur des alten Servers gewaehlt.' $false)) }
    }
    $ok = -not (@($c | Where-Object { -not $_.Ok -and $_.Blocking }).Count)
    [pscustomobject]@{ Ok = $ok; Checks = @($c) }
}

function Format-SmPrecheck {
    param([Parameter(Mandatory)]$Result)
    (@($Result.Checks | ForEach-Object { '{0}  {1}' -f $(if ($_.Ok) { 'OK    ' } elseif ($_.Blocking) { 'FEHLER' } else { 'HINWEIS' }), $(if ($_.Ok -and $_.Name -ne 'Namenskonflikte') { $_.Name } else { $_.Text }) })) -join "`r`n"
}

# ---------------------------------------------------------------- Inventur

function Get-SmPrintInventoryData {
    <# Rohdaten von Get-Printer, Get-PrinterDriver, Get-PrinterPort zur Inventur (Typ 3/4, x64/x86, AD-Veroeffentlichung). #>
    param([string]$Role = '')
    $printers = @(Get-Printer -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                Name = [string]$_.Name; DriverName = [string]$_.DriverName; PortName = [string]$_.PortName; ShareName = [string]$_.ShareName
                Shared = [bool]$_.Shared; Published = [bool]$_.Published; Location = [string]$_.Location; Comment = [string]$_.Comment; Type = [string]$_.Type
            } })
    $drivers = @(Get-PrinterDriver -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                Name = [string]$_.Name; Version = (ConvertTo-SmDriverVersion $_.DriverVersion); Architecture = (Get-SmDriverArch ([string]$_.PrinterEnvironment))
                DriverType = [int]$_.MajorVersion; Manufacturer = [string]$_.Manufacturer
            } })
    $ports = @(Get-PrinterPort -ErrorAction Stop | ForEach-Object {
            [ordered]@{ Name = [string]$_.Name; Description = [string]$_.Description; Address = [string]$_.PrinterHostAddress; PortNumber = [int]$_.PortNumber }
        })
    New-SmPrintInventory -Computer $env:COMPUTERNAME -Role $Role -Printers $printers -Drivers $drivers -Ports $ports
}

function Write-SmPrintJson {
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$Path)
    $json = ConvertTo-Json -InputObject $Data -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding $false))
}

function Get-SmFileStamp { (Get-Date).ToString('yyyyMMdd-HHmmss') }

function Get-SmSafeComputer { ([string]$env:COMPUTERNAME -replace '[^A-Za-z0-9\-]', '') }

function New-SmPrintInventoryFile {
    <# Erstellt die Inventur als JSON im Sicherungsordner. Liefert Path, Name, Sha256, Length, Log. #>
    param([ValidateSet('alt', 'neu', '')][string]$Role = '', [string]$Stage = '')
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $name = 'Print-Inventur-{0}{1}-{2}.json' -f (Get-SmSafeComputer), $(if ($Stage -match '^[a-z]+$') { '-' + $Stage } else { '' }), (Get-SmFileStamp)
    $path = Resolve-SmPrintFile -Folder $folder -Name $name
    $inv = Get-SmPrintInventoryData -Role $Role
    Write-SmPrintJson -Data $inv -Path $path
    $sha = Get-SmPrintFileHash -Path $path
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Inventur erstellt: {0} ({1} Drucker, {2} Treiber, {3} Ports), SHA256 {4}' -f $name, @($inv.Printers).Count, @($inv.Drivers).Count, @($inv.Ports).Count, $sha)
    [pscustomobject]@{ Path = $path; Name = $name; Sha256 = $sha; Length = (Get-Item -LiteralPath $path).Length; Log = @($log) }
}

# ---------------------------------------------------------------- Export und Import per PrintBrm

function Invoke-SmPrintExportCore {
    <# PrintBrm -B -F <datei>: alle Drucker, Treiber, Ports, Warteschlangen und Freigaben. Danach die Inventur. #>
    param([switch]$Confirmed)
    if (-not $Confirmed) { throw 'Export nicht bestaetigt.' }
    $log = New-Object System.Collections.ArrayList
    $pre = Test-SmPrintPrecheck -Mode Export
    if (-not $pre.Ok) { throw ("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
    $folder = Initialize-SmPrintFolder
    $name = 'Print-Export-{0}-{1}.printerExport' -f (Get-SmSafeComputer), (Get-SmFileStamp)
    $path = Resolve-SmPrintFile -Folder $folder -Name $name -Pattern $script:SmPrintExportPattern
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Export gestartet: PrintBrm -B -F {0}' -f $name)
    $r = Invoke-SmNative -Path (Get-SmPrintBrmPath) -Arguments @('-B', '-F', $path) -TimeoutSec $script:SmPrintBrmTimeoutSec
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0) {
        throw ('PrintBrm meldet Exitcode {0}. Details im Ereignisprotokoll PrintBRM. {1}' -f $r.ExitCode, $r.Error)
    }
    $sha = Get-SmPrintFileHash -Path $path
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Export fertig: {0} ({1}), SHA256 {2}' -f $name, (Format-SmSize (Get-Item -LiteralPath $path).Length), $sha)
    $inv = New-SmPrintInventoryFile -Role 'alt'
    foreach ($l in $inv.Log) { [void]$log.Add($l) }
    [pscustomobject]@{ Export = [pscustomobject]@{ Path = $path; Name = $name; Sha256 = $sha; Length = (Get-Item -LiteralPath $path).Length }; Inventory = $inv; Log = @($log) }
}

function Receive-SmPrintShareFile {
    <# Laedt eine Datei aus dem Tauschordner in den Sicherungsordner. Name per Whitelist, Groesse begrenzt, SHA256 wird geliefert. #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Name, [string]$Pattern = $script:SmPrintExportPattern, [long]$MaxBytes = $script:SmPrintMaxExportBytes)
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $path = Resolve-SmPrintFile -Folder $folder -Name $Name -Pattern $Pattern
    $remote = @(Get-SmShareFiles -Share $Share | Where-Object Name -eq $Name)
    if (-not $remote) { throw "Die Datei $Name ist nicht im Tauschordner." }
    if ($remote[0].Length -gt $MaxBytes) { throw ('Datei zu gross ({0}, erlaubt {1}).' -f (Format-SmSize $remote[0].Length), (Format-SmSize $MaxBytes)) }
    if ((Get-SmFreeBytes -Path $folder) -lt (2 * $remote[0].Length + 100MB)) { throw 'Zu wenig freier Platz fuer den Download.' }
    Receive-SmShareFile -Share $Share -Name $Name -OutFile $path
    if ((Get-Item -LiteralPath $path).Length -ne $remote[0].Length) { throw "Die heruntergeladene Datei $Name ist unvollstaendig." }
    $sha = Get-SmPrintFileHash -Path $path
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Heruntergeladen: {0} ({1}), SHA256 {2}' -f $Name, (Format-SmSize $remote[0].Length), $sha)
    [pscustomobject]@{ Path = $path; Name = $Name; Sha256 = $sha; Length = $remote[0].Length; Log = @($log) }
}

function ConvertTo-SmShaNormal {
    <# Eingegebene SHA256: ohne Leerzeichen, grossgeschrieben, muss genau 64 Hexzeichen haben (sonst Fehler). #>
    param([AllowEmptyString()][string]$Value)
    $s = ([regex]::Replace($Value, '\s', '')).ToUpperInvariant()
    if ($s -notmatch '^[0-9A-F]{64}$') { throw 'Die Pruefsumme muss aus 64 Hexzeichen bestehen (die vollstaendige SHA256 vom alten Server).' }
    $s
}

function Test-SmShaMatch {
    <# Vergleicht die eingegebene mit der berechneten SHA256 vollstaendig (ohne Gross-/Kleinschreibung und Leerzeichen). Ungueltige Eingabe: $false. #>
    param([AllowEmptyString()][string]$Entered, [AllowEmptyString()][string]$Actual)
    try { (ConvertTo-SmShaNormal $Entered) -eq (ConvertTo-SmShaNormal $Actual) } catch { $false }
}

function Copy-SmPrintHashed {
    <# Kopiert eine Datei und berechnet dabei die SHA256 genau der geschriebenen Bytes. Liefert die SHA256 (gross). #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Dest)
    $sha = [Security.Cryptography.SHA256]::Create()
    $in = [IO.File]::Open($Source, 'Open', 'Read', 'Read')
    try {
        $out = [IO.File]::Open($Dest, 'CreateNew', 'Write', 'None')
        try {
            $buf = New-Object byte[] (4MB)
            while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0); $out.Write($buf, 0, $n) }
            [void]$sha.TransformFinalBlock($buf, 0, 0)
        }
        finally { $out.Dispose() }
    }
    finally { $in.Dispose() }
    $h = -join ($sha.Hash | ForEach-Object { $_.ToString('X2') })
    $sha.Dispose()
    $h
}

function Remove-SmPrintTemp {
    <# Loescht das Arbeitsverzeichnis %TEMP%\ServerMigration-print-<GUID>, aber nur, wenn der Pfad genau diese Form hat (GetFullPath-Pruefung). #>
    param([string]$Path)
    if (-not $Path) { return }
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if ($full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase) -and ([IO.Path]::GetFileName($full) -match '^ServerMigration-print-[0-9a-f]{32}$') -and (Test-Path -LiteralPath $full -PathType Container)) {
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Read-SmPrintExportContent {
    <# Inhalt der Exportdatei, soweit lesbar: PrintBrm -Q -F <datei> (Abfrage der Sicherungsdatei). Liefert Ok, ExitCode und Lines (gekuerzt, nur Text). #>
    param([Parameter(Mandatory)][string]$File)
    $r = Invoke-SmNative -Path (Get-SmPrintBrmPath) -Arguments @('-Q', '-F', $File) -TimeoutSec 900
    $lines = @(([string]$r.Raw -split "`r?`n") | ForEach-Object { Format-SmPrintText $_ 200 } | Where-Object { $_ } | Select-Object -First 300)
    [pscustomobject]@{ Ok = ($r.ExitCode -eq 0 -and $lines.Count -gt 0); ExitCode = $r.ExitCode; Lines = $lines }
}

function Compare-SmPrintExportContent {
    <# Vergleicht die Inventur mit dem lesbaren Inhalt des Exports: Jeder Drucker der Inventur muss im Export vorkommen. Liefert Missing (Namen). #>
    param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)][string[]]$Lines)
    $text = ($Lines -join "`n").ToLowerInvariant()
    @($Inventory.Printers | Where-Object { -not $text.Contains($_.Name.ToLowerInvariant()) } | ForEach-Object Name)
}

function Initialize-SmPrintImportCore {
    <#
    .SYNOPSIS
        Bereitet den Import vor (aendert nichts am System): Die eingegebene SHA256 wird beim Kopieren der Exportdatei in ein neues
        %TEMP%\ServerMigration-print-<GUID> gegen genau die kopierten Bytes geprueft, von dort wird auch importiert. Danach Vorpruefung
        und Inhalt aus der Exportdatei (PrintBrm -Q), abgeglichen mit der Inventur des alten Servers.
        Liefert einen Plan (Ok, Problems, Lines, Missing, TempRoot, TempFile, Sha256, Log).
    #>
    param([Parameter(Mandatory)][string]$FileName, [Parameter(Mandatory)][string]$ExpectedSha, $OldInventory, [switch]$Force)
    $log = New-Object System.Collections.ArrayList
    $expected = ConvertTo-SmShaNormal $ExpectedSha
    $folder = Initialize-SmPrintFolder
    $src = Resolve-SmPrintFile -Folder $folder -Name $FileName -Pattern $script:SmPrintExportPattern
    $tmp = Join-Path $env:TEMP ('ServerMigration-print-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tmp)
    try {
        $dest = Join-Path $tmp $FileName
        $actual = Copy-SmPrintHashed -Source $src -Dest $dest
        if ($actual -ne $expected) { throw 'Die SHA256 stimmt nicht mit der Datei im Sicherungsordner ueberein. Nichts importiert.' }
        Add-SmPrintAudit -Folder $folder -Log $log -Line ('Pruefsumme bestaetigt, Arbeitskopie erstellt: {0}, SHA256 {1}' -f $FileName, $actual)
        $pre = Test-SmPrintPrecheck -Mode Import -ExportFile $dest -OldInventory $OldInventory -Force:$Force
        $problems = New-Object System.Collections.ArrayList
        if (-not $pre.Ok) { [void]$problems.Add("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
        $content = Read-SmPrintExportContent -File $dest
        $missing = @()
        if (-not $content.Ok) { [void]$problems.Add('Der Inhalt der Exportdatei ist nicht lesbar (PrintBrm -Q, Exitcode ' + $content.ExitCode + '). Ohne gepruefte Inhalte wird nicht importiert.') }
        elseif ($OldInventory) {
            $missing = @(Compare-SmPrintExportContent -Inventory $OldInventory -Lines $content.Lines)
            if ($missing.Count) { [void]$problems.Add('Inventur und Export weichen ab. In der Exportdatei nicht gefunden: ' + (($missing | Select-Object -First 10) -join ', ')) }
        }
        [pscustomobject]@{
            Ok = ($problems.Count -eq 0); Problems = @($problems); Lines = $content.Lines; Missing = $missing; Precheck = (Format-SmPrecheck $pre)
            FileName = $FileName; TempRoot = $tmp; TempFile = $dest; Sha256 = $actual; HasInventory = [bool]$OldInventory; Log = @($log)
        }
    }
    catch { Remove-SmPrintTemp $tmp; throw }
}

function Initialize-SmPrintImport {
    param([Parameter(Mandatory)][string]$FileName, [Parameter(Mandatory)][string]$ExpectedSha, $OldInventory, [switch]$Force)
    try { Initialize-SmPrintImportCore -FileName $FileName -ExpectedSha $ExpectedSha -OldInventory $OldInventory -Force:$Force }
    catch { Stop-SmPrintFailure -Action 'Import (Vorbereitung)' -ErrorRecord $_ }
}

function Format-SmPrintImportConfirm {
    <# Text der Bestaetigung: Was wirklich importiert wird (aus der Exportdatei selbst), dazu die Optionen. #>
    param([Parameter(Mandatory)]$Plan, [bool]$Shares, [bool]$Publish, [bool]$Force)
    $head = @($Plan.Lines | Select-Object -First 25)
    $t = "Import mit PrintBrm starten?`r`n`r`nDatei: {0}`r`nSHA256 stimmt: {1}`r`n`r`nInhalt der Exportdatei (PrintBrm -Q, {2} Zeilen, erste {3}):`r`n{4}" -f $Plan.FileName, ($Plan.Sha256.Substring(0, 12) + '...'), @($Plan.Lines).Count, $head.Count, ($head -join "`r`n")
    $t += "`r`n`r`nFreigaben übernehmen: {0}`r`nIm Active Directory veröffentlichen: {1}`r`nVorhandene Drucker überschreiben: {2}`r`n" -f $(if ($Shares) { 'ja' } else { 'nein' }), $(if ($Publish) { 'ja' } else { 'nein' }), $(if ($Force) { 'JA (Namensgleiche werden ersetzt)' } else { 'nein' })
    $t += "`r`n" + $(if ($Plan.HasInventory) { 'Inventur und Export stimmen überein.' } else { 'Keine Inventur zum Abgleich gewählt.' }) + "`r`nDer Import ändert Drucker, Treiber und Ports dieses Servers."
    $t
}

function Invoke-SmPrintImportCore {
    <#
    .SYNOPSIS
        PrintBrm -R -F <Arbeitskopie> [-O FORCE] [-P ORIG]. Pflicht: Plan aus Initialize-SmPrintImport (Ok), -Confirmed.
        Vor dem Start wird die Arbeitskopie erneut gehasht (dieselben Bytes wie bestaetigt). Danach wird das Arbeitsverzeichnis geloescht.
        -KeepShares:$false: Danach werden die neu angelegten Drucker (und die der alten Inventur) nicht mehr freigegeben.
    #>
    param([Parameter(Mandatory)]$Plan, [switch]$Confirmed, [switch]$Force, [switch]$Publish, [bool]$KeepShares = $true, $OldInventory)
    try {
        if (-not $Confirmed) { throw 'Import nicht bestaetigt.' }
        if (-not $Plan -or -not $Plan.Ok) { throw 'Der Import ist nicht vorbereitet oder die Pruefung des Exports ist fehlgeschlagen.' }
        $log = New-Object System.Collections.ArrayList
        $folder = Initialize-SmPrintFolder
        if ((Get-SmPrintFileHash -Path $Plan.TempFile) -ne $Plan.Sha256) { throw 'Die Arbeitskopie hat sich seit der Pruefung veraendert. Nichts importiert.' }
        $pre = Test-SmPrintPrecheck -Mode Import -ExportFile $Plan.TempFile -OldInventory $OldInventory -Force:$Force
        if (-not $pre.Ok) { throw ("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
        $before = @{}; foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue)) { $before[([string]$p.Name).ToLowerInvariant()] = $true }
        $brmArgs = @('-R', '-F', $Plan.TempFile)
        if ($Force) { $brmArgs += @('-O', 'FORCE') }
        if ($Publish) { $brmArgs += @('-P', 'ORIG') }
        Add-SmPrintAudit -Folder $folder -Log $log -Line ('Import gestartet: PrintBrm -R -F {0} (SHA256 {1}; Freigaben {2}, Veroeffentlichung {3}, Ueberschreiben {4})' -f $Plan.FileName, $Plan.Sha256, $(if ($KeepShares) { 'uebernehmen' } else { 'nicht uebernehmen' }), $(if ($Publish) { 'ja' } else { 'nein' }), $(if ($Force) { 'ja' } else { 'nein' }))
        $r = Invoke-SmNative -Path (Get-SmPrintBrmPath) -Arguments $brmArgs -TimeoutSec $script:SmPrintBrmTimeoutSec
        if ($r.ExitCode -ne 0) { throw ('PrintBrm meldet Exitcode {0}. Details im Ereignisprotokoll PrintBRM. {1}' -f $r.ExitCode, $r.Error) }
        Add-SmPrintAudit -Folder $folder -Log $log -Line 'Import fertig: Exitcode 0'
        if (-not $KeepShares) {
            $names = @{}
            foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue)) { if (-not $before.ContainsKey(([string]$p.Name).ToLowerInvariant())) { $names[[string]$p.Name] = $true } }
            if ($OldInventory) { foreach ($p in $OldInventory.Printers) { $names[$p.Name] = $true } }
            $n = 0
            foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared -and $names.ContainsKey([string]$_.Name) })) { Set-Printer -Name $p.Name -Shared $false -ErrorAction Stop; $n++ }
            Add-SmPrintAudit -Folder $folder -Log $log -Line ('Freigaben entfernt (nicht uebernommen): {0} Drucker' -f $n)
        }
        [pscustomobject]@{ ExitCode = $r.ExitCode; Log = @($log) }
    }
    finally { if ($Plan) { Remove-SmPrintTemp $Plan.TempRoot } }
}

function Invoke-SmPrintImport {
    param([Parameter(Mandatory)]$Plan, [switch]$Confirmed, [switch]$Force, [switch]$Publish, [bool]$KeepShares = $true, $OldInventory)
    try { Invoke-SmPrintImportCore -Plan $Plan -Confirmed:$Confirmed -Force:$Force -Publish:$Publish -KeepShares $KeepShares -OldInventory $OldInventory }
    catch { Stop-SmPrintFailure -Action 'Import' -ErrorRecord $_ }
}

# ---------------------------------------------------------------- Druckprotokoll (wevtutil)

function Get-SmPrintLogStatus {
    <# Liest den Zustand des Protokolls mit wevtutil gl: Enabled und MaxSize (Bytes). #>
    $r = Invoke-SmNative -Path (Get-SmWevtutilPath) -Arguments @('gl', $script:SmPrintLog) -TimeoutSec 60
    if ($r.ExitCode -ne 0) { throw ('wevtutil meldet Exitcode {0}: {1}' -f $r.ExitCode, $r.Error) }
    $full = $r.Raw
    $en = [regex]::Match($full, '(?im)^\s*enabled:\s*(true|false)\s*$')
    $ms = [regex]::Match($full, '(?im)^\s*maxSize:\s*(\d+)\s*$')
    if (-not $en.Success -or -not $ms.Success) { throw 'Die Ausgabe von wevtutil ist nicht lesbar.' }
    [pscustomobject]@{ Enabled = ($en.Groups[1].Value -eq 'true'); MaxSize = [long]$ms.Groups[1].Value }
}

function ConvertTo-SmLogBytes {
    <# Groesse in MB (1 bis 4096) in Bytes, auf Vielfache von 64 KB gerundet (Vorgabe von wevtutil). #>
    param($Megabytes)
    $n = 0
    if (-not [int]::TryParse([string]$Megabytes, [ref]$n) -or $n -lt 1 -or $n -gt 4096) { throw 'Die Groesse muss eine ganze Zahl von 1 bis 4096 (MB) sein.' }
    [long]([math]::Ceiling(($n * 1MB) / 64KB) * 64KB)
}

function Enable-SmPrintLogCore {
    <# Schaltet das Druckprotokoll ein: sichert zuerst den alten Zustand, dann wevtutil sl <Protokoll> /e:true /ms:<Bytes>. #>
    param([Parameter(Mandatory)]$Megabytes, [switch]$Confirmed)
    if (-not $Confirmed) { throw 'Einschalten nicht bestaetigt.' }
    $bytes = ConvertTo-SmLogBytes $Megabytes
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { throw ("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $stateFile = Join-Path $folder $script:SmPrintStateFile
    $old = Get-SmPrintLogStatus
    $newState = $false
    if (-not (Test-Path -LiteralPath $stateFile)) {
        Write-SmPrintJson -Data ([ordered]@{ Schema = 1; Saved = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); Enabled = $old.Enabled; MaxSize = $old.MaxSize }) -Path $stateFile
        $newState = $true
        Add-SmPrintAudit -Folder $folder -Log $log -Line ('Alter Zustand des Druckprotokolls gesichert: aktiv={0}, Groesse {1}' -f $old.Enabled, (Format-SmSize $old.MaxSize))
    }
    $r = Invoke-SmNative -Path (Get-SmWevtutilPath) -Arguments @('sl', $script:SmPrintLog, '/e:true', ('/ms:' + $bytes)) -TimeoutSec 60
    if ($r.ExitCode -ne 0) {
        if ($newState) { Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue }
        throw ('wevtutil meldet Exitcode {0}: {1}' -f $r.ExitCode, $r.Error)
    }
    $now = Get-SmPrintLogStatus
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Druckprotokoll eingeschaltet: aktiv={0}, Groesse {1}' -f $now.Enabled, (Format-SmSize $now.MaxSize))
    [pscustomobject]@{ Status = $now; Log = @($log) }
}

function Read-SmPrintLogState {
    <# Gesicherter Zustand (aus dem gehaerteten Ordner, trotzdem geprueft). #>
    param([Parameter(Mandatory)][string]$Path)
    $d = Read-SmPrintJson -Path $Path -MaxBytes 64KB
    $en = Get-SmPrintVal $d 'Enabled'; $ms = Get-SmPrintLong (Get-SmPrintVal $d 'MaxSize')
    if ($en -isnot [bool] -or $ms -lt 64KB -or $ms -gt 8GB) { throw 'Die gesicherte Zustandsdatei ist ungueltig.' }
    [pscustomobject]@{ Enabled = $en; MaxSize = $ms }
}

function Disable-SmPrintLogCore {
    <# Stellt den gesicherten alten Zustand wieder her (wevtutil sl /e:<alt> /ms:<alt>). Ohne gesicherten Zustand Abbruch. #>
    param([switch]$Confirmed)
    if (-not $Confirmed) { throw 'Ausschalten nicht bestaetigt.' }
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { throw ("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $stateFile = Join-Path $folder $script:SmPrintStateFile
    if (-not (Test-Path -LiteralPath $stateFile)) { throw 'Es gibt keinen gesicherten alten Zustand. Das Druckprotokoll wurde von diesem Fenster nicht eingeschaltet.' }
    $old = Read-SmPrintLogState -Path $stateFile
    $r = Invoke-SmNative -Path (Get-SmWevtutilPath) -Arguments @('sl', $script:SmPrintLog, ('/e:' + $old.Enabled.ToString().ToLowerInvariant()), ('/ms:' + $old.MaxSize)) -TimeoutSec 60
    if ($r.ExitCode -ne 0) {
        throw ('wevtutil meldet Exitcode {0}: {1}' -f $r.ExitCode, $r.Error)
    }
    Remove-Item -LiteralPath $stateFile -Force
    $now = Get-SmPrintLogStatus
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Druckprotokoll auf den alten Zustand gesetzt: aktiv={0}, Groesse {1}' -f $now.Enabled, (Format-SmSize $now.MaxSize))
    [pscustomobject]@{ Status = $now; Log = @($log) }
}

function Enable-SmPrintLog {
    param([Parameter(Mandatory)]$Megabytes, [switch]$Confirmed)
    try { Enable-SmPrintLogCore -Megabytes $Megabytes -Confirmed:$Confirmed } catch { Stop-SmPrintFailure -Action 'Druckprotokoll einschalten' -ErrorRecord $_ }
}

function Disable-SmPrintLog {
    param([switch]$Confirmed)
    try { Disable-SmPrintLogCore -Confirmed:$Confirmed } catch { Stop-SmPrintFailure -Action 'Druckprotokoll ausschalten' -ErrorRecord $_ }
}

function Invoke-SmPrintExport {
    param([switch]$Confirmed)
    try { Invoke-SmPrintExportCore -Confirmed:$Confirmed } catch { Stop-SmPrintFailure -Action 'Export' -ErrorRecord $_ }
}

# ---------------------------------------------------------------- Zugriffe sammeln

function Get-SmPrintEvents {
    <# Ereignis 307 seit $Since. Liefert Events (geparst) und Truncated. Ereignistexte werden nur als Daten gelesen (XML ohne DTD). #>
    param([Parameter(Mandatory)][datetime]$Since, [int]$Max = $script:SmPrintMaxEvents)
    $raw = @()
    try { $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $script:SmPrintLog; Id = 307; StartTime = $Since } -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $_.Exception.Message -notmatch 'No events') { throw } }
    $events = @($raw | ForEach-Object { ConvertFrom-SmPrintEventXml -Xml ([string]$_.ToXml()) } | Where-Object { $_ })
    [pscustomobject]@{ Events = $events; Truncated = ($raw.Count -ge $Max) }
}

function Get-SmPrintSnapshot {
    <# Sofortbild: SMB-Sitzungen, offene Dateien (nur Druckfreigaben bzw. Spooler) und, falls ermittelbar, Verbindungen des Spoolers. #>
    $notes = New-Object System.Collections.ArrayList
    $printPath = $null
    try { $s = Get-SmbShare -Name 'print$' -ErrorAction Stop; $printPath = [string]$s.Path } catch { [void]$notes.Add('Freigabe print$ nicht ermittelbar') }
    $files = @()
    try {
        $files = @(Get-SmbOpenFile -ErrorAction Stop | Where-Object {
                $p = [string]$_.Path
                ($p -match '(?i)spoolss|\\spool\\|print\$') -or ($printPath -and $p.StartsWith($printPath, [StringComparison]::OrdinalIgnoreCase))
            } | Select-Object -First 5000 | ForEach-Object { [ordered]@{ Client = (Format-SmPrintText $_.ClientComputerName); User = (Format-SmPrintText $_.ClientUserName); Path = (Format-SmPrintText $_.Path 260) } })
    }
    catch { [void]$notes.Add('Offene Dateien nicht ermittelbar') }
    $printUsers = @{}; foreach ($f in $files) { $printUsers[($f.Client + '|' + $f.User).ToLowerInvariant()] = $true }
    $sessions = @()
    try {
        $sessions = @(Get-SmbSession -ErrorAction Stop | Select-Object -First 5000 | ForEach-Object {
                $c = Format-SmPrintText $_.ClientComputerName; $u = Format-SmPrintText $_.ClientUserName
                [ordered]@{ Client = $c; User = $u; Opens = [int]$_.NumOpens; PrintOpen = [bool]$printUsers.ContainsKey(($c + '|' + $u).ToLowerInvariant()) }
            })
    }
    catch { [void]$notes.Add('SMB-Sitzungen nicht ermittelbar') }
    $conns = $null
    try {
        $sp = Get-Process -Name spoolsv -ErrorAction Stop | Select-Object -First 1
        $conns = @(Get-NetTCPConnection -OwningProcess $sp.Id -State Established -ErrorAction Stop | Select-Object -First 2000 | ForEach-Object { [ordered]@{ Remote = [string]$_.RemoteAddress; RemotePort = [int]$_.RemotePort; LocalPort = [int]$_.LocalPort } })
    }
    catch { [void]$notes.Add('Verbindungen des Spoolers nicht ermittelbar') }
    [ordered]@{ Taken = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); SmbSessions = $sessions; OpenFiles = $files; SpoolerConnections = $conns; Notes = @($notes) }
}

function Invoke-SmPrintCollect {
    <# Sammelt Ereignis 307 der letzten $Days Tage plus Sofortbild und schreibt eine JSON-Datei in den Sicherungsordner. #>
    param([int]$Days = 90, [switch]$Pseudonymize, [string]$Salt = '')
    if ($Days -lt 1 -or $Days -gt 3650) { throw 'Tage: 1 bis 3650.' }
    if ($Pseudonymize -and $Salt.Trim().Length -lt 8) { throw 'Pseudonyme brauchen einen Projekt-Salt mit mindestens 8 Zeichen.' }
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { throw ("Vorpruefung nicht bestanden:`r`n" + (Format-SmPrecheck $pre)) }
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $since = (Get-Date).AddDays(-$Days)
    $got = Get-SmPrintEvents -Since $since
    $snap = Get-SmPrintSnapshot
    $events = $got.Events
    if ($Pseudonymize) {   # Benutzernamen sind personenbezogene Daten: Hash mit Projekt-Salt, der Salt kommt nicht in die Datei
        $events = @($events | ForEach-Object { $e = $_.PSObject.Copy(); $e.User = Get-SmPseudonym -Value $e.User -Salt $Salt -HexLength 8; $e })
        foreach ($x in @($snap.SmbSessions) + @($snap.OpenFiles)) { $x['User'] = Get-SmPseudonym -Value ([string]$x['User']) -Salt $Salt -HexLength 8 }
    }
    $data = New-SmPrintAccessFile -Computer $env:COMPUTERNAME -Events $events -Snapshot $snap -RequestedFrom $since -Truncated $got.Truncated -Pseudonymized:$Pseudonymize
    $name = 'Print-Zugriffe-{0}-{1}.json' -f (Get-SmSafeComputer), (Get-SmFileStamp)
    $path = Resolve-SmPrintFile -Folder $folder -Name $name
    Write-SmPrintJson -Data $data -Path $path
    $sha = Get-SmPrintFileHash -Path $path
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Zugriffe gesammelt: {0} Ereignisse 307{1}, {2} SMB-Sitzungen, {3} offene Druckdateien, Benutzernamen {5}, SHA256 {4}' -f $data.Count, $(if ($got.Truncated) { ' (gekuerzt auf die neuesten)' } else { '' }), @($snap.SmbSessions).Count, @($snap.OpenFiles).Count, $sha, $(if ($Pseudonymize) { 'pseudonymisiert' } else { 'im Klartext' }))
    [pscustomobject]@{ Path = $path; Name = $name; Sha256 = $sha; Length = (Get-Item -LiteralPath $path).Length; Count = $data.Count; Log = @($log) }
}

function Send-SmPrintFile {
    <# Laedt eine Datei aus dem Sicherungsordner in den Tauschordner (in Teilen) und liefert die SHA256 der lokalen Datei. #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Name, [scriptblock]$Progress)
    $log = New-Object System.Collections.ArrayList
    $folder = Initialize-SmPrintFolder
    $path = Resolve-SmPrintFile -Folder $folder -Name $Name
    $sha = Get-SmPrintFileHash -Path $path
    $remote = Send-SmShareFile -Share $Share -Path $path -Progress $Progress
    Add-SmPrintAudit -Folder $folder -Log $log -Line ('Hochgeladen: {0} ({1}), SHA256 {2}' -f $Name, (Format-SmSize $remote.Length), $sha)
    [pscustomobject]@{ Name = $Name; Sha256 = $sha; Length = $remote.Length; Log = @($log) }
}

# ---------------------------------------------------------------- Seite im Server-Fenster

function Get-SmPrintServerPageXaml {
    param([Parameter(Mandatory)][string]$Root)
    [IO.File]::ReadAllText((Join-Path $Root 'UI\PrintServer.xaml'))
}

function Get-SmPrintServerUiNames {
    @('RbPrOld', 'RbPrNew', 'TxtPrFolder', 'BoxPrOld', 'BoxPrNew', 'TxtPrCheck', 'BtnPrCheckExp', 'BtnPrExport', 'TxtPrExpSha', 'BtnPrShaCopy',
        'CmbPrExportFile', 'CmbPrInvFile', 'BtnPrListShare', 'BtnPrDownload', 'TxtPrSha', 'TxtPrShaIn', 'ChkPrShares', 'ChkPrPublish', 'ChkPrForce', 'BtnPrCheckImp', 'BtnPrImport', 'BtnPrInventory',
        'LstPrLocal', 'BtnPrLocalRefresh', 'BtnPrUpload', 'TxtPrUploadState',
        'TxtPrLogStatus', 'TxtPrLogSize', 'BtnPrLogRefresh', 'BtnPrLogOn', 'BtnPrLogOff', 'TxtPrDays', 'ChkPrPseudo', 'TxtPrSalt', 'BtnPrCollect')
}

function Initialize-SmPrintServerPage {
    <#
    .SYNOPSIS
        Verdrahtet die Seite Print des Server-Fensters (UI\PrintServer.xaml). GetShare liefert den verbundenen Tauschordner oder $null.
        Lange Arbeiten laufen in einem eigenen Runspace (Start-SmJob); jede aendernde Aktion fragt vorher im Fenster nach.
    #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$AddLog, [Parameter(Mandatory)][scriptblock]$GetShare)
    $script:SmPS = @{ Ui = $Ui; Modules = $JobModules; Log = $AddLog; GetShare = $GetShare; Busy = $false; OldInv = $null; DlSha = $null; DlName = $null; OnResult = $null; What = '' }
    $Ui.RbPrOld.IsChecked = $true
    $Ui.TxtPrFolder.Text = 'Sicherungsordner: ' + (Get-SmPrintFolder)
    $Ui.TxtPrDays.Text = '90'
    $Ui.TxtPrLogSize.Text = '100'
    $Ui.BtnPrImport.IsEnabled = $false
    Update-SmPrintRole
    $Ui.RbPrOld.Add_Checked({ Update-SmPrintRole }); $Ui.RbPrNew.Add_Checked({ Update-SmPrintRole })
    $Ui.BtnPrCheckExp.Add_Click({ Show-SmPrintPrecheck -Mode Export })
    $Ui.BtnPrExport.Add_Click({ Start-SmPrintExportUi })
    $Ui.BtnPrShaCopy.Add_Click({ $t = $script:SmPS.Ui.TxtPrExpSha.Text; if ($t) { [System.Windows.Clipboard]::SetText($t); Show-SmToast 'SHA256 kopiert.' } })
    $Ui.BtnPrListShare.Add_Click({ Update-SmPrintShareLists })
    $Ui.BtnPrDownload.Add_Click({ Start-SmPrintDownloadUi })
    $Ui.TxtPrShaIn.Add_TextChanged({ Update-SmPrintImportState })
    $Ui.BtnPrCheckImp.Add_Click({ Show-SmPrintPrecheck -Mode Import })
    $Ui.BtnPrImport.Add_Click({ Start-SmPrintImportUi })
    $Ui.BtnPrInventory.Add_Click({ Start-SmPrintInventoryUi })
    $Ui.BtnPrLocalRefresh.Add_Click({ Update-SmPrintLocalList })
    $Ui.BtnPrUpload.Add_Click({ Start-SmPrintUploadUi })
    $Ui.BtnPrLogRefresh.Add_Click({ Update-SmPrintLogUi })
    $Ui.BtnPrLogOn.Add_Click({ Start-SmPrintLogSwitchUi -On })
    $Ui.BtnPrLogOff.Add_Click({ Start-SmPrintLogSwitchUi })
    $Ui.BtnPrCollect.Add_Click({ Start-SmPrintCollectUi })
    Update-SmPrintLocalList
    Update-SmPrintLogUi
}

function Update-SmPrintRole {
    $u = $script:SmPS.Ui
    $old = [bool]$u.RbPrOld.IsChecked
    $u.BoxPrOld.Visibility = if ($old) { 'Visible' } else { 'Collapsed' }
    $u.BoxPrNew.Visibility = if ($old) { 'Collapsed' } else { 'Visible' }
}

function Update-SmPrintImportState {
    <# Der Import-Knopf ist nur an, wenn eine Datei heruntergeladen ist und die eingegebene SHA256 vollstaendig passt. #>
    $st = $script:SmPS; $u = $st.Ui
    $match = [bool]($st.DlSha -and (Test-SmShaMatch -Entered $u.TxtPrShaIn.Text -Actual $st.DlSha))
    $u.BtnPrImport.IsEnabled = ($match -and -not $st.Busy)
    $u.TxtPrSha.Text = if (-not $st.DlSha) { 'Noch nichts heruntergeladen.' } elseif (-not $u.TxtPrShaIn.Text.Trim()) { 'Bitte die vollständige SHA256 vom alten Server einfügen.' } elseif ($match) { 'SHA256 stimmt.' } else { 'SHA256 stimmt nicht (oder ist unvollständig).' }
}

function Set-SmPrintBusy([bool]$Busy) {
    $st = $script:SmPS; $st.Busy = $Busy
    foreach ($n in 'BtnPrExport', 'BtnPrDownload', 'BtnPrInventory', 'BtnPrUpload', 'BtnPrLogOn', 'BtnPrLogOff', 'BtnPrCollect', 'BtnPrListShare') { $st.Ui[$n].IsEnabled = -not $Busy }
    Update-SmPrintImportState
}

function Write-SmPrintUiLog($Lines) { foreach ($l in @($Lines)) { & $script:SmPS.Log ([string]$l) } }

function Confirm-SmPrint([string]$Text, [string]$Title = 'Bitte bestätigen') {
    [System.Windows.MessageBox]::Show($Text, $Title, 'YesNo', 'Question', 'No') -eq 'Yes'
}

function Start-SmPrintJobUi {
    <# Gemeinsamer Ablauf: Oberflaeche sperren, Auftrag starten, Ergebnis und Protokollzeilen zeigen (immer nur ein Auftrag). #>
    param([Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Params = @{}, [Parameter(Mandatory)][scriptblock]$OnResult, [string]$What = 'Aktion')
    $st = $script:SmPS
    if ($st.Busy) { return }
    $st.OnResult = $OnResult; $st.What = $What
    Set-SmPrintBusy $true
    [void](Start-SmJob -Modules $st.Modules -Params $Params -Script $Script -OnDone {
            param($result, $err)
            Set-SmPrintBusy $false
            $s = $script:SmPS
            if ($err) { Write-SmPrintUiLog ($s.What + ' fehlgeschlagen: ' + $err); $s.Ui.TxtPrCheck.Text = $s.What + " fehlgeschlagen:`r`n" + $err; return }
            $r = $result[-1]
            if ($r -and $r.PSObject.Properties['Log']) { Write-SmPrintUiLog $r.Log }
            & $s.OnResult $r
        })
}

function Show-SmPrintPrecheck {
    param([ValidateSet('Export', 'Import')][string]$Mode)
    $u = $script:SmPS.Ui
    try {
        $file = $null; $inv = $null
        if ($Mode -eq 'Import') {
            if ($u.CmbPrExportFile.SelectedItem) { $file = Join-Path (Get-SmPrintFolder) ([string]$u.CmbPrExportFile.SelectedItem) }
            $inv = $script:SmPS.OldInv
        }
        $res = Test-SmPrintPrecheck -Mode $Mode -ExportFile $file -OldInventory $inv -Force:([bool]$u.ChkPrForce.IsChecked)
        $u.TxtPrCheck.Text = "Vorprüfung ($Mode)`r`n" + (Format-SmPrecheck $res)
        & $script:SmPS.Log ('Vorprüfung {0}: {1}' -f $Mode, $(if ($res.Ok) { 'bestanden' } else { 'nicht bestanden' }))
        $res
    }
    catch { $u.TxtPrCheck.Text = 'Vorprüfung nicht möglich: ' + $_.Exception.Message }
}

function Start-SmPrintExportUi {
    $res = Show-SmPrintPrecheck -Mode Export
    if (-not $res -or -not $res.Ok) { return }
    if (-not (Confirm-SmPrint ("Alle Drucker, Treiber, Ports, Warteschlangen und Freigaben mit PrintBrm exportieren?`r`n`r`nDie Datei kann einige Minuten dauern und enthält Treiberdateien. Sie liegt im gesicherten Ordner unter ProgramData.") 'Export')) { return }
    $u = $script:SmPS.Ui; $u.TxtPrUploadState.Text = 'Export läuft …'
    Start-SmPrintJobUi -What 'Export' -Script {
        param($State, $P)
        Invoke-SmPrintExport -Confirmed
    } -OnResult {
        param($r)
        $u = $script:SmPS.Ui
        $u.TxtPrExpSha.Text = $r.Export.Sha256
        $u.TxtPrUploadState.Text = 'Export fertig.'
        $u.TxtPrCheck.Text = ("Export: {0} ({1})`r`nSHA256 {2}`r`nInventur: {3}`r`nDie SHA256 mit dem Knopf kopieren und am neuen Server vollständig einfügen. Danach hochladen." -f $r.Export.Name, (Format-SmSize $r.Export.Length), $r.Export.Sha256, $r.Inventory.Name)
        Update-SmPrintLocalList
    }
}

function Update-SmPrintShareLists {
    $share = & $script:SmPS.GetShare
    $u = $script:SmPS.Ui
    if (-not $share) { $u.TxtPrCheck.Text = 'Kein Tauschordner verbunden. Auf der Startseite "Ordner prüfen" wählen.'; return }
    try {
        $files = @(Get-SmShareFiles -Share $share)
        $u.CmbPrExportFile.Items.Clear(); $u.CmbPrInvFile.Items.Clear()
        foreach ($f in $files) {
            if ($f.Name -match $script:SmPrintExportPattern) { [void]$u.CmbPrExportFile.Items.Add($f.Name) }
            elseif ($f.Name -match '^Print-Inventur-[\w.\-]+\.json$') { [void]$u.CmbPrInvFile.Items.Add($f.Name) }
        }
        if ($u.CmbPrExportFile.Items.Count) { $u.CmbPrExportFile.SelectedIndex = 0 }
        if ($u.CmbPrInvFile.Items.Count) { $u.CmbPrInvFile.SelectedIndex = 0 }
        & $script:SmPS.Log ('Tauschordner: {0} Exportdateien, {1} Inventuren' -f $u.CmbPrExportFile.Items.Count, $u.CmbPrInvFile.Items.Count)
    }
    catch { $u.TxtPrCheck.Text = 'Fehler: ' + $_.Exception.Message }
}

function Start-SmPrintDownloadUi {
    $u = $script:SmPS.Ui
    $share = & $script:SmPS.GetShare
    if (-not $share) { $u.TxtPrCheck.Text = 'Kein Tauschordner verbunden.'; return }
    if (-not $u.CmbPrExportFile.SelectedItem) { $u.TxtPrCheck.Text = 'Keine Exportdatei im Tauschordner gewählt.'; return }
    $script:SmPS.DlSha = $null; $script:SmPS.DlName = $null
    $inv = if ($u.CmbPrInvFile.SelectedItem) { [string]$u.CmbPrInvFile.SelectedItem } else { $null }
    Start-SmPrintJobUi -What 'Download' -Params @{ Share = $share; Name = [string]$u.CmbPrExportFile.SelectedItem; Inv = $inv } -Script {
        param($State, $P)
        $exp = Receive-SmPrintShareFile -Share $P.Share -Name $P.Name
        $invObj = $null; $log = @($exp.Log)
        if ($P.Inv) {
            $f = Receive-SmPrintShareFile -Share $P.Share -Name $P.Inv -Pattern '^Print-Inventur-[\w.\-]+\.json$' -MaxBytes 64MB
            $log += $f.Log
            $invObj = Read-SmPrintInventory -Path $f.Path
        }
        [pscustomobject]@{ Export = $exp; Inventory = $invObj; Log = $log }
    } -OnResult {
        param($r)
        $u = $script:SmPS.Ui
        $script:SmPS.OldInv = $r.Inventory; $script:SmPS.DlSha = $r.Export.Sha256; $script:SmPS.DlName = $r.Export.Name
        $u.TxtPrCheck.Text = ("Heruntergeladen: {0} ({1}).`r`nDie berechnete SHA256 wird hier absichtlich nicht angezeigt. Bitte die vollständige SHA256 vom alten Server einfügen; erst bei vollständiger Übereinstimmung ist der Import-Knopf frei." -f $r.Export.Name, (Format-SmSize $r.Export.Length))
        Update-SmPrintImportState
        Update-SmPrintLocalList
    }
}

function Start-SmPrintImportUi {
    $u = $script:SmPS.Ui; $st = $script:SmPS
    if (-not $st.DlSha -or -not (Test-SmShaMatch -Entered $u.TxtPrShaIn.Text -Actual $st.DlSha)) { $u.TxtPrCheck.Text = 'Die SHA256 stimmt nicht. Nichts importiert.'; return }
    $st.Force = [bool]$u.ChkPrForce.IsChecked; $st.Shares = [bool]$u.ChkPrShares.IsChecked; $st.Pub = [bool]$u.ChkPrPublish.IsChecked
    # Schritt 1: Arbeitskopie (gleiche Bytes wie geprueft), Vorpruefung und Inhalt der Exportdatei, noch ohne Aenderung am System
    Start-SmPrintJobUi -What 'Import (Vorbereitung)' -Params @{ Name = $st.DlName; Sha = $u.TxtPrShaIn.Text; Inv = $st.OldInv; Force = $st.Force } -Script {
        param($State, $P)
        Initialize-SmPrintImport -FileName $P.Name -ExpectedSha $P.Sha -OldInventory $P.Inv -Force:$P.Force
    } -OnResult {
        param($plan)
        $st = $script:SmPS; $u = $st.Ui
        if (-not $plan.Ok) {
            Remove-SmPrintTemp $plan.TempRoot
            $u.TxtPrCheck.Text = "Import nicht möglich:`r`n" + ($plan.Problems -join "`r`n")
            & $st.Log 'Import nicht gestartet: Prüfung nicht bestanden.'
            return
        }
        $u.TxtPrCheck.Text = "Vorprüfung bestanden.`r`n" + $plan.Precheck
        if (-not (Confirm-SmPrint (Format-SmPrintImportConfirm -Plan $plan -Shares $st.Shares -Publish $st.Pub -Force $st.Force) 'Import')) {
            Remove-SmPrintTemp $plan.TempRoot
            & $st.Log 'Import vom Benutzer abgebrochen, Arbeitskopie gelöscht.'
            return
        }
        # Schritt 2: importieren, immer aus der Arbeitskopie
        $st.Plan = $plan
        Start-SmPrintJobUi -What 'Import' -Params @{ Plan = $plan; Force = $st.Force; Shares = $st.Shares; Pub = $st.Pub; Inv = $st.OldInv } -Script {
            param($State, $P)
            Invoke-SmPrintImport -Plan $P.Plan -Confirmed -Force:$P.Force -Publish:$P.Pub -KeepShares $P.Shares -OldInventory $P.Inv
        } -OnResult {
            param($r)
            $script:SmPS.Ui.TxtPrCheck.Text = "Import fertig (Exitcode 0).`r`nNächster Schritt: Inventur erstellen und hochladen, der Berater vergleicht sie mit der alten."
            Show-SmToast 'Import fertig. Bitte jetzt die Inventur erstellen.'
        }
    }
}

function Start-SmPrintInventoryUi {
    $u = $script:SmPS.Ui
    if (-not (Test-SmAdmin)) { $u.TxtPrCheck.Text = 'Das Fenster muss als Administrator laufen.'; return }
    $stage = if ($u.RbPrNew.IsChecked) { 'neu' } else { 'alt' }
    Start-SmPrintJobUi -What 'Inventur' -Params @{ Role = $stage } -Script {
        param($State, $P)
        New-SmPrintInventoryFile -Role $P.Role
    } -OnResult {
        param($r)
        $script:SmPS.Ui.TxtPrCheck.Text = ("Inventur: {0} ({1})`r`nSHA256 {2}" -f $r.Name, (Format-SmSize $r.Length), $r.Sha256)
        Update-SmPrintLocalList
    }
}

function Update-SmPrintLocalList {
    $u = $script:SmPS.Ui
    $u.LstPrLocal.Items.Clear()
    $folder = Get-SmPrintFolder
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return }
    try {
        Assert-SmSecureFolder -Path $folder
        foreach ($f in @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -match '^Print-[\w.\-]+\.(json|printerExport)$' } | Sort-Object LastWriteTime -Descending)) { [void]$u.LstPrLocal.Items.Add($f.Name) }
    }
    catch { $u.TxtPrCheck.Text = $_.Exception.Message }
}

function Start-SmPrintUploadUi {
    $u = $script:SmPS.Ui
    $share = & $script:SmPS.GetShare
    if (-not $share) { $u.TxtPrUploadState.Text = 'Kein Tauschordner verbunden.'; return }
    if (-not $u.LstPrLocal.SelectedItem) { $u.TxtPrUploadState.Text = 'Bitte eine Datei in der Liste wählen.'; return }
    $u.TxtPrUploadState.Text = 'Lade hoch …'
    Start-SmPrintJobUi -What 'Hochladen' -Params @{ Share = $share; Name = [string]$u.LstPrLocal.SelectedItem } -Script {
        param($State, $P)
        Send-SmPrintFile -Share $P.Share -Name $P.Name
    } -OnResult {
        param($r)
        $script:SmPS.Ui.TxtPrUploadState.Text = ('Hochgeladen: {0} ({1}), SHA256 {2}' -f $r.Name, (Format-SmSize $r.Length), $r.Sha256)
    }
}

function Update-SmPrintLogUi {
    $u = $script:SmPS.Ui
    try {
        $s = Get-SmPrintLogStatus
        $u.TxtPrLogStatus.Text = ('Protokoll {0}: {1}, Größe {2}' -f $script:SmPrintLog, $(if ($s.Enabled) { 'eingeschaltet' } else { 'ausgeschaltet' }), (Format-SmSize $s.MaxSize))
    }
    catch { $u.TxtPrLogStatus.Text = 'Status nicht lesbar: ' + $_.Exception.Message }
}

function Start-SmPrintLogSwitchUi {
    param([switch]$On)
    $u = $script:SmPS.Ui
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { $u.TxtPrCheck.Text = "Vorprüfung nicht bestanden:`r`n" + (Format-SmPrecheck $pre); return }
    $mb = $u.TxtPrLogSize.Text
    if ($On) {
        try { [void](ConvertTo-SmLogBytes $mb) } catch { $u.TxtPrCheck.Text = $_.Exception.Message; return }
        if (-not (Confirm-SmPrint ("Druckprotokoll einschalten?`r`n`r`nGröße: {0} MB. Der alte Zustand wird gesichert; 'Ausschalten' stellt ihn wieder her. Das Protokoll enthält Benutzer- und Rechnernamen." -f $mb) 'Druckprotokoll')) { return }
    }
    else {
        if (-not (Confirm-SmPrint "Druckprotokoll auf den gesicherten alten Zustand zurücksetzen?" 'Druckprotokoll')) { return }
    }
    Start-SmPrintJobUi -What 'Druckprotokoll' -Params @{ On = [bool]$On; Mb = $mb } -Script {
        param($State, $P)
        if ($P.On) { Enable-SmPrintLog -Megabytes $P.Mb -Confirmed } else { Disable-SmPrintLog -Confirmed }
    } -OnResult {
        param($r)
        Update-SmPrintLogUi
        $script:SmPS.Ui.TxtPrCheck.Text = 'Druckprotokoll geändert. Siehe Protokoll.'
    }
}

function Start-SmPrintCollectUi {
    $u = $script:SmPS.Ui
    $days = 0
    if (-not [int]::TryParse($u.TxtPrDays.Text, [ref]$days) -or $days -lt 1 -or $days -gt 3650) { $u.TxtPrCheck.Text = 'Tage: eine ganze Zahl von 1 bis 3650.'; return }
    $pseudo = [bool]$u.ChkPrPseudo.IsChecked; $salt = $u.TxtPrSalt.Text
    if ($pseudo -and $salt.Trim().Length -lt 8) { $u.TxtPrCheck.Text = 'Für Pseudonyme bitte einen Projekt-Salt mit mindestens 8 Zeichen eingeben (für alle Sammlungen des Projekts derselbe).'; return }
    $pre = Test-SmPrintPrecheck -Mode Log
    if (-not $pre.Ok) { $u.TxtPrCheck.Text = "Vorprüfung nicht bestanden:`r`n" + (Format-SmPrecheck $pre); return }
    $hint = "Datenschutz: Benutzer- und Rechnernamen aus Ereignis 307 sind personenbezogene Daten.`r`nBenutzernamen: {0}.`r`nDie Datei liegt im gesicherten Ordner; hochgeladen wird erst auf Ihren Klick. Nach dem Projekt im Tauschordner und lokal löschen." -f $(if ($pseudo) { 'werden pseudonymisiert (Hash mit Projekt-Salt, der Salt steht nicht in der Datei)' } else { 'stehen im Klartext in der Datei' })
    if (-not (Confirm-SmPrint ("Druckzugriffe der letzten {0} Tage sammeln?`r`n`r`n{1}" -f $days, $hint) 'Zugriffe sammeln')) { return }
    Start-SmPrintJobUi -What 'Sammeln' -Params @{ Days = $days; Pseudo = $pseudo; Salt = $salt } -Script {
        param($State, $P)
        Invoke-SmPrintCollect -Days $P.Days -Pseudonymize:$P.Pseudo -Salt $P.Salt
    } -OnResult {
        param($r)
        $script:SmPS.Ui.TxtPrCheck.Text = ("Gesammelt: {0} ({1} Ereignisse), SHA256 {2}`r`nZum Hochladen in der Liste wählen. Datenschutz: Die Datei enthält personenbezogene Daten." -f $r.Name, $r.Count, $r.Sha256)
        Update-SmPrintLocalList
    }
}
