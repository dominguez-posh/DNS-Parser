#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 1: Syntax und Analyse aller Scripts, beide Fenster mit -ParseOnly (hell und dunkel),
    Pruefsumme, Aufteilung in Teile, Einzeiler, und Tauschordner gegen einen nachgebauten SharePoint-Server auf localhost
    (Freigabelink mit Weiterleitung und Gast-Cookie, Dateien auflisten, hochladen auch in Teilen, herunterladen,
    Einzeiler mit richtiger und falscher Pruefsumme). Keine echten Tenants, keine Links ins Netz.
    Mit Windows PowerShell 5.1 ausfuehren: powershell.exe -NoProfile -STA -File tests\Test-ServerMigration.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
# Ist Windows PowerShell 5.1 aus PowerShell 7 gestartet, steht dessen Modulpfad im PSModulePath und verdeckt die 5.1-Module (z. B. Get-FileHash): entfernen.
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = Join-Path $env:TEMP ('sm-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force $work | Out-Null
$script:fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

# ---------------------------------------------------------------- 1. Syntax, Kodierung, Analyse
$scripts = @(Get-ChildItem -Path $repo -Recurse -Include *.ps1 -File | Where-Object { $_.FullName -notmatch '\\(\.git|\.claude)\\' -and $_.Name -ne 'DNSParser.ps1' })
Check "Scripts gefunden ($($scripts.Count))" ($scripts.Count -ge 7)
foreach ($s in $scripts) {
    $errs = $null; $tokens = $null
    [void][Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$tokens, [ref]$errs)
    Check ("Syntax: " + $s.Name) (-not $errs)
    $bytes = [IO.File]::ReadAllBytes($s.FullName)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $ascii = -not ($bytes | Where-Object { $_ -gt 127 } | Select-Object -First 1)
    Check ("Kodierung ASCII oder UTF-8 mit BOM: " + $s.Name) ($bom -or $ascii)
}
if (Get-Module -ListAvailable PSScriptAnalyzer) {
    $found = @(Invoke-ScriptAnalyzer -Path $repo -Recurse -Severity Error | Where-Object { $_.ScriptName -ne 'DNSParser.ps1' })
    Check "PSScriptAnalyzer: keine Fehler ($($found.Count))" ($found.Count -eq 0)
}
else { Write-Host 'INFO PSScriptAnalyzer nicht installiert, Analyse uebersprungen' -ForegroundColor Yellow }

# ---------------------------------------------------------------- 2. Fenster bauen (nichts anzeigen)
foreach ($mode in 'Light', 'Dark') {
    foreach ($entry in @(@('Berater-Tool', 'Start-ServerMigration.ps1'), @('Server-Fenster', 'server\Start-SmServer.ps1'))) {
        $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $repo $entry[1]) -ParseOnly -Theme $mode 2>&1 | Out-String
        Check ("$($entry[0]) -ParseOnly ($mode): $($out.Trim())") ($out.Trim() -eq 'PARSE OK')
    }
}

# ---------------------------------------------------------------- 3. Module laden
. (Join-Path $repo 'Modules\SmTausch.ps1')
. (Join-Path $repo 'Modules\SmPaket.ps1')

# Pruefsumme
$f = Join-Path $work 'abc.bin'; [IO.File]::WriteAllBytes($f, [Text.Encoding]::ASCII.GetBytes('abc'))
Check 'SHA256 von "abc" (Datei)' ((Get-SmSha256 -Path $f) -eq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD')
Check 'SHA256 von "abc" (Bytes)' ((Get-SmSha256 -Bytes ([Text.Encoding]::ASCII.GetBytes('abc'))) -eq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD')
Check 'SHA256 gleich Get-FileHash' ((Get-SmSha256 -Path $f) -eq (Get-FileHash $f -Algorithm SHA256).Hash)

# Aufteilung in Teile
function PlanOk([long]$Len, [long]$Chunk) {
    $p = @(Get-SmChunkPlan -Length $Len -ChunkSize $Chunk)
    if ($p.Count -eq 0) { return $Len -le $Chunk }
    $sum = 0L; $next = 0L; $ok = $true
    foreach ($c in $p) { if ($c.Offset -ne $next -or $c.Length -lt 1 -or $c.Length -gt $Chunk) { $ok = $false }; $next += $c.Length; $sum += $c.Length }
    $ok -and $sum -eq $Len -and $p[0].Kind -eq 'Start' -and $p[-1].Kind -eq 'Finish' -and (@($p | Where-Object Kind -eq 'Start').Count -eq 1) -and (@($p | Where-Object Kind -eq 'Finish').Count -eq 1)
}
Check 'Teile: leere Datei -> einfacher Upload' (@(Get-SmChunkPlan -Length 0 -ChunkSize 100).Count -eq 0)
Check 'Teile: genau ein Teil -> einfacher Upload' (@(Get-SmChunkPlan -Length 100 -ChunkSize 100).Count -eq 0)
Check 'Teile: 101 Bytes = 2 Teile (100 + 1)' ((@(Get-SmChunkPlan -Length 101 -ChunkSize 100) | ForEach-Object Length) -join ',' -eq '100,1')
Check 'Teile: genaues Vielfaches (300 = 3 x 100), letzter nicht leer' ((@(Get-SmChunkPlan -Length 300 -ChunkSize 100) | ForEach-Object { "$($_.Kind):$($_.Length)" }) -join ',' -eq 'Start:100,Continue:100,Finish:100')
Check 'Teile: Summe und Reihenfolge fuer viele Groessen' ((@(0, 1, 99, 100, 101, 199, 200, 201, 1000, 12345) | Where-Object { -not (PlanOk $_ 100) }).Count -eq 0)
Check 'Teile: 1 GB mit 10 MB = 103 Teile' (@(Get-SmChunkPlan -Length 1GB -ChunkSize 10MB).Count -eq 103)
Check 'Teile: ChunkSize 0 abgelehnt' (Throws { Get-SmChunkPlan -Length 10 -ChunkSize 0 })

# Link-Pruefung
$good = 'https://contoso-my.sharepoint.com/:f:/g/personal/max_contoso_com/EaBcD-12_xyz?e=AbC123'
Check 'Link: gueltiger Ordnerlink' ((Test-SmShareLink ('  <' + $good + '>  ')) -eq $good)
Check 'Link: Dateilink abgelehnt' (Throws { Test-SmShareLink 'https://contoso-my.sharepoint.com/:u:/g/personal/max_contoso_com/EaBc?e=1' })
Check 'Link: fremde Domain abgelehnt' (Throws { Test-SmShareLink 'https://evil.example.com/:f:/g/x' })
Check 'Link: Anfuehrungszeichen abgelehnt' (Throws { Test-SmShareLink ($good + "';calc;'") })
Check 'Link: typografisches Anfuehrungszeichen abgelehnt' (Throws { Test-SmShareLink ($good + [string][char]0x2019 + 'x') })
Check 'Link: Leerzeichen abgelehnt' (Throws { Test-SmShareLink ($good + ' x') })
Check 'Link: http abgelehnt' (Throws { Test-SmShareLink $good.Replace('https', 'http') })
Check 'Link: leer abgelehnt' (Throws { Test-SmShareLink '' })

# Einzeiler (Aufbau)
$sha = 'A' * 64
$line = New-SmOneLiner -Link $good -Sha256 $sha
Check 'Einzeiler: eine Zeile und ASCII' (($line -notmatch "[`r`n]") -and ($line -notmatch '[^\x20-\x7E]'))
Check 'Einzeiler: Link und Pruefsumme enthalten' ($line.Contains("`$L='$good'") -and $line.Contains("`$H='$sha'"))
Check 'Einzeiler: Skriptfreigabe nur -Scope Process' ($line.Contains('Set-ExecutionPolicy Bypass -Scope Process'))
Check 'Einzeiler: Pruefung vor Entpacken und Start' ($line.IndexOf('ComputeHash') -lt $line.IndexOf('Expand-Archive') -and $line.IndexOf('Expand-Archive') -lt $line.IndexOf('Start-SmServer.ps1'))
Check 'Einzeiler: schreibt kein Protokoll und keine Datei ausser dem Paket' ($line -notmatch '(?i)Start-Transcript|Out-File|Add-Content|Set-Content')
Check 'Einzeiler: Zielpruefung nach Weiterleitung (https, sharepoint.com) vor dem Download' ($line.Contains("Scheme-ne'https'") -and $line.Contains('sharepoint\.com') -and $line.IndexOf('Scheme-ne') -lt $line.IndexOf('GetFileByServerRelativeUrl'))
Check 'Einzeiler: Pruefsumme im Speicher, Ausfuehrung aus neuem Zufallsverzeichnis' ($line.Contains('ComputeHash($b)') -and $line.Contains('[guid]::NewGuid()') -and $line -notmatch 'Get-FileHash|OutFile|Remove-Item')
Check 'Einzeiler: ServerArguments -ParseOnly erlaubt' ((New-SmOneLiner -Link $good -Sha256 $sha -ServerArguments '-ParseOnly').EndsWith('-ParseOnly}'))
Check 'Einzeiler: ServerArguments mit Fremdcode abgelehnt' (Throws { New-SmOneLiner -Link $good -Sha256 $sha -ServerArguments "'; calc" })
Check 'Einzeiler: ServerArguments, andere Schalter abgelehnt' (Throws { New-SmOneLiner -Link $good -Sha256 $sha -ServerArguments '-ParseOnly; calc' })
Check 'Link: sharepoint.de nicht erlaubt (nur sharepoint.com)' (Throws { Test-SmShareLink 'https://contoso.sharepoint.de/:f:/g/x' })
Check 'Einzeiler: falsche Pruefsumme abgelehnt' (Throws { New-SmOneLiner -Link $good -Sha256 'abc' })
Check 'Einzeiler: Parser findet keine Syntaxfehler' ($(try { [void][scriptblock]::Create($line); $true } catch { $false }))

# Paket
$pkgDir = Join-Path $work 'pkg'
$pkg = New-SmServerPackage -RepoRoot $repo -OutDir $pkgDir
Add-Type -AssemblyName System.IO.Compression.FileSystem
$entries = @([IO.Compression.ZipFile]::OpenRead($pkg.Path).Entries | ForEach-Object FullName)
foreach ($n in $script:SmServerFiles) { Check ('Paket enthaelt ' + $n) ($entries -contains ('ServerMigration/' + $n)) }
Check 'Paket: keine Backslashes in den Eintragsnamen' (-not ($entries | Where-Object { $_ -match '\\' }))
Check 'Paket: Pruefsumme passt zur Datei' ($pkg.Sha256 -eq (Get-FileHash $pkg.Path -Algorithm SHA256).Hash)
Check 'Paket: Berater-Tool nicht enthalten' (-not ($entries | Where-Object { $_ -match 'Start-ServerMigration|SmPaket' }))

# ---------------------------------------------------------------- 4. nachgebauter SharePoint
$port = Get-Random -Minimum 18100 -Maximum 18900
$base = "http://localhost:$port"
$folder = '/personal/max_contoso_com/Documents/Tausch Test'
$link = "$base/:f:/g/personal/max_contoso_com/EAbcDEF?e=x1Y2z3"
$store = [hashtable]::Synchronized(@{})
$stats = [hashtable]::Synchronized(@{ Start = 0; Continue = 0; Finish = 0; FailOnce = $false; Failed = 0 })

$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("$base/")
$listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Start()
$rs = [runspacefactory]::CreateRunspace(); $rs.Open()
$server = [powershell]::Create(); $server.Runspace = $rs
[void]$server.AddScript({
        param($listener, $store, $stats, $base, $folder)
        $web = '/personal/max_contoso_com'
        $uploads = @{}
        while ($listener.IsListening) {
            try { $c = $listener.GetContext() } catch { break }
            $q = $c.Request; $res = $c.Response
            $raw = [uri]::UnescapeDataString($q.RawUrl)
            $body = $null; $status = 200; $type = 'application/json'
            $guest = $q.Cookies['FedAuth'] -and $q.Cookies['FedAuth'].Value -eq 'gast'
            if ($q.Url.AbsolutePath -eq '/:f:/g/personal/max_contoso_com/EAbcDEF') {
                $res.AddHeader('Set-Cookie', 'FedAuth=gast; path=/')
                $res.StatusCode = 302
                $res.RedirectLocation = "$base$web/_layouts/15/onedrive.aspx?id=" + [uri]::EscapeDataString($folder) + '&ga=1'
                $res.Close(); continue
            }
            elseif ($q.Url.AbsolutePath -eq '/:f:/g/personal/max_contoso_com/EVIL') {
                $res.StatusCode = 302
                $res.RedirectLocation = ($base -replace 'localhost', '127.0.0.1') + "$web/_layouts/15/onedrive.aspx?id=" + [uri]::EscapeDataString($folder)
                $res.Close(); continue
            }
            elseif ($q.Url.AbsolutePath -eq "$web/_layouts/15/onedrive.aspx") { $type = 'text/html'; $body = [Text.Encoding]::UTF8.GetBytes('<html>OneDrive</html>') }
            elseif (-not $guest) { $status = 401; $body = [Text.Encoding]::UTF8.GetBytes('{"error":"no guest session"}') }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -eq "$web/_api/contextinfo") { $body = [Text.Encoding]::UTF8.GetBytes('{"FormDigestValue":"digest-123"}') }
            elseif ($q.HttpMethod -eq 'POST' -and $q.Headers['X-RequestDigest'] -ne 'digest-123') { $status = 403 }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -match "^$web/_api/web/GetFolderByServerRelativeUrl\(@f\)/Files/add\(url='([^']+)',overwrite=true\)\?@f='(.+)'$") {
                if ($Matches[2] -ne $folder) { $status = 403 }
                else {
                    $ms = New-Object IO.MemoryStream; $q.InputStream.CopyTo($ms)
                    $store[$Matches[1]] = $ms.ToArray()
                    $body = [Text.Encoding]::UTF8.GetBytes('{"Name":"' + $Matches[1] + '"}')
                }
            }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -match "^$web/_api/web/GetFileByServerRelativeUrl\(@f\)/(Start|Continue|Finish)Upload\(uploadId=guid'([0-9a-f-]+)'(?:,fileOffset=(\d+))?\)\?@f='(.+)'$") {
                $kind = $Matches[1]; $id = $Matches[2]; $off = if ($Matches[3]) { [long]$Matches[3] } else { 0L }; $path = $Matches[4]
                $name = if ($path.StartsWith($folder + '/')) { $path.Substring($folder.Length + 1) } else { $null }
                if (-not $name -or -not $store.ContainsKey($name)) { $status = 404 }
                else {
                    $ms = New-Object IO.MemoryStream; $q.InputStream.CopyTo($ms)
                    $stats[$kind]++
                    if ($kind -eq 'Start') { $uploads[$id] = New-Object IO.MemoryStream }
                    if ($kind -eq 'Continue' -and $stats.FailOnce -and -not $stats.Failed) { $stats.Failed = 1; $status = 500 }   # einmaliger Serverfehler
                    elseif (-not $uploads.ContainsKey($id)) { $status = 404 }
                    elseif ($uploads[$id].Length -ne $off) { $status = 400 }   # falscher Offset
                    elseif ($ms.Length -lt 1) { $status = 400 }
                    else {
                        $b = $ms.ToArray(); $uploads[$id].Write($b, 0, $b.Length)
                        if ($kind -eq 'Finish') { $store[$name] = $uploads[$id].ToArray(); $uploads.Remove($id); $body = [Text.Encoding]::UTF8.GetBytes('{"Name":"' + $name + '"}') }
                        else { $body = [Text.Encoding]::UTF8.GetBytes('{"value":"' + $uploads[$id].Length + '"}') }
                    }
                }
            }
            elseif ($raw -match "^$web/_api/web/GetFolderByServerRelativeUrl\(@f\)/Files\?@f='(.+)'$") {
                if ($Matches[1] -ne $folder) { $status = 404 }
                else {
                    $items = @($store.Keys | Where-Object { $_ -notlike '__*' } | ForEach-Object { '{"Name":"' + $_ + '","Length":"' + $store[$_].Length + '","TimeLastModified":"2026-11-07T10:00:00Z"}' })
                    $body = [Text.Encoding]::UTF8.GetBytes('{"value":[' + ($items -join ',') + ']}')
                }
            }
            elseif ($raw -match "^$web/_api/web/GetFileByServerRelativeUrl\(@f\)/\`$value\?@f='(.+)'$") {
                $name = $Matches[1].Substring([math]::Min($Matches[1].Length, $folder.Length + 1))
                if ($Matches[1].StartsWith($folder + '/') -and $store.ContainsKey($name)) { $type = 'application/octet-stream'; $body = $store[$name] } else { $status = 404 }
            }
            else { $status = 404 }
            $res.StatusCode = $status; $res.ContentType = $type
            if ($body) { $res.OutputStream.Write($body, 0, $body.Length) }
            $res.Close()
        }
    }).AddArgument($listener).AddArgument($store).AddArgument($stats).AddArgument($base).AddArgument($folder)
$serverHandle = $server.BeginInvoke()

try {
    $share = Connect-SmShare -Link $link -AnyHost
    Check 'Freigabelink: Ordner erkannt' ($share.Folder -eq $folder)
    Check 'Freigabelink: Web erkannt' ($share.Web -eq "$base/personal/max_contoso_com")
    Check 'Freigabelink: Ordnername' ($share.Name -eq 'Tausch Test')
    Check 'leerer Tauschordner' (@(Get-SmShareFiles -Share $share).Count -eq 0)
    $evil = $false; try { Connect-SmShare -Link "$base/:f:/g/personal/max_contoso_com/EVIL" -AnyHost | Out-Null } catch { $evil = $_.Exception.Message -match 'unerlaubtes Ziel' }
    Check 'Tauschordner: Weiterleitung auf fremden Host abgelehnt' $evil
    $bad = $false; try { Connect-SmShare -Link "$base/nicht-da" | Out-Null } catch { $bad = $_.Exception.Message -match 'nicht erreichbar' }
    Check 'ungueltiger Link: verstaendliche Meldung' $bad

    # kleine Datei: ein Aufruf
    $small = Join-Path $work 'klein_1.txt'; [IO.File]::WriteAllText($small, ('x' * 5000))
    $sent = Send-SmShareFile -Share $share -Path $small -ChunkSize 64KB
    Check 'Hochladen klein: Datei im Ordner, Groesse stimmt' ($sent.Name -eq 'klein_1.txt' -and $sent.Length -eq 5000)
    Check 'Hochladen klein: keine Teile benutzt' ($stats.Start -eq 0)
    $back = Join-Path $work 'klein_zurueck.txt'
    Receive-SmShareFile -Share $share -Name 'klein_1.txt' -OutFile $back
    Check 'Herunterladen klein: Inhalt gleich' ((Get-FileHash $back).Hash -eq (Get-FileHash $small).Hash)

    # grosse Datei in Teilen (Zufallsbytes, 3 Teile und Rest)
    $big = Join-Path $work 'gross_1.bin'
    $rnd = New-Object byte[] (64KB * 3 + 1234); (New-Object Random 42).NextBytes($rnd); [IO.File]::WriteAllBytes($big, $rnd)
    $prog = New-Object System.Collections.ArrayList
    $sentBig = Send-SmShareFile -Share $share -Path $big -ChunkSize 64KB -Progress { param($s, $t) [void]$prog.Add("$s/$t") }
    Check 'Hochladen gross: Groesse stimmt' ($sentBig.Length -eq $rnd.Length)
    Check "Hochladen gross: Start/Continue/Finish = $($stats.Start)/$($stats.Continue)/$($stats.Finish) (erwartet 1/2/1)" ($stats.Start -eq 1 -and $stats.Continue -eq 2 -and $stats.Finish -eq 1)
    Check 'Hochladen gross: Fortschritt meldet jeden Teil bis 100 Prozent' ($prog.Count -eq 4 -and $prog[-1] -eq "$($rnd.Length)/$($rnd.Length)")
    $backBig = Join-Path $work 'gross_zurueck.bin'
    Receive-SmShareFile -Share $share -Name 'gross_1.bin' -OutFile $backBig
    Check 'Herunterladen gross: vollstaendig und gleich zusammengesetzt (SHA256)' ((Get-FileHash $backBig).Hash -eq (Get-FileHash $big).Hash)

    # genaues Vielfaches und erneutes Hochladen ersetzt die Datei
    $exact = Join-Path $work 'gross_1.bin'
    [IO.File]::WriteAllBytes($exact, (New-Object byte[] (64KB * 2)))
    $stats.Start = 0; $stats.Continue = 0; $stats.Finish = 0
    $sentExact = Send-SmShareFile -Share $share -Path $exact -ChunkSize 64KB
    Check 'Hochladen genaues Vielfaches: 2 Teile, ersetzt die Datei' ($sentExact.Length -eq 128KB -and $stats.Start -eq 1 -and $stats.Finish -eq 1 -and @(Get-SmShareFiles -Share $share | Where-Object Name -eq 'gross_1.bin').Count -eq 1)

    # einmaliger Serverfehler mitten im Upload: Wiederholung
    $retry = Join-Path $work 'retry_1.bin'
    [IO.File]::WriteAllBytes($retry, $rnd)
    $stats.FailOnce = $true; $stats.Failed = 0
    $sentRetry = Send-SmShareFile -Share $share -Path $retry -ChunkSize 64KB
    Check 'Hochladen: ein Serverfehler wird wiederholt, Datei vollstaendig' ($stats.Failed -eq 1 -and $sentRetry.Length -eq $rnd.Length -and (Get-SmSha256 -Bytes $store['retry_1.bin']) -eq (Get-SmSha256 -Path $retry))
    $stats.FailOnce = $false

    # Dateiname mit Sonderzeichen
    $odd = Join-Path $work 'mit leerzeichen.txt'; [IO.File]::WriteAllText($odd, 'x')
    Check 'Dateiname mit Leerzeichen abgelehnt' (Throws { Send-SmShareFile -Share $share -Path $odd })

    # ------------------------------------------------------------ Berater legt das Paket selbst ab, Einzeiler startet das Server-Fenster
    $pub = Publish-SmServerPackage -Share $share -RepoRoot $repo -OutDir (Join-Path $work 'pub') -AnyHost
    Check 'Paket im Tauschordner, Groesse stimmt' ($pub.Remote.Name -eq 'SM-Server-Paket.zip' -and $pub.Remote.Length -eq $pub.Package.Length)
    Check 'Paket im Tauschordner: Inhalt gleich der lokalen Datei' ((Get-SmSha256 -Bytes $store['SM-Server-Paket.zip']) -eq $pub.Package.Sha256)
    Check 'Einzeiler enthaelt die Pruefsumme des abgelegten Pakets' ($pub.OneLiner.Contains("`$H='$($pub.Package.Sha256)'"))
    Check 'Einzeiler wird nicht in eine Datei geschrieben' (-not (Test-Path (Join-Path $work 'pub\Einzeiler.txt')))

    $temp = Join-Path $work 'temp'; New-Item -ItemType Directory -Force $temp | Out-Null
    $runner = Join-Path $work 'einzeiler.ps1'
    # nur im Test: das Fenster wird gebaut, aber nicht angezeigt
    $testLine = New-SmOneLiner -Link $link -Sha256 $pub.Package.Sha256 -ServerArguments '-ParseOnly' -AnyHost
    [IO.File]::WriteAllText($runner, $testLine, [Text.Encoding]::ASCII)
    $oldTemp = $env:TEMP; $env:TEMP = $temp
    try { $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File $runner 2>&1 | Out-String } finally { $env:TEMP = $oldTemp }
    Check "Einzeiler: Paket geladen, geprueft, Fenster gebaut ($($out.Trim()))" ($out -match 'PARSE OK')
    $runDirs = @(Get-ChildItem -LiteralPath $temp -Directory -Filter 'ServerMigration-*')
    Check 'Einzeiler: Paket in neues Zufallsverzeichnis entpackt' ($runDirs.Count -eq 1 -and $runDirs[0].Name -match '^ServerMigration-[0-9a-f]{32}$' -and (Test-Path (Join-Path $runDirs[0].FullName 'ServerMigration\UI\Theme.xaml')))

    # falsche Pruefsumme: nichts entpacken, nichts ausfuehren
    Remove-Item $runDirs[0].FullName -Recurse -Force
    $store['SM-Server-Paket.zip'] = [Text.Encoding]::ASCII.GetBytes('manipuliert')
    $env:TEMP = $temp
    $ErrorActionPreference = 'Continue'   # das Kind schreibt den erwarteten Fehler nach stderr
    try { $out2 = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File $runner 2>&1 | Out-String } finally { $env:TEMP = $oldTemp; $ErrorActionPreference = 'Stop' }
    Check 'falsche Pruefsumme: Abbruch mit Meldung' ($out2 -match 'Pruefsumme falsch' -and $out2 -notmatch 'PARSE OK')
    Check 'falsche Pruefsumme: nichts entpackt, nichts geschrieben' (@(Get-ChildItem -LiteralPath $temp).Count -eq 0)

    # Weiterleitung auf fremden Host: der Einzeiler bricht vor dem Download ab
    $evilRunner = Join-Path $work 'einzeiler-evil.ps1'
    [IO.File]::WriteAllText($evilRunner, (New-SmOneLiner -Link "$base/:f:/g/personal/max_contoso_com/EVIL" -Sha256 $pub.Package.Sha256 -ServerArguments '-ParseOnly' -AnyHost), [Text.Encoding]::ASCII)
    $env:TEMP = $temp
    $ErrorActionPreference = 'Continue'
    try { $out3 = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File $evilRunner 2>&1 | Out-String } finally { $env:TEMP = $oldTemp; $ErrorActionPreference = 'Stop' }
    Check 'Einzeiler: Weiterleitung auf fremden Host abgelehnt, nichts geschrieben' ($out3 -match 'unerlaubtes Ziel' -and $out3 -notmatch 'PARSE OK' -and @(Get-ChildItem -LiteralPath $temp).Count -eq 0)
}
finally {
    $listener.Stop(); $listener.Close()
    try { [void]$server.EndInvoke($serverHandle) } catch { }
    $server.Dispose(); $rs.Dispose()
}
# ---------------------------------------------------------------- 5. Phase 2: Projektliste (eigene Datei)
Write-Host ''
Write-Host '--- Projektliste (tests\Test-Projekte.ps1)'
$script:fails += [int](@(& (Join-Path $PSScriptRoot 'Test-Projekte.ps1') -Repo $repo -Work $work)[-1])
# ---------------------------------------------------------------- 5. DNS (Phase 3): Parser, Auswertung, Server-Funktionen, Geschwindigkeit
$dnsOut = Join-Path $work 'test-dns.txt'
$ErrorActionPreference = 'Continue'
& powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $repo 'tests\Test-Dns.ps1') *> $dnsOut
$dnsCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
foreach ($l in (Get-Content -LiteralPath $dnsOut)) { if ($l -match '^(OK|FAIL|INFO) ') { Write-Host $l } }
Check "Test-Dns.ps1: Exitcode $dnsCode (0 = keine Fehler)" ($dnsCode -eq 0)

Write-Host ''
Write-Host "$script:fails Fehler"
exit $script:fails
