<#
.SYNOPSIS
    Tauschordner: Dateien ueber einen SharePoint-/OneDrive-Ordner mit dem Freigabelink
    "Jeder mit dem Link kann bearbeiten" austauschen, ohne Anmeldung.
.DESCRIPTION
    Wird per Dot-Source geladen. Der Freigabelink oeffnet eine anonyme Gastsitzung (Cookie). Mit dieser
    Sitzung liest und schreibt die SharePoint-REST-API im Ordner. Es werden keine Zugangsdaten gespeichert.
    Kleine Dateien gehen in einem Aufruf hoch, grosse in Teilen (StartUpload / ContinueUpload / FinishUpload).
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

# Groesse eines Teils beim Hochladen (SharePoint erlaubt bis 250 MB je Teil, 10 MB sind ein guter Mittelwert)
$script:SmChunkSize = 10MB

function Initialize-SmWeb {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    try { [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials } catch { }
}

function Get-SmFinalUri {
    param($Response)
    $base = $Response.BaseResponse
    if ($base.PSObject.Properties['ResponseUri'] -and $base.ResponseUri) { return [uri]$base.ResponseUri }          # Windows PowerShell 5.1
    if ($base.PSObject.Properties['RequestMessage'] -and $base.RequestMessage) { return [uri]$base.RequestMessage.RequestUri }   # PowerShell 7
    return $null
}

function Resolve-SmShareFolder {
    <# Server-relativer Ordnerpfad aus der Zieladresse des Freigabelinks (Parameter id oder RootFolder). #>
    param([uri]$FinalUri, [string]$Content)
    $candidates = @()
    if ($FinalUri) { $candidates += $FinalUri.Query }
    if ($Content) { $candidates += $Content }
    foreach ($text in $candidates) {
        $m = [regex]::Match($text, '(?i)[?&](?:amp;)?(?:id|RootFolder)=(%2F[^&"''<>\s]+|/[^&"''<>\s]+)')
        if ($m.Success) { return [uri]::UnescapeDataString($m.Groups[1].Value).TrimEnd('/') }
    }
    return $null
}

function Format-SmSpString {
    param([string]$Value)
    "'" + [uri]::EscapeDataString($Value.Replace("'", "''")) + "'"
}

function Test-SmFinalHost {
    <# Weiterleitungsziel: https auf *.sharepoint.com (mit -AnyHost nur fuer Tests: derselbe Host wie der Link). #>
    param($Final, [string]$Authority, [switch]$AnyHost)
    if (-not $Final) { return $false }
    if ($AnyHost) { return ($Final.Authority -eq $Authority) }
    [bool]($Final.Scheme -eq 'https' -and $Final.Host -match '^[A-Za-z0-9-]+\.sharepoint\.com$')
}

function Connect-SmShare {
    <# Oeffnet den Tauschordner ueber den Freigabelink. Liefert ein Objekt mit Web, Folder und Session. #>
    param([Parameter(Mandatory)][string]$Link, [switch]$AnyHost)   # AnyHost nur fuer Tests: Ziel muss derselbe Host wie der Link sein
    Initialize-SmWeb
    try {
        $r = Invoke-WebRequest -Uri $Link -UseBasicParsing -SessionVariable shareSession -MaximumRedirection 10 -ErrorAction Stop
    }
    catch {
        throw ("Der Tauschordner ist nicht erreichbar: {0}. Hat der Server Internetzugang zu *.sharepoint.com? Ist der Link noch gueltig?" -f $_.Exception.Message)
    }
    $final = Get-SmFinalUri $r
    $okHost = Test-SmFinalHost -Final $final -Authority ([uri]$Link).Authority -AnyHost:$AnyHost
    if (-not $okHost) { throw 'Der Freigabelink leitet auf ein unerlaubtes Ziel weiter (erlaubt: https auf *.sharepoint.com). Abgebrochen.' }
    $folder = Resolve-SmShareFolder -FinalUri $final -Content $r.Content
    if (-not $folder) {
        throw ("Der Link fuehrt nicht zu einem Ordner ({0}). Bitte einen Ordner mit 'Jeder mit dem Link' und 'Bearbeiten' teilen und den Ordnerlink verwenden." -f $final)
    }
    $parts = $folder.Trim('/') -split '/'
    $web = $final.GetLeftPart([UriPartial]::Authority)
    if ($parts.Count -ge 2 -and $parts[0] -match '^(?i)(personal|sites|teams)$') { $web += '/' + $parts[0] + '/' + $parts[1] }
    [pscustomobject]@{
        Link    = $Link
        Web     = $web
        Folder  = $folder
        Name    = $parts[-1]
        Session = $shareSession
        AnyHost = [bool]$AnyHost
        Authority = ([uri]$Link).Authority
        Digest  = $null
        DigestAt = [datetime]::MinValue
    }
}

function Invoke-SmShareApi {
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Uri, [string]$Method = 'Get', $Body, [string]$OutFile, [hashtable]$Headers = @{}, [switch]$Response)
    $h = @{ Accept = 'application/json;odata=nometadata' }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    $p = @{ Uri = $Uri; Method = $Method; WebSession = $Share.Session; Headers = $h; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p.Body = $Body; $p.ContentType = 'application/octet-stream' }
    if ($Response) { return (Invoke-WebRequest @p) }   # Antwort mit Kopfzeilen (z. B. ETag)
    if ($OutFile) { $p.OutFile = $OutFile; Invoke-WebRequest @p | Out-Null; return }
    Invoke-RestMethod @p
}

function Get-SmShareDigest {
    <# Formular-Digest fuer Schreibzugriffe; wird bis zu 15 Minuten wiederverwendet (er gilt etwa 30 Minuten). #>
    param([Parameter(Mandatory)]$Share, [switch]$Force)
    if (-not $Force -and $Share.Digest -and ((Get-Date) - $Share.DigestAt).TotalMinutes -lt 15) { return $Share.Digest }
    $ctx = Invoke-SmShareApi -Share $Share -Uri ($Share.Web + '/_api/contextinfo') -Method Post
    if (-not $ctx.FormDigestValue) { throw 'Keine Schreibberechtigung im Tauschordner (kein Formular-Digest). Ist der Link auf "Bearbeiten" gestellt?' }
    $Share.Digest = $ctx.FormDigestValue
    $Share.DigestAt = Get-Date
    $Share.Digest
}

function Get-SmShareFiles {
    <# Dateien im Tauschordner (Name, Groesse, Aenderung). #>
    param([Parameter(Mandatory)]$Share)
    $u = '{0}/_api/web/GetFolderByServerRelativeUrl(@f)/Files?@f={1}' -f $Share.Web, (Format-SmSpString $Share.Folder)
    $r = Invoke-SmShareApi -Share $Share -Uri $u
    @($r.value | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Length = [long]$_.Length; Modified = $_.TimeLastModified } })
}

function Receive-SmShareFile {
    <#
    .SYNOPSIS
        Laedt eine Datei aus dem Tauschordner und bricht ab, sobald mehr als MaxBytes ankommen (Angabe im Kopf oder gelesene Bytes).
        Die teilweise geladene Datei wird dann geloescht.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$OutFile, [long]$MaxBytes = 2GB)
    Initialize-SmWeb
    $u = '{0}/_api/web/GetFileByServerRelativeUrl(@f)/$value?@f={1}' -f $Share.Web, (Format-SmSpString ($Share.Folder + '/' + $Name))
    $req = [Net.HttpWebRequest][Net.WebRequest]::Create($u)
    $req.Method = 'GET'; $req.Accept = 'application/json;odata=nometadata'; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 10
    $req.Timeout = 120000; $req.ReadWriteTimeout = 120000
    if ($Share.Session) {
        if ($Share.Session.Cookies) { $req.CookieContainer = $Share.Session.Cookies }
        if ($Share.Session.UserAgent) { $req.UserAgent = $Share.Session.UserAgent }
    }
    $resp = $req.GetResponse()
    try {
        if (-not (Test-SmFinalHost -Final $resp.ResponseUri -Authority ([string]$Share.Authority) -AnyHost:([bool]$Share.AnyHost))) { throw 'Der Download wurde auf ein unerlaubtes Ziel weitergeleitet. Abgebrochen.' }
        if ($resp.ContentLength -gt $MaxBytes) { throw ('Die Datei ist groesser als das Limit ({0:N0} Bytes).' -f $MaxBytes) }
        $src = $resp.GetResponseStream()
        $dst = [IO.File]::Open($OutFile, 'Create', 'Write', 'None')
        $ok = $false
        try {
            $buf = New-Object byte[] (1MB); $total = 0L
            while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
                $total += $n
                if ($total -gt $MaxBytes) { throw ('Der Download ist groesser als das Limit ({0:N0} Bytes), abgebrochen.' -f $MaxBytes) }
                $dst.Write($buf, 0, $n)
            }
            $ok = $true
        }
        finally { $dst.Dispose(); $src.Dispose(); if (-not $ok) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue } }
    }
    finally { $resp.Close() }
}

function Get-SmChunkPlan {
    <#
    .SYNOPSIS
        Teilt eine Dateigroesse in Teile fuer den Upload in Teilen auf. Reine Rechnung, ohne Zugriff auf Dateien oder Netz.
    .DESCRIPTION
        Liefert je Teil Index, Offset, Length und Kind: 'Start' (erster), 'Continue' (mittlere), 'Finish' (letzter).
        Passt die Datei in einen Teil (oder ist leer), ist die Liste leer: dann genuegt ein einfacher Upload.
        Der letzte Teil ist nie leer.
    #>
    param([Parameter(Mandatory)][long]$Length, [long]$ChunkSize = $script:SmChunkSize)
    if ($ChunkSize -lt 1) { throw 'ChunkSize muss groesser als 0 sein.' }
    if ($Length -le $ChunkSize) { return @() }
    $count = [int][math]::Ceiling($Length / $ChunkSize)
    for ($i = 0; $i -lt $count; $i++) {
        $offset = [long]$i * $ChunkSize
        $kind = if ($i -eq 0) { 'Start' } elseif ($i -eq $count - 1) { 'Finish' } else { 'Continue' }
        [pscustomobject]@{ Index = $i; Offset = $offset; Length = [long][math]::Min($ChunkSize, $Length - $offset); Kind = $kind }
    }
}

function ConvertTo-SmOffset {
    <# StartUpload und ContinueUpload liefern die neue Position, je nach Antwortformat als Zahl, Text oder { value = ... }. #>
    param($Response)
    $v = $Response
    if ($null -ne $Response -and $Response.PSObject.Properties['value']) { $v = $Response.value }
    if ($null -ne $v -and $v.PSObject.Properties['d'] -and $v.d) { $v = $v.d }
    $n = 0L
    if ([long]::TryParse([string]$v, [ref]$n)) { return $n }
    throw ('Unerwartete Antwort beim Hochladen in Teilen: ' + [string]$v)
}

function Send-SmShareFile {
    <#
    .SYNOPSIS
        Laedt eine Datei in den Tauschordner (eine vorhandene gleichen Namens wird ersetzt).
        Grosse Dateien gehen in Teilen hoch. Progress bekommt (gesendete Bytes, Gesamtbytes).
    #>
    param(
        [Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Path,
        [long]$ChunkSize = $script:SmChunkSize, [scriptblock]$Progress, [int]$Retries = 3
    )
    $name = Split-Path -Leaf $Path
    if ($name -notmatch '^[\w.\-]+$') { throw "Dateiname mit Sonderzeichen: $name" }
    $length = (Get-Item -LiteralPath $Path).Length
    $folderArg = Format-SmSpString $Share.Folder
    $addUri = "{0}/_api/web/GetFolderByServerRelativeUrl(@f)/Files/add(url='{1}',overwrite=true)?@f={2}" -f $Share.Web, $name, $folderArg
    $plan = @(Get-SmChunkPlan -Length $length -ChunkSize $ChunkSize)
    try {
        if ($plan.Count -eq 0) {
            $digest = Get-SmShareDigest -Share $Share
            $null = Invoke-SmShareApi -Share $Share -Uri $addUri -Method Post -Body ([IO.File]::ReadAllBytes($Path)) -Headers @{ 'X-RequestDigest' = $digest }
            if ($Progress) { & $Progress $length $length }
        }
        else {
            # leere Datei anlegen, dann Teile anhaengen
            $digest = Get-SmShareDigest -Share $Share
            $null = Invoke-SmShareApi -Share $Share -Uri $addUri -Method Post -Body ([byte[]]@()) -Headers @{ 'X-RequestDigest' = $digest }
            $uploadId = [guid]::NewGuid().ToString()
            $fileArg = Format-SmSpString ($Share.Folder + '/' + $name)
            $base = '{0}/_api/web/GetFileByServerRelativeUrl(@f)' -f $Share.Web
            $fs = [IO.File]::OpenRead($Path)
            try {
                $sent = 0L
                foreach ($c in $plan) {
                    $buf = New-Object byte[] $c.Length
                    [void]$fs.Seek($c.Offset, 'Begin')
                    $got = 0
                    while ($got -lt $c.Length) { $n = $fs.Read($buf, $got, [int]($c.Length - $got)); if ($n -le 0) { throw 'Datei ist kuerzer als erwartet.' }; $got += $n }
                    $uri = switch ($c.Kind) {
                        'Start' { "$base/StartUpload(uploadId=guid'$uploadId')?@f=$fileArg" }
                        'Continue' { "$base/ContinueUpload(uploadId=guid'$uploadId',fileOffset=$($c.Offset))?@f=$fileArg" }
                        'Finish' { "$base/FinishUpload(uploadId=guid'$uploadId',fileOffset=$($c.Offset))?@f=$fileArg" }
                    }
                    for ($try = 1; $try -le $Retries; $try++) {
                        try {
                            $digest = Get-SmShareDigest -Share $Share
                            $resp = Invoke-SmShareApi -Share $Share -Uri $uri -Method Post -Body $buf -Headers @{ 'X-RequestDigest' = $digest }
                            if ($c.Kind -ne 'Finish') {
                                $next = ConvertTo-SmOffset $resp
                                if ($next -ne ($c.Offset + $c.Length)) { throw "Server meldet Position $next, erwartet $($c.Offset + $c.Length)." }
                            }
                            break
                        }
                        catch {
                            if ($try -eq $Retries) { throw }
                            Start-Sleep -Seconds (2 * $try)
                            $null = Get-SmShareDigest -Share $Share -Force
                        }
                    }
                    $sent += $c.Length
                    if ($Progress) { & $Progress $sent $length }
                }
            }
            finally { $fs.Dispose() }
        }
    }
    catch {
        throw ("Hochladen fehlgeschlagen: {0}. Ist der Link auf 'Bearbeiten' gestellt?" -f $_.Exception.Message)
    }
    $check = @(Get-SmShareFiles -Share $Share | Where-Object Name -eq $name)
    if (-not $check) { throw "Die Datei $name ist nach dem Hochladen nicht im Tauschordner zu sehen." }
    if ($check[0].Length -ne $length) { throw "Die Datei $name hat im Tauschordner $($check[0].Length) Bytes statt $length." }
    $check[0]
}
