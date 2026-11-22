<#
.SYNOPSIS
    Phase 2: Projektliste. Alle Projekte in einer verschluesselten Datei, die direkt ueber einen Freigabelink
    (SharePoint-REST wie beim Tauschordner) gelesen und geschrieben wird. Einzelne Projekte lassen sich als Datei weitergeben.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht vorher Modules\SmTausch.ps1 und Modules\SmPaket.ps1, fuer die Oberflaeche auch SmShell.ps1).
    Dateiformat (.smproj, immer gleich fuer Liste und Einzelprojekt):
        4 Byte  Kennung "SMPJ"
        1 Byte  Formatversion (1)
        4 Byte  PBKDF2-Iterationen (big endian, mindestens 200000)
        16 Byte Salt (zufaellig)
        16 Byte IV (zufaellig)
        n Byte  AES-256-CBC (PKCS7) ueber den JSON-Inhalt
        32 Byte HMAC-SHA256 ueber alles davor (encrypt-then-MAC)
    Schluessel: PBKDF2-SHA256 (Rfc2898DeriveBytes mit HashAlgorithmName) liefert 64 Byte, 32 fuer AES, 32 fuer HMAC.
    Der Inhalt traegt eine eigene Schemaversion (Schema), damit spaetere Phasen je Projekt Ergebnisse (Results) ergaenzen koennen.
    Das Kennwort bleibt im Speicher. Optional merkt sich der Rechner Link und Kennwort per DPAPI (CurrentUser).
    Links, Kennwoerter und Schluessel kommen in keine Meldung und kein Protokoll (Sicherheits-Checkliste Punkt 6).
    Windows PowerShell 5.1, .NET 4.7.2 oder neuer. Datei bleibt ASCII.
#>

$script:SmProjFileName = 'ServerMigration-Projekte.smproj'
$script:SmProjMagic = [byte[]](0x53, 0x4D, 0x50, 0x4A)   # SMPJ
$script:SmProjFormat = 1
$script:SmProjSchema = 1
$script:SmProjMinIter = 200000
$script:SmProjMaxIter = 5000000
$script:SmProjDefaultIter = 250000
$script:SmProjMaxBytes = 20MB
$script:SmProjMinPassword = 8
$script:SmProjRoles = @('DNS', 'DHCP', 'Print', 'DC')
$script:SmProjGenerations = @('alt', 'neu')
$script:SmProjStatus = @('Geplant', 'Laufend', 'Abgeschlossen', 'Archiviert')
$script:SmProjMaxProjects = 500
$script:SmProjMaxServers = 100

# ---------------------------------------------------------------- Hilfen

function Get-SmSafeMessage {
    <# Entfernt Adressen und uebergebene Geheimnisse (Link, Kennwort) aus einer Meldung. #>
    param([string]$Message, [string[]]$Secrets = @())
    $m = [string]$Message
    foreach ($s in $Secrets) { if ($s -and $s.Length -ge 3) { $m = $m.Replace($s, '<geheim>') } }
    $m = [regex]::Replace($m, '(?i)\b(?:https?|ftp)://\S+', '<Adresse>')
    $m = [regex]::Replace($m, "(?i)'[^']*\.sharepoint\.com[^']*'", '<Adresse>')
    $m
}

function ConvertTo-SmPlain {
    <# Macht aus JSON-Objekten, Hashtables und Listen ueberall geordnete Hashtables und object[] (Unbekanntes bleibt erhalten). #>
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [datetime]) { return $Obj.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Obj -is [string] -or $Obj -is [bool] -or $Obj.GetType().IsPrimitive -or $Obj -is [decimal]) { return $Obj }
    if ($Obj -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $Obj.Keys) { $h[[string]$k] = ConvertTo-SmPlain $Obj[$k] }
        return $h
    }
    if ($Obj -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Obj) { $list.Add((ConvertTo-SmPlain $i)) }
        return , $list.ToArray()
    }
    $h = [ordered]@{}
    foreach ($p in $Obj.PSObject.Properties) { if ($p.MemberType -eq 'NoteProperty') { $h[$p.Name] = ConvertTo-SmPlain $p.Value } }
    $h
}

function Get-SmNowText { [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Assert-SmText {
    param($Value, [string]$Label, [int]$Max, [switch]$Required, [switch]$Multiline)
    $v = if ($null -eq $Value) { '' } else { [string]$Value }
    $bad = if ($Multiline) { '[\x00-\x08\x0B\x0C\x0E-\x1F]' } else { '[\x00-\x1F]' }
    if ($v -match $bad) { throw "$Label enthaelt unerlaubte Steuerzeichen." }
    $v = $v.Trim()
    if ($Required -and -not $v) { throw "$Label fehlt." }
    if ($v.Length -gt $Max) { throw "$Label ist zu lang (hoechstens $Max Zeichen)." }
    $v
}

# ---------------------------------------------------------------- Verschluesselung

function Get-SmProjectKeys {
    param([Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)][byte[]]$Salt, [Parameter(Mandatory)][int]$Iterations)
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { [pscustomobject]@{ Enc = $kdf.GetBytes(32); Mac = $kdf.GetBytes(32) } } finally { $kdf.Dispose() }
}

function Test-SmBytesEqual {
    <# Vergleich in konstanter Zeit (fuer den HMAC). #>
    param([byte[]]$A, [byte[]]$B)
    if ($A.Length -ne $B.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $d = $d -bor ($A[$i] -bxor $B[$i]) }
    $d -eq 0
}

function Protect-SmProjectData {
    <#
    .SYNOPSIS
        Verschluesselt ein Objekt (Projektliste oder Einzelprojekt) mit einem Kennwort. Liefert die Bytes der .smproj-Datei.
    #>
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$Password, [int]$Iterations = $script:SmProjDefaultIter)
    if ($Password.Length -lt $script:SmProjMinPassword) { throw "Das Kennwort ist zu kurz (mindestens $script:SmProjMinPassword Zeichen)." }
    if ($Iterations -lt $script:SmProjMinIter -or $Iterations -gt $script:SmProjMaxIter) { throw 'Ungueltige Iterationszahl.' }
    $json = ConvertTo-Json -InputObject (ConvertTo-SmPlain $Data) -Depth 32 -Compress
    $plain = [Text.Encoding]::UTF8.GetBytes($json)
    if ($plain.Length -gt $script:SmProjMaxBytes) { throw 'Die Projektdaten sind zu gross.' }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16
    $rng.GetBytes($salt); $rng.GetBytes($iv); $rng.Dispose()
    $keys = Get-SmProjectKeys -Password $Password -Salt $salt -Iterations $Iterations
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $keys.Enc; $aes.IV = $iv
        $enc = $aes.CreateEncryptor()
        try { $cipher = $enc.TransformFinalBlock($plain, 0, $plain.Length) } finally { $enc.Dispose() }
    }
    finally { $aes.Dispose() }
    $ms = New-Object IO.MemoryStream
    $ms.Write($script:SmProjMagic, 0, 4)
    $ms.WriteByte([byte]$script:SmProjFormat)
    $it = [BitConverter]::GetBytes([int]$Iterations); [Array]::Reverse($it)   # big endian
    $ms.Write($it, 0, 4)
    $ms.Write($salt, 0, 16); $ms.Write($iv, 0, 16); $ms.Write($cipher, 0, $cipher.Length)
    $head = $ms.ToArray()
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, $keys.Mac)
    try { $tag = $hmac.ComputeHash($head) } finally { $hmac.Dispose() }
    $ms.Write($tag, 0, 32)
    $out = $ms.ToArray(); $ms.Dispose()
    [Array]::Clear($keys.Enc, 0, 32); [Array]::Clear($keys.Mac, 0, 32); [Array]::Clear($plain, 0, $plain.Length)
    , $out
}

function Unprotect-SmProjectData {
    <#
    .SYNOPSIS
        Prueft und entschluesselt eine .smproj-Datei. Liefert den Inhalt als geordnete Hashtable.
        Falsches Kennwort und veraenderte Datei ergeben dieselbe klare Meldung, nie Teildaten.
    #>
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Password)
    $headLen = 4 + 1 + 4 + 16 + 16
    if ($Bytes.Length -gt $script:SmProjMaxBytes) { throw 'Die Datei ist zu gross fuer eine Projektdatei.' }
    if ($Bytes.Length -lt $headLen + 16 + 32 -or $Bytes[0] -ne 0x53 -or $Bytes[1] -ne 0x4D -or $Bytes[2] -ne 0x50 -or $Bytes[3] -ne 0x4A) {
        throw 'Das ist keine Projektdatei von Server-Migration (Kennung fehlt).'
    }
    $ver = [int]$Bytes[4]
    if ($ver -ne $script:SmProjFormat) { throw "Die Datei hat Format $ver, dieses Tool kennt Format $script:SmProjFormat. Bitte das Tool aktualisieren." }
    $itb = $Bytes[5..8]; [Array]::Reverse($itb)
    $iter = [BitConverter]::ToInt32([byte[]]$itb, 0)
    if ($iter -lt $script:SmProjMinIter -or $iter -gt $script:SmProjMaxIter) { throw 'Die Datei hat ungueltige Schluesselparameter und wird nicht gelesen.' }
    $cipherLen = $Bytes.Length - $headLen - 32
    if ($cipherLen -lt 16 -or $cipherLen % 16 -ne 0) { throw 'Die Projektdatei ist beschaedigt (Laenge).' }
    $salt = [byte[]]$Bytes[9..24]; $iv = [byte[]]$Bytes[25..40]
    $keys = Get-SmProjectKeys -Password $Password -Salt $salt -Iterations $iter
    try {
        $head = New-Object byte[] ($Bytes.Length - 32); [Array]::Copy($Bytes, 0, $head, 0, $head.Length)
        $tag = New-Object byte[] 32; [Array]::Copy($Bytes, $Bytes.Length - 32, $tag, 0, 32)
        $hmac = New-Object Security.Cryptography.HMACSHA256 (, $keys.Mac)
        try { $calc = $hmac.ComputeHash($head) } finally { $hmac.Dispose() }
        if (-not (Test-SmBytesEqual $calc $tag)) { throw 'Das Kennwort ist falsch oder die Datei wurde veraendert. Es wurden keine Daten gelesen.' }
        $cipher = New-Object byte[] $cipherLen; [Array]::Copy($Bytes, $headLen, $cipher, 0, $cipherLen)
        $aes = [Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $keys.Enc; $aes.IV = $iv
            $dec = $aes.CreateDecryptor()
            try { $plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length) }
            catch { throw 'Die Projektdatei ist beschaedigt (Entschluesselung).' }
            finally { $dec.Dispose() }
        }
        finally { $aes.Dispose() }
    }
    finally { [Array]::Clear($keys.Enc, 0, 32); [Array]::Clear($keys.Mac, 0, 32) }
    try { $obj = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($plain)) } catch { throw 'Der Inhalt der Projektdatei ist nicht lesbar.' }
    finally { [Array]::Clear($plain, 0, $plain.Length) }
    $plainObj = ConvertTo-SmPlain $obj
    if ($plainObj -isnot [System.Collections.IDictionary]) { throw 'Der Inhalt der Projektdatei ist nicht lesbar.' }
    $plainObj
}

# ---------------------------------------------------------------- Datenmodell

function New-SmProject {
    param(
        [Parameter(Mandatory)][string]$Name, [string]$Customer = '', [string]$Notes = '', [string]$ShareLink = '',
        [object[]]$Servers = @(), [string]$Status = 'Geplant'
    )
    $now = Get-SmNowText
    ConvertTo-SmProjectRecord ([ordered]@{
            Id = [guid]::NewGuid().ToString(); Name = $Name; Customer = $Customer; Notes = $Notes; ShareLink = $ShareLink
            Servers = $Servers; Status = $Status; Created = $now; Modified = $now; Results = [ordered]@{}
        })
}

function ConvertTo-SmProjectRecord {
    <#
    .SYNOPSIS
        Prueft ein Projekt (aus der Oberflaeche, aus JSON, aus einer Importdatei) und liefert eine bereinigte Kopie.
        Unbekannte Felder (z. B. Ergebnisse spaeterer Phasen) bleiben erhalten. Werte kommen nur ueber Whitelists durch.
    #>
    param([Parameter(Mandatory)]$Project)
    $p = ConvertTo-SmPlain $Project
    if ($p -isnot [System.Collections.IDictionary]) { throw 'Projekt ungueltig.' }
    $now = Get-SmNowText
    $id = if ($p['Id']) { [string]$p['Id'] } else { [guid]::NewGuid().ToString() }
    if ($id -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw 'Projekt-Id ungueltig.' }
    $link = Assert-SmText $p['ShareLink'] 'Tauschordner-Link' 2000
    if ($link) { $link = Test-SmShareLink $link }
    $status = Assert-SmText $p['Status'] 'Status' 30
    if (-not $status) { $status = 'Geplant' }
    if ($script:SmProjStatus -notcontains $status) { throw "Status '$status' ist nicht erlaubt." }
    $servers = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($p['Servers'])) {
        if ($null -eq $s) { continue }
        if ($s -isnot [System.Collections.IDictionary]) { throw 'Server-Eintrag ungueltig.' }
        $sn = Assert-SmText $s['Name'] 'Servername' 253 -Required
        if ($sn -notmatch '^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$') { throw "Servername '$sn' ist ungueltig (erlaubt: Buchstaben, Ziffern, Punkt, Bindestrich)." }
        $role = [string]$s['Role']; $gen = [string]$s['Generation']
        if ($script:SmProjRoles -cnotcontains $role) { throw "Rolle '$role' ist nicht erlaubt (DNS, DHCP, Print, DC)." }
        if ($script:SmProjGenerations -cnotcontains $gen) { throw "Eintrag '$gen' ist nicht erlaubt (alt oder neu)." }
        $entry = [ordered]@{ Name = $sn; Role = $role; Generation = $gen }
        foreach ($k in $s.Keys) { if (-not $entry.Contains($k)) { $entry[$k] = $s[$k] } }
        $servers.Add($entry)
    }
    if ($servers.Count -gt $script:SmProjMaxServers) { throw "Zu viele Server (hoechstens $script:SmProjMaxServers)." }
    $created = if ($p['Created'] -and [string]$p['Created'] -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { [string]$p['Created'] } else { $now }
    $modified = if ($p['Modified'] -and [string]$p['Modified'] -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { [string]$p['Modified'] } else { $now }
    $results = if ($p['Results'] -is [System.Collections.IDictionary]) { $p['Results'] } else { [ordered]@{} }
    $out = [ordered]@{
        Id = $id.ToLowerInvariant(); Name = (Assert-SmText $p['Name'] 'Projektname' 100 -Required); Customer = (Assert-SmText $p['Customer'] 'Kunde' 100)
        Notes = (Assert-SmText $p['Notes'] 'Notizen' 20000 -Multiline); ShareLink = $link; Servers = $servers.ToArray()
        Status = $status; Created = $created; Modified = $modified; Results = $results
    }
    foreach ($k in $p.Keys) { if (-not $out.Contains($k)) { $out[$k] = $p[$k] } }
    $out
}

function New-SmProjectList {
    [ordered]@{ Kind = 'List'; Schema = $script:SmProjSchema; Created = (Get-SmNowText); Projects = @() }
}

function ConvertTo-SmProjectList {
    <# Prueft eine entschluesselte Projektliste und liefert eine bereinigte Kopie. #>
    param([Parameter(Mandatory)]$Data)
    $d = ConvertTo-SmPlain $Data
    if ($d -isnot [System.Collections.IDictionary] -or $d['Kind'] -ne 'List') { throw 'Das ist keine Projektliste (eventuell ein einzelnes exportiertes Projekt).' }
    $schema = 0
    if (-not [int]::TryParse([string]$d['Schema'], [ref]$schema) -or $schema -lt 1) { throw 'Die Projektliste hat keine gueltige Schemaversion.' }
    if ($schema -gt $script:SmProjSchema) { throw "Die Projektliste hat Schema $schema, dieses Tool kennt Schema $script:SmProjSchema. Bitte das Tool aktualisieren." }
    $projects = @($d['Projects'])
    if ($projects.Count -gt $script:SmProjMaxProjects) { throw "Zu viele Projekte (hoechstens $script:SmProjMaxProjects)." }
    $seen = @{}; $list = New-Object System.Collections.Generic.List[object]
    foreach ($pr in $projects) {
        if ($null -eq $pr) { continue }
        $rec = ConvertTo-SmProjectRecord $pr
        if ($seen.ContainsKey($rec.Id)) { throw 'Die Projektliste enthaelt eine Projekt-Id doppelt.' }
        $seen[$rec.Id] = $true; $list.Add($rec)
    }
    $d['Projects'] = $list.ToArray(); $d['Schema'] = $schema
    $d
}

function Copy-SmData { param($Data) ConvertTo-SmPlain (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject (ConvertTo-SmPlain $Data) -Depth 32 -Compress)) }

function Set-SmProjectInList {
    <# Fuegt ein Projekt hinzu oder ersetzt das mit gleicher Id. Liefert die neue Liste (die alte bleibt unveraendert). #>
    param([Parameter(Mandatory)]$List, [Parameter(Mandatory)]$Project, [switch]$KeepModified)
    $l = Copy-SmData $List
    $rec = ConvertTo-SmProjectRecord $Project
    if (-not $KeepModified) { $rec['Modified'] = Get-SmNowText }
    $items = New-Object System.Collections.Generic.List[object]; $found = $false
    foreach ($e in @($l['Projects'])) { if ($e['Id'] -eq $rec.Id) { $items.Add($rec); $found = $true } else { $items.Add($e) } }
    if (-not $found) { $items.Add($rec) }
    $l['Projects'] = $items.ToArray()
    ConvertTo-SmProjectList $l
}

function Remove-SmProjectFromList {
    param([Parameter(Mandatory)]$List, [Parameter(Mandatory)][string]$Id)
    $l = Copy-SmData $List
    $l['Projects'] = @(@($l['Projects']) | Where-Object { $_['Id'] -ne $Id })
    ConvertTo-SmProjectList $l
}

function Find-SmProjects {
    <# Suche in Name, Kunde, Notizen, Status und Servernamen (ohne Beachtung der Gross-/Kleinschreibung). #>
    param([Parameter(Mandatory)]$List, [string]$Text = '')
    $all = @($List['Projects'])
    $t = $Text.Trim()
    if (-not $t) { return @($all | Sort-Object { $_['Name'] }) }
    $hit = foreach ($p in $all) {
        $hay = @($p['Name'], $p['Customer'], $p['Notes'], $p['Status']) + @(@($p['Servers']) | ForEach-Object { $_['Name'] })
        if (($hay -join "`n").IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $p }
    }
    @($hit | Sort-Object { $_['Name'] })
}

# ---------------------------------------------------------------- Export und Import eines Projekts

function Export-SmProject {
    <# Liefert die Bytes einer .smproj-Datei mit einem Projekt, verschluesselt mit eigenem Kennwort. #>
    param([Parameter(Mandatory)]$Project, [Parameter(Mandatory)][string]$Password, [int]$Iterations = $script:SmProjDefaultIter)
    $rec = ConvertTo-SmProjectRecord $Project
    Protect-SmProjectData -Data ([ordered]@{ Kind = 'Project'; Schema = $script:SmProjSchema; Exported = (Get-SmNowText); Project = $rec }) -Password $Password -Iterations $Iterations
}

function Import-SmProject {
    <# Entschluesselt eine exportierte Projektdatei und liefert das geprueft bereinigte Projekt (Stand unveraendert). #>
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Password)
    $d = Unprotect-SmProjectData -Bytes $Bytes -Password $Password
    if ($d['Kind'] -ne 'Project') { throw 'Das ist keine exportierte Projektdatei (eventuell die ganze Projektliste).' }
    $schema = 0
    if (-not [int]::TryParse([string]$d['Schema'], [ref]$schema) -or $schema -lt 1 -or $schema -gt $script:SmProjSchema) { throw 'Die Projektdatei hat eine unbekannte Schemaversion. Bitte das Tool aktualisieren.' }
    ConvertTo-SmProjectRecord $d['Project']
}

# ---------------------------------------------------------------- Ablage auf dem Freigabelink (mit ETag)

function Get-SmHttpStatus {
    param($ErrorRecord)
    try { $r = $ErrorRecord.Exception.Response; if ($r) { return [int]$r.StatusCode } } catch { }
    0
}

function Get-SmProjectFileMeta {
    <# ETag und Groesse der Projektdatei im Tauschordner; $null, wenn es sie nicht gibt. #>
    param([Parameter(Mandatory)]$Share)
    $u = '{0}/_api/web/GetFileByServerRelativeUrl(@f)?@f={1}&$select=ETag,Length' -f $Share.Web, (Format-SmSpString ($Share.Folder + '/' + $script:SmProjFileName))
    try { $r = Invoke-SmShareApi -Share $Share -Uri $u }
    catch {
        if ((Get-SmHttpStatus $_) -eq 404) { return $null }
        throw ('Die Projektliste ist nicht lesbar: ' + (Get-SmSafeMessage $_.Exception.Message @($Share.Link)))
    }
    $etag = if ($r.PSObject.Properties['ETag']) { [string]$r.ETag } elseif ($r.PSObject.Properties['odata.etag']) { [string]$r.'odata.etag' } else { $null }
    if (-not $etag) { throw 'Der Ablageort liefert keinen ETag. Ohne ETag kann die Projektliste nicht sicher gespeichert werden.' }
    [pscustomobject]@{ ETag = $etag; Length = [long]$r.Length }
}

function Read-SmProjectStore {
    <# Liest und entschluesselt die Projektliste. Exists = $false, wenn noch keine Datei da ist. #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Password)
    for ($try = 1; $try -le 3; $try++) {
        $meta = Get-SmProjectFileMeta -Share $Share
        if (-not $meta) { return [pscustomobject]@{ Exists = $false; ETag = $null; List = (New-SmProjectList) } }
        if ($meta.Length -gt $script:SmProjMaxBytes) { throw 'Die Projektdatei im Ablageort ist ungewoehnlich gross und wird nicht gelesen.' }
        $u = '{0}/_api/web/GetFileByServerRelativeUrl(@f)/$value?@f={1}' -f $Share.Web, (Format-SmSpString ($Share.Folder + '/' + $script:SmProjFileName))
        try { $resp = Invoke-WebRequest -Uri $u -WebSession $Share.Session -UseBasicParsing -ErrorAction Stop -Headers @{ Accept = 'application/octet-stream' } }
        catch { throw ('Die Projektliste ist nicht lesbar: ' + (Get-SmSafeMessage $_.Exception.Message @($Share.Link))) }
        $bytes = $resp.RawContentStream.ToArray()
        $after = Get-SmProjectFileMeta -Share $Share
        if ($after -and $after.ETag -eq $meta.ETag) {
            $list = ConvertTo-SmProjectList (Unprotect-SmProjectData -Bytes $bytes -Password $Password)
            return [pscustomobject]@{ Exists = $true; ETag = $meta.ETag; List = $list }
        }
        # die Datei hat sich waehrend des Lesens geaendert: nochmal
    }
    throw 'Die Projektliste wird gerade von jemand anderem gespeichert. Bitte gleich nochmal versuchen.'
}

function Send-SmProjectBytes {
    <#
    .SYNOPSIS
        Schreibt die Bytes in die Projektdatei. Mit ETag: ersetzt nur, wenn die Datei noch diesen Stand hat (If-Match).
        Ohne ETag: legt die Datei neu an und scheitert, wenn es sie schon gibt. Liefert Ok/Conflict.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][byte[]]$Bytes, [string]$ETag)
    $digest = Get-SmShareDigest -Share $Share
    $folderArg = Format-SmSpString $Share.Folder
    try {
        if ($ETag) {
            $u = '{0}/_api/web/GetFileByServerRelativeUrl(@f)/$value?@f={1}' -f $Share.Web, (Format-SmSpString ($Share.Folder + '/' + $script:SmProjFileName))
            $null = Invoke-SmShareApi -Share $Share -Uri $u -Method Post -Body $Bytes -Headers @{ 'X-RequestDigest' = $digest; 'If-Match' = $ETag; 'X-HTTP-Method' = 'PUT' }
        }
        else {
            $u = "{0}/_api/web/GetFolderByServerRelativeUrl(@f)/Files/add(url='{1}',overwrite=false)?@f={2}" -f $Share.Web, $script:SmProjFileName, $folderArg
            $null = Invoke-SmShareApi -Share $Share -Uri $u -Method Post -Body $Bytes -Headers @{ 'X-RequestDigest' = $digest }
        }
    }
    catch {
        $status = Get-SmHttpStatus $_
        if ($ETag -and $status -in 409, 412) { return [pscustomobject]@{ Ok = $false; Conflict = $true; ETag = $null } }
        if (-not $ETag) {
            $exists = $null
            try { $exists = Get-SmProjectFileMeta -Share $Share } catch { }
            if ($exists) { return [pscustomobject]@{ Ok = $false; Conflict = $true; ETag = $null } }
        }
        throw ('Speichern der Projektliste fehlgeschlagen: ' + (Get-SmSafeMessage $_.Exception.Message @($Share.Link)) + ' Ist der Link auf Bearbeiten gestellt?')
    }
    $meta = Get-SmProjectFileMeta -Share $Share
    [pscustomobject]@{ Ok = $true; Conflict = $false; ETag = $meta.ETag }
}

function Save-SmProjectStore {
    <#
    .SYNOPSIS
        Verschluesselt die Liste und speichert sie, wenn niemand sie inzwischen geaendert hat.
        Conflict = $true: jemand anderes war schneller, nichts wurde ueberschrieben. Dann neu laden.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)]$List, [string]$ETag)
    $checked = ConvertTo-SmProjectList $List
    $bytes = Protect-SmProjectData -Data $checked -Password $Password
    # Vorab-Pruefung schliesst die meisten Konflikte aus, falls der Ablageort If-Match nicht auswertet; If-Match deckt den Rest ab
    $meta = Get-SmProjectFileMeta -Share $Share
    if ($ETag) { if (-not $meta -or $meta.ETag -ne $ETag) { return [pscustomobject]@{ Ok = $false; Conflict = $true; ETag = $null } } }
    elseif ($meta) { return [pscustomobject]@{ Ok = $false; Conflict = $true; ETag = $null } }
    Send-SmProjectBytes -Share $Share -Bytes $bytes -ETag $ETag
}

# ---------------------------------------------------------------- Kennwort merken (DPAPI, nur dieser Benutzer auf diesem Rechner)

function Get-SmRememberPath { Join-Path $env:APPDATA 'ServerMigration\verbindung.dat' }

function Save-SmRemembered {
    param([Parameter(Mandatory)][string]$Link, [Parameter(Mandatory)][string]$Password, [string]$Path = (Get-SmRememberPath))
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $json = ConvertTo-Json -InputObject ([ordered]@{ Link = $Link; Password = $Password }) -Compress
    $secure = ConvertTo-SecureString -String $json -AsPlainText -Force
    [IO.File]::WriteAllText($Path, (ConvertFrom-SecureString -SecureString $secure), [Text.Encoding]::ASCII)
}

function Get-SmRemembered {
    param([string]$Path = (Get-SmRememberPath))
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $secure = ConvertTo-SecureString -String ([IO.File]::ReadAllText($Path).Trim())
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $json = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $o = ConvertFrom-Json -InputObject $json
        if ($o.Link -and $o.Password) { return [pscustomobject]@{ Link = [string]$o.Link; Password = [string]$o.Password } }
    }
    catch { }
    $null   # unlesbar (anderer Benutzer oder Rechner): wie nicht gemerkt
}

function Clear-SmRemembered {
    param([string]$Path = (Get-SmRememberPath))
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}

# ---------------------------------------------------------------- Oberflaeche (Seite "Projekte")

function Get-SmProjectPageXaml {
    param([Parameter(Mandatory)][string]$Root)
    [IO.File]::ReadAllText((Join-Path $Root 'UI\Projekte.xaml'))
}

function Get-SmProjectUiNames {
    @('TxtListLink', 'PwdList', 'ChkRemember', 'BtnListConnect', 'BtnListNew', 'BtnListReload', 'BtnForget', 'TxtListState', 'BoxConflict', 'TxtConflict', 'BtnConflictReload',
        'TxtSearch', 'LstProjects', 'TxtActive', 'BtnProjNew', 'BtnProjEdit', 'BtnProjDelete', 'BtnProjActivate', 'BtnProjExport', 'BtnProjImport', 'TxtListEmpty',
        'BoxEditor', 'TxtEditorTitle', 'TxtName', 'TxtCustomer', 'CmbStatus', 'TxtShare', 'TxtNotes', 'LstServers', 'TxtSrvName', 'CmbSrvRole', 'CmbSrvGen', 'BtnSrvAdd', 'BtnSrvRemove',
        'BtnProjSave', 'BtnProjCancel', 'TxtEditorError')
}

function Get-SmPasswordDialogXaml {
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="440" SizeToContent="Height" WindowStartupLocation="CenterOwner" ResizeMode="NoResize" ShowInTaskbar="False"
        Background="{DynamicResource Surface}" Foreground="{DynamicResource Text}" FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="14">
    <StackPanel Margin="24,20,24,20">
        <TextBlock x:Name="TxtDlgTitle" Style="{DynamicResource CardTitle}"/>
        <TextBlock x:Name="TxtDlgText" Style="{DynamicResource Hint}" Margin="0,4,0,12"/>
        <TextBlock Text="Kennwort" Style="{DynamicResource SmallLabel}"/>
        <PasswordBox x:Name="PwdDlg1" Padding="8,6" Background="{DynamicResource Card}" Foreground="{DynamicResource Text}" BorderBrush="{DynamicResource Border}" AutomationProperties.Name="Kennwort"/>
        <StackPanel x:Name="BoxDlg2" Visibility="Collapsed">
            <TextBlock Text="Kennwort wiederholen" Style="{DynamicResource SmallLabel}" Margin="0,10,0,2"/>
            <PasswordBox x:Name="PwdDlg2" Padding="8,6" Background="{DynamicResource Card}" Foreground="{DynamicResource Text}" BorderBrush="{DynamicResource Border}" AutomationProperties.Name="Kennwort wiederholen"/>
        </StackPanel>
        <TextBlock x:Name="TxtDlgError" Foreground="{DynamicResource DangerText}" TextWrapping="Wrap" Margin="0,8,0,0"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button x:Name="BtnDlgOk" Content="OK" Style="{DynamicResource PrimaryButton}" IsDefault="True" Margin="0,0,8,0" MinWidth="80"/>
            <Button x:Name="BtnDlgCancel" Content="Abbrechen" IsCancel="True" MinWidth="80"/>
        </StackPanel>
    </StackPanel>
</Window>
'@
}

function Show-SmPasswordDialog {
    <# Fragt ein Kennwort ab (bei -Confirm zweimal, mit Mindestlaenge). Liefert das Kennwort oder $null bei Abbruch. #>
    param([string]$Title = 'Kennwort', [string]$Text = '', [switch]$Confirm, $Owner)
    [xml]$x = Get-SmPasswordDialogXaml
    $win = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($x))
    if ($Owner) { $win.Owner = $Owner }
    $win.Title = $Title
    $win.FindName('TxtDlgTitle').Text = $Title
    $win.FindName('TxtDlgText').Text = $Text
    if ($Confirm) { $win.FindName('BoxDlg2').Visibility = 'Visible' }
    $state = @{ Value = $null; Confirm = [bool]$Confirm; Win = $win; Min = $script:SmProjMinPassword }   # der Handler ist ein Closure: kein $script: darin
    $win.FindName('BtnDlgOk').Add_Click({
            $w = $state.Win
            $p1 = $w.FindName('PwdDlg1').Password
            $err = $w.FindName('TxtDlgError')
            if (-not $p1) { $err.Text = 'Bitte ein Kennwort eingeben.'; return }
            if ($state.Confirm) {
                if ($p1.Length -lt $state.Min) { $err.Text = "Das Kennwort ist zu kurz (mindestens $($state.Min) Zeichen)."; return }
                if ($p1 -cne $w.FindName('PwdDlg2').Password) { $err.Text = 'Die beiden Kennwoerter sind nicht gleich.'; return }
            }
            $state.Value = $p1
            $w.DialogResult = $true
        }.GetNewClosure())
    [void]$win.ShowDialog()
    $state.Value
}

function Initialize-SmProjectPage {
    <#
    .SYNOPSIS
        Verdrahtet die Seite "Projekte" (UI\Projekte.xaml). OnActiveChanged($project) wird gerufen, wenn das aktive Projekt wechselt
        ($project ist $null, wenn keins mehr aktiv ist); die Seite "Tauschordner" uebernimmt daraus den Link.
    #>
    param([Parameter(Mandatory)]$Ui, [Parameter(Mandatory)][string[]]$JobModules, [Parameter(Mandatory)][scriptblock]$AddLog, [scriptblock]$OnActiveChanged)
    $script:SmProj = @{ Ui = $Ui; Modules = $JobModules; Log = $AddLog; OnActive = $OnActiveChanged; Link = $null; Password = $null; ETag = $null; List = $null; ActiveId = $null; Editing = $null; EditServers = @(); Busy = $false; Pending = $null }
    $st = $script:SmProj
    foreach ($s in $script:SmProjStatus) { [void]$Ui.CmbStatus.Items.Add($s) }
    foreach ($s in $script:SmProjRoles) { [void]$Ui.CmbSrvRole.Items.Add($s) }
    foreach ($s in $script:SmProjGenerations) { [void]$Ui.CmbSrvGen.Items.Add($s) }
    $Ui.CmbSrvRole.SelectedIndex = 0; $Ui.CmbSrvGen.SelectedIndex = 0; $Ui.CmbStatus.SelectedIndex = 0
    Update-SmProjectPage

    $Ui.BtnListConnect.Add_Click({ Start-SmProjConnect })
    $Ui.BtnListReload.Add_Click({ Start-SmProjConnect -Reload })
    $Ui.BtnConflictReload.Add_Click({ Start-SmProjConnect -Reload })
    $Ui.BtnListNew.Add_Click({ Start-SmProjCreateList })
    $Ui.BtnForget.Add_Click({ Clear-SmRemembered; $script:SmProj.Ui.BtnForget.Visibility = 'Collapsed'; $script:SmProj.Ui.ChkRemember.IsChecked = $false; & $script:SmProj.Log 'Gemerkte Verbindung auf diesem Rechner geloescht'; Show-SmToast 'Gemerkte Verbindung geloescht.' })
    $Ui.TxtSearch.Add_TextChanged({ Update-SmProjectPage })
    $Ui.LstProjects.Add_SelectionChanged({ Update-SmProjectButtons })
    $Ui.LstProjects.Add_MouseDoubleClick({ Open-SmProjEditor -Existing })
    $Ui.BtnProjNew.Add_Click({ Open-SmProjEditor })
    $Ui.BtnProjEdit.Add_Click({ Open-SmProjEditor -Existing })
    $Ui.BtnProjCancel.Add_Click({ $script:SmProj.Editing = $null; $script:SmProj.Ui.BoxEditor.Visibility = 'Collapsed' })
    $Ui.BtnProjSave.Add_Click({ Save-SmProjEditor })
    $Ui.BtnSrvAdd.Add_Click({ Add-SmProjEditorServer })
    $Ui.BtnSrvRemove.Add_Click({ Remove-SmProjEditorServer })
    $Ui.BtnProjDelete.Add_Click({ Remove-SmProjSelected })
    $Ui.BtnProjActivate.Add_Click({ Set-SmProjActive })
    $Ui.BtnProjExport.Add_Click({ Export-SmProjSelected })
    $Ui.BtnProjImport.Add_Click({ Import-SmProjFromFile })

    $r = Get-SmRemembered
    if ($r) {
        $Ui.TxtListLink.Text = $r.Link; $Ui.PwdList.Password = $r.Password; $Ui.ChkRemember.IsChecked = $true; $Ui.BtnForget.Visibility = 'Visible'
        Start-SmProjConnect
    }
}

function Get-SmProjSelectedId {
    $item = $script:SmProj.Ui.LstProjects.SelectedItem
    if ($item) { [string]$item.Tag } else { $null }
}

function Get-SmProjById([string]$Id) {
    if (-not $script:SmProj.List) { return $null }
    @($script:SmProj.List['Projects']) | Where-Object { $_['Id'] -eq $Id } | Select-Object -First 1
}

function Set-SmProjBusy([bool]$Busy) {
    $st = $script:SmProj; $st.Busy = $Busy
    $u = $st.Ui
    foreach ($n in 'BtnListConnect', 'BtnListNew', 'BtnListReload') { $u[$n].IsEnabled = -not $Busy }
    Update-SmProjectButtons
}

function Update-SmProjectButtons {
    $st = $script:SmProj; $u = $st.Ui
    $conn = [bool]$st.List
    $free = $conn -and -not $st.Busy
    $sel = [bool](Get-SmProjSelectedId)
    $u.BtnListReload.IsEnabled = $conn -and -not $st.Busy
    $u.BtnProjNew.IsEnabled = $free; $u.BtnProjImport.IsEnabled = $free
    $u.BtnProjEdit.IsEnabled = $free -and $sel; $u.BtnProjDelete.IsEnabled = $free -and $sel
    $u.BtnProjActivate.IsEnabled = $conn -and $sel; $u.BtnProjExport.IsEnabled = $conn -and $sel
    $u.BtnProjSave.IsEnabled = $free
}

function Update-SmProjectPage {
    <# Zeichnet die Projektliste (mit Suche) neu und behaelt die Auswahl. #>
    $st = $script:SmProj; $u = $st.Ui
    $keep = Get-SmProjSelectedId
    $u.LstProjects.Items.Clear()
    if ($st.List) {
        foreach ($p in (Find-SmProjects -List $st.List -Text $u.TxtSearch.Text)) {
            $row = New-Object System.Windows.Controls.StackPanel; $row.Margin = '14,8,14,8'
            $head = New-Object System.Windows.Controls.TextBlock
            $mark = if ($p['Id'] -eq $st.ActiveId) { [string][char]0x25CF + ' ' } else { '' }
            $head.Text = $mark + $p['Name']
            $head.FontWeight = 'SemiBold'
            $sub = New-Object System.Windows.Controls.TextBlock
            $sub.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'MutedText'); $sub.FontSize = 12
            $sub.Text = (@($p['Customer'], $p['Status'], ('{0} Server' -f @($p['Servers']).Count)) | Where-Object { $_ }) -join '  |  '
            [void]$row.Children.Add($head); [void]$row.Children.Add($sub)
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = $row; $item.Tag = $p['Id']
            [void]$u.LstProjects.Items.Add($item)
            if ($p['Id'] -eq $keep) { $item.IsSelected = $true }
        }
    }
    $u.TxtListEmpty.Visibility = if ($u.LstProjects.Items.Count -eq 0) { 'Visible' } else { 'Collapsed' }
    $u.TxtListEmpty.Text = if (-not $st.List) { 'Noch keine Projektliste verbunden.' } elseif ($u.TxtSearch.Text.Trim()) { 'Kein Projekt gefunden.' } else { 'Die Liste ist leer. Mit "Neues Projekt" anlegen.' }
    $active = if ($st.ActiveId) { Get-SmProjById $st.ActiveId } else { $null }
    $u.TxtActive.Text = if ($active) { 'Aktives Projekt: ' + $active['Name'] } else { 'Kein aktives Projekt gewaehlt.' }
    Update-SmProjectButtons
}

function Show-SmProjConflict([bool]$Show, [string]$Text = '') {
    $u = $script:SmProj.Ui
    $u.BoxConflict.Visibility = if ($Show) { 'Visible' } else { 'Collapsed' }
    $u.TxtConflict.Text = $Text
}

function Start-SmProjConnect {
    param([switch]$Reload)
    $st = $script:SmProj; $u = $st.Ui
    if ($st.Busy) { return }
    $link = $null
    if ($Reload -and $st.Link) { $link = $st.Link; $pw = $st.Password }
    else {
        try { $link = Test-SmShareLink $u.TxtListLink.Text } catch { $u.TxtListState.Text = 'Link ungueltig'; & $st.Log 'Projektliste: der Link ist kein gueltiger Freigabelink'; return }
        $pw = $u.PwdList.Password
        if (-not $pw) { $u.TxtListState.Text = 'Bitte das Kennwort eingeben'; return }
    }
    $st.Pending = @{ Link = $link; Pw = $pw }   # kein Closure (in einem Closure waere $script: nicht die Seite): Zustand im Seitenobjekt
    Set-SmProjBusy $true; $u.TxtListState.Text = 'Verbinde und entschluessele ...'; Show-SmProjConflict $false
    & $st.Log 'Projektliste: lade und entschluessele'
    [void](Start-SmJob -Modules $st.Modules -Params @{ Link = $link; Password = $pw } -Script {
            param($State, $P)
            $share = Connect-SmShare -Link $P.Link
            Read-SmProjectStore -Share $share -Password $P.Password
        } -OnDone {
            param($result, $err)
            $s = $script:SmProj; $ui2 = $s.Ui
            $link = $s.Pending.Link; $pw = $s.Pending.Pw; $s.Pending = $null
            Set-SmProjBusy $false
            if ($err) { $ui2.TxtListState.Text = 'Fehlgeschlagen'; & $s.Log ('Projektliste: ' + (Get-SmSafeMessage $err @($link, $pw))); return }
            $r = $result[-1]
            if (-not $r.Exists) {
                $ui2.TxtListState.Text = 'Dort liegt noch keine Projektliste'
                & $s.Log 'Projektliste: keine Datei im Ordner. "Neue Liste anlegen" benutzen.'
                return
            }
            $s.Link = $link; $s.Password = $pw; $s.ETag = $r.ETag; $s.List = $r.List
            if ($ui2.ChkRemember.IsChecked) { try { Save-SmRemembered -Link $link -Password $pw; $ui2.BtnForget.Visibility = 'Visible' } catch { & $s.Log 'Das Kennwort konnte nicht gemerkt werden.' } }
            $ui2.TxtListState.Text = 'Verbunden: {0} Projekte' -f @($r.List['Projects']).Count
            & $s.Log ('Projektliste geladen ({0} Projekte)' -f @($r.List['Projects']).Count)
            if ($s.ActiveId -and -not (Get-SmProjById $s.ActiveId)) { $s.ActiveId = $null; if ($s.OnActive) { & $s.OnActive $null } }
            elseif ($s.ActiveId -and $s.OnActive) { & $s.OnActive (Get-SmProjById $s.ActiveId) }
            Update-SmProjectPage
        })
}

function Start-SmProjCreateList {
    $st = $script:SmProj; $u = $st.Ui
    if ($st.Busy) { return }
    try { $link = Test-SmShareLink $u.TxtListLink.Text } catch { $u.TxtListState.Text = 'Link ungueltig'; & $st.Log 'Projektliste: der Link ist kein gueltiger Freigabelink'; return }
    $pw = Show-SmPasswordDialog -Title 'Neue Projektliste' -Text 'Dieses Kennwort verschluesselt die Liste. Es wird nirgends gespeichert; ohne Kennwort sind die Projekte nicht lesbar. Bitte gut aufbewahren.' -Confirm -Owner $script:SmWin.Window
    if (-not $pw) { return }
    $st.Pending = @{ Link = $link; Pw = $pw }
    Set-SmProjBusy $true; $u.TxtListState.Text = 'Lege die Liste an ...'; Show-SmProjConflict $false
    & $st.Log 'Projektliste: lege eine neue Liste an'
    [void](Start-SmJob -Modules $st.Modules -Params @{ Link = $link; Password = $pw; List = (New-SmProjectList) } -Script {
            param($State, $P)
            $share = Connect-SmShare -Link $P.Link
            $save = Save-SmProjectStore -Share $share -Password $P.Password -List $P.List -ETag $null
            [pscustomobject]@{ Save = $save; List = $P.List }
        } -OnDone {
            param($result, $err)
            $s = $script:SmProj; $ui2 = $s.Ui
            $link = $s.Pending.Link; $pw = $s.Pending.Pw; $s.Pending = $null
            Set-SmProjBusy $false
            if ($err) { $ui2.TxtListState.Text = 'Fehlgeschlagen'; & $s.Log ('Projektliste: ' + (Get-SmSafeMessage $err @($link, $pw))); return }
            $r = $result[-1]
            if ($r.Save.Conflict) { $ui2.TxtListState.Text = 'Dort gibt es schon eine Projektliste'; & $s.Log 'Projektliste: im Ordner liegt schon eine Liste. Mit "Verbinden" und ihrem Kennwort oeffnen.'; return }
            $s.Link = $link; $s.Password = $pw; $s.ETag = $r.Save.ETag; $s.List = $r.List
            $ui2.PwdList.Password = $pw
            if ($ui2.ChkRemember.IsChecked) { try { Save-SmRemembered -Link $link -Password $pw; $ui2.BtnForget.Visibility = 'Visible' } catch { & $s.Log 'Das Kennwort konnte nicht gemerkt werden.' } }
            $ui2.TxtListState.Text = 'Neue Liste angelegt und verbunden'
            & $s.Log 'Projektliste: neue verschluesselte Liste angelegt'
            Update-SmProjectPage
        })
}

function Invoke-SmProjSave {
    <#
    .SYNOPSIS
        Wendet eine Aenderung auf den aktuellen Stand der Liste an und speichert mit ETag.
        Bei einem Konflikt wird nichts ueberschrieben: Hinweis mit "Neu laden".
        Mutate($liste, $Arg) liefert die neue Liste; OnSaved laeuft nach dem Speichern.
    #>
    param([Parameter(Mandatory)][scriptblock]$Mutate, $Arg, [scriptblock]$OnSaved, [string]$Done = 'Gespeichert')
    $st = $script:SmProj; $u = $st.Ui
    if ($st.Busy -or -not $st.List) { return }
    try { $new = & $Mutate (Copy-SmData $st.List) $Arg } catch { $u.TxtEditorError.Text = Get-SmSafeMessage $_.Exception.Message; & $st.Log ('Aenderung abgelehnt: ' + (Get-SmSafeMessage $_.Exception.Message)); return }
    Set-SmProjBusy $true; $u.TxtListState.Text = 'Speichere ...'
    $st.Pending = @{ Done = $Done; OnSaved = $OnSaved }
    [void](Start-SmJob -Modules $st.Modules -Params @{ Link = $st.Link; Password = $st.Password; List = $new; ETag = $st.ETag } -Script {
            param($State, $P)
            $share = Connect-SmShare -Link $P.Link
            $save = Save-SmProjectStore -Share $share -Password $P.Password -List $P.List -ETag $P.ETag
            [pscustomobject]@{ Save = $save; List = $P.List }
        } -OnDone {
            param($result, $err)
            $s = $script:SmProj; $ui2 = $s.Ui
            $captured = $s.Pending; $s.Pending = $null
            Set-SmProjBusy $false
            if ($err) { $ui2.TxtListState.Text = 'Speichern fehlgeschlagen'; & $s.Log ('Projektliste: ' + (Get-SmSafeMessage $err @($s.Link, $s.Password))); return }
            $r = $result[-1]
            if ($r.Save.Conflict) {
                $ui2.TxtListState.Text = 'Konflikt, nichts gespeichert'
                Show-SmProjConflict $true 'Jemand anderes hat die Projektliste inzwischen gespeichert. Deine Aenderung wurde NICHT gespeichert, damit nichts ueberschrieben wird. Neu laden und die Aenderung dann noch einmal machen.'
                & $s.Log 'Projektliste: Konflikt (ETag), nicht gespeichert'
                return
            }
            $s.ETag = $r.Save.ETag; $s.List = $r.List
            $ui2.TxtListState.Text = '{0} ({1} Projekte)' -f $captured.Done, @($r.List['Projects']).Count
            & $s.Log ('Projektliste: ' + $captured.Done)
            if ($captured.OnSaved) { & $captured.OnSaved }
            if ($s.ActiveId -and $s.OnActive) { $a = Get-SmProjById $s.ActiveId; if (-not $a) { $s.ActiveId = $null }; & $s.OnActive $a }
            Update-SmProjectPage
        })
}

function Open-SmProjEditor {
    param([switch]$Existing)
    $st = $script:SmProj; $u = $st.Ui
    $p = $null
    if ($Existing) { $id = Get-SmProjSelectedId; if (-not $id) { return }; $p = Get-SmProjById $id; if (-not $p) { return } }
    $st.Editing = if ($p) { Copy-SmData $p } else { New-SmProject -Name 'Neues Projekt' }
    $u.TxtEditorTitle.Text = if ($p) { 'Projekt bearbeiten' } else { 'Neues Projekt' }
    $u.TxtName.Text = if ($p) { $p['Name'] } else { '' }
    $u.TxtCustomer.Text = [string]$st.Editing['Customer']; $u.TxtShare.Text = [string]$st.Editing['ShareLink']; $u.TxtNotes.Text = [string]$st.Editing['Notes']
    $u.CmbStatus.SelectedItem = $st.Editing['Status']
    $st.EditServers = @($st.Editing['Servers'])
    Update-SmProjEditorServers
    $u.TxtEditorError.Text = ''; $u.BoxEditor.Visibility = 'Visible'
    $u.TxtName.Focus() | Out-Null
}

function Update-SmProjEditorServers {
    $st = $script:SmProj; $u = $st.Ui
    $u.LstServers.Items.Clear()
    foreach ($s in $st.EditServers) { [void]$u.LstServers.Items.Add(('{0}   {1}   {2}' -f $s['Name'], $s['Role'], $s['Generation'])) }
}

function Add-SmProjEditorServer {
    $st = $script:SmProj; $u = $st.Ui
    $n = $u.TxtSrvName.Text.Trim()
    try {
        $entry = [ordered]@{ Name = $n; Role = [string]$u.CmbSrvRole.SelectedItem; Generation = [string]$u.CmbSrvGen.SelectedItem }
        $null = ConvertTo-SmProjectRecord ([ordered]@{ Name = 'x'; Servers = @($entry) })
    }
    catch { $u.TxtEditorError.Text = Get-SmSafeMessage $_.Exception.Message; return }
    $st.EditServers = @($st.EditServers) + @($entry); $u.TxtSrvName.Text = ''; $u.TxtEditorError.Text = ''
    Update-SmProjEditorServers
}

function Remove-SmProjEditorServer {
    $st = $script:SmProj; $u = $st.Ui
    $i = $u.LstServers.SelectedIndex
    if ($i -lt 0) { return }
    $st.EditServers = @(for ($k = 0; $k -lt @($st.EditServers).Count; $k++) { if ($k -ne $i) { $st.EditServers[$k] } })
    Update-SmProjEditorServers
}

function Save-SmProjEditor {
    $st = $script:SmProj; $u = $st.Ui
    if (-not $st.Editing) { return }
    try {
        $rec = $st.Editing
        $rec['Name'] = $u.TxtName.Text; $rec['Customer'] = $u.TxtCustomer.Text; $rec['ShareLink'] = $u.TxtShare.Text; $rec['Notes'] = $u.TxtNotes.Text
        $rec['Status'] = [string]$u.CmbStatus.SelectedItem; $rec['Servers'] = @($st.EditServers)
        $rec = ConvertTo-SmProjectRecord $rec
    }
    catch { $u.TxtEditorError.Text = Get-SmSafeMessage $_.Exception.Message; return }
    $u.TxtEditorError.Text = ''
    $name = $rec['Name']
    Invoke-SmProjSave -Done 'Projekt gespeichert' -Arg $rec -Mutate { param($l, $a) Set-SmProjectInList -List $l -Project $a } -OnSaved {
        $script:SmProj.Editing = $null; $script:SmProj.Ui.BoxEditor.Visibility = 'Collapsed'
    }
}

function Remove-SmProjSelected {
    $st = $script:SmProj
    $id = Get-SmProjSelectedId; if (-not $id) { return }
    $p = Get-SmProjById $id; if (-not $p) { return }
    $ask = [System.Windows.MessageBox]::Show(('Projekt "{0}" wirklich loeschen? Das gilt fuer alle, die diese Projektliste nutzen.' -f $p['Name']), 'Projekt loeschen', 'YesNo', 'Warning', 'No')
    if ($ask -ne 'Yes') { return }
    if ($st.ActiveId -eq $id) { $st.ActiveId = $null }
    Invoke-SmProjSave -Done 'Projekt geloescht' -Arg $id -Mutate { param($l, $a) Remove-SmProjectFromList -List $l -Id $a }
}

function Set-SmProjActive {
    $st = $script:SmProj
    $id = Get-SmProjSelectedId; if (-not $id) { return }
    $p = Get-SmProjById $id; if (-not $p) { return }
    $st.ActiveId = $id
    & $st.Log ('Aktives Projekt: ' + $p['Name'])
    if ($st.OnActive) { & $st.OnActive $p }
    Update-SmProjectPage
}

function Export-SmProjSelected {
    $st = $script:SmProj
    $id = Get-SmProjSelectedId; if (-not $id) { return }
    $p = Get-SmProjById $id; if (-not $p) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'Server-Migration Projekt (*.smproj)|*.smproj'; $dlg.DefaultExt = '.smproj'
    $dlg.FileName = (($p['Name'] -replace '[^\w\-]+', '_').Trim('_')) + '.smproj'
    if (-not $dlg.ShowDialog($script:SmWin.Window)) { return }
    $pw = Show-SmPasswordDialog -Title 'Projekt exportieren' -Text 'Eigenes Kennwort fuer diese Datei. Es muss dem Empfaenger getrennt mitgeteilt werden.' -Confirm -Owner $script:SmWin.Window
    if (-not $pw) { return }
    try {
        $bytes = Export-SmProject -Project $p -Password $pw
        [IO.File]::WriteAllBytes($dlg.FileName, $bytes)
        & $st.Log ('Projekt exportiert: ' + $p['Name']); Show-SmToast 'Projekt exportiert.'
    }
    catch { & $st.Log ('Export fehlgeschlagen: ' + (Get-SmSafeMessage $_.Exception.Message @($pw))) }
}

function Import-SmProjFromFile {
    $st = $script:SmProj
    if (-not $st.List -or $st.Busy) { return }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Server-Migration Projekt (*.smproj)|*.smproj'
    if (-not $dlg.ShowDialog($script:SmWin.Window)) { return }
    if ((Get-Item -LiteralPath $dlg.FileName).Length -gt $script:SmProjMaxBytes) { & $st.Log 'Import: die Datei ist zu gross.'; return }
    $pw = Show-SmPasswordDialog -Title 'Projekt importieren' -Text 'Kennwort, mit dem die Datei exportiert wurde.' -Owner $script:SmWin.Window
    if (-not $pw) { return }
    try { $p = Import-SmProject -Bytes ([IO.File]::ReadAllBytes($dlg.FileName)) -Password $pw }
    catch { & $st.Log ('Import fehlgeschlagen: ' + (Get-SmSafeMessage $_.Exception.Message @($pw))); [System.Windows.MessageBox]::Show((Get-SmSafeMessage $_.Exception.Message @($pw)), 'Import', 'OK', 'Warning') | Out-Null; return }
    if (Get-SmProjById $p['Id']) {
        $ask = [System.Windows.MessageBox]::Show(('Das Projekt "{0}" gibt es in der Liste schon. Ja = ersetzen, Nein = als Kopie anlegen.' -f $p['Name']), 'Import', 'YesNoCancel', 'Question', 'Cancel')
        if ($ask -eq 'Cancel') { return }
        if ($ask -eq 'No') { $p['Id'] = [guid]::NewGuid().ToString(); $p['Name'] = ($p['Name'] + ' (Kopie)') }
    }
    Invoke-SmProjSave -Done 'Projekt importiert' -Arg $p -Mutate { param($l, $a) Set-SmProjectInList -List $l -Project $a -KeepModified }
}
