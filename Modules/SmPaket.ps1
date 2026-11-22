<#
.SYNOPSIS
    Server-Paket (ZIP), Pruefsumme und Einzeiler fuer das Server-Fenster.
.DESCRIPTION
    Wird per Dot-Source geladen (braucht Modules\SmTausch.ps1 fuer Publish-SmServerPackage).
    Das Berater-Tool baut das Paket aus dem Repo, legt es im Tauschordner ab und gibt den Einzeiler mit SHA256 aus.
    Der Einzeiler laedt das Paket aus dem Tauschordner, prueft die Pruefsumme und startet erst dann das Server-Fenster.
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmPackageName = 'SM-Server-Paket.zip'
$script:SmPackageRoot = 'ServerMigration'
# Dateien, die das Server-Fenster braucht (relativ zur Wurzel des Repos)
$script:SmServerFiles = @(
    'server/Start-SmServer.ps1', 'Modules/SmTheme.ps1', 'Modules/SmShell.ps1', 'Modules/SmTausch.ps1',
    'UI/Theme.xaml', 'UI/Shell.xaml'
)

function Test-SmShareLink {
    <#
    .SYNOPSIS
        Prueft einen Freigabelink des Tauschordners. Liefert den bereinigten Link oder wirft einen Fehler.
        Anfuehrungszeichen und Leerzeichen sind nicht erlaubt, weil der Link im Einzeiler in einfachen Anfuehrungszeichen steht.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Link, [switch]$AnyHost)
    $l = $Link.Trim().Trim('<', '>').Trim()
    $hostPattern = if ($AnyHost) { '(?:https?://[A-Za-z0-9.:-]+)' } else { '(?:https://[A-Za-z0-9-]+\.sharepoint\.(?:com|de|us|cn))' }   # AnyHost nur fuer Tests gegen einen nachgebauten Server
    if ($l -notmatch ('^' + $hostPattern + "/[^\s'""\u2018\u2019\u201a\u201b]+$")) {
        throw 'Das ist kein SharePoint-/OneDrive-Freigabelink (https://<firma>.sharepoint.com/... bzw. https://<firma>-my.sharepoint.com/...), oder er enthaelt Leerzeichen bzw. Anfuehrungszeichen.'
    }
    if ($l -match '/:[uwxpbtvi]:/') {
        throw 'Das ist ein Link auf eine Datei. Bitte den ORDNER teilen (Jeder mit dem Link, Bearbeiten) und dessen Link verwenden.'
    }
    $l
}

function Get-SmSha256 {
    <# SHA256 einer Datei, grossgeschrieben (wie Get-FileHash). Auch fuer Bytefolgen. #>
    param([Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory, ParameterSetName = 'Bytes')][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $fs = [IO.File]::OpenRead($Path)
            try { $h = $sha.ComputeHash($fs) } finally { $fs.Dispose() }
        }
        else { $h = $sha.ComputeHash($Bytes) }
    }
    finally { $sha.Dispose() }
    -join ($h | ForEach-Object { $_.ToString('X2') })
}

function New-SmServerPackage {
    <# Baut das Server-Paket (ZIP mit Ordner ServerMigration/) aus dem Repo. Liefert Pfad und SHA256. #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$OutDir)
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $target = Join-Path $OutDir $script:SmPackageName
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($target, 'Create')
    try {
        foreach ($rel in $script:SmServerFiles) {
            $src = Join-Path $RepoRoot ($rel -replace '/', '\')
            if (-not (Test-Path -LiteralPath $src)) { throw "Paket unvollstaendig, Datei fehlt: $rel" }
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $src, ($script:SmPackageRoot + '/' + $rel), 'Optimal')
        }
    }
    finally { $zip.Dispose() }
    [pscustomobject]@{ Path = $target; Name = $script:SmPackageName; Sha256 = (Get-SmSha256 -Path $target); Length = (Get-Item -LiteralPath $target).Length }
}

function New-SmOneLiner {
    <#
    .SYNOPSIS
        Einzeiler fuer den Server: laedt das Paket aus dem Tauschordner, prueft SHA256 und startet das Server-Fenster.
        Stimmt die Pruefsumme nicht, wird nichts entpackt und nichts ausgefuehrt. Die Skriptfreigabe gilt nur fuer diesen Prozess.
    .PARAMETER AnyHost
        Nur fuer Tests: erlaubt einen nachgebauten Server statt *.sharepoint.com (Anfuehrungszeichen und Leerzeichen bleiben verboten).
    .PARAMETER ServerArguments
        Nur fuer Tests: haengt Argumente an den Start des Server-Fensters an (z. B. -ParseOnly).
    #>
    param([Parameter(Mandatory)][string]$Link, [Parameter(Mandatory)][string]$Sha256, [string]$ServerArguments = '', [switch]$AnyHost)
    $l = Test-SmShareLink $Link -AnyHost:$AnyHost
    if ($Sha256 -notmatch '^[0-9A-F]{64}$') { throw 'Die Pruefsumme muss 64 Hexzeichen in Grossbuchstaben sein.' }
    $extra = if ($ServerArguments) { ' ' + $ServerArguments } else { '' }
    $t = @(
        '& {[Net.ServicePointManager]::SecurityProtocol=3072;$ProgressPreference=''SilentlyContinue'';'
        '$L=''__LINK__'';$H=''__SHA__'';'
        '$r=iwr $L -UseBasicParsing -SessionVariable S;$u=$r.BaseResponse.ResponseUri;if(!$u){$u=$r.BaseResponse.RequestMessage.RequestUri};'
        'if(($u.AbsoluteUri+'' ''+$r.Content)-notmatch''[?&](?:amp;)?(?:id|RootFolder)=((?:%2F|/)[^&"''''<>\s]+)''){throw "Kein Ordnerlink: $u"};'
        '$f=[uri]::UnescapeDataString($Matches[1]).TrimEnd(''/'');$p=$f.Trim(''/'')-split''/'';$w=([uri]$u).GetLeftPart(''Authority'');'
        'if($p[0]-match''^(personal|sites|teams)$''){$w+=''/''+$p[0]+''/''+$p[1]};'
        '$t="$env:TEMP\ServerMigration";$z="$t.zip";'
        'iwr ("$w/_api/web/GetFileByServerRelativeUrl(@f)/`$value?@f=''"+[uri]::EscapeDataString(($f+''/__PKG__'').Replace("''","''''"))+"''") -WebSession $S -OutFile $z -UseBasicParsing;'
        'if((Get-FileHash $z -Algorithm SHA256).Hash-ne$H){throw ''Pruefsumme falsch: Das Paket im Tauschordner ist nicht das erwartete. Nichts ausgefuehrt.''};'
        'Remove-Item $t -Recurse -Force -EA 0;Expand-Archive $z $t -Force;Set-ExecutionPolicy Bypass -Scope Process -Force -EA 0;'
        '& "$t\ServerMigration\server\Start-SmServer.ps1" -ShareLink $L__EXTRA__}'
    ) -join ''
    $t.Replace('__LINK__', $l).Replace('__SHA__', $Sha256).Replace('__PKG__', $script:SmPackageName).Replace('__EXTRA__', $extra)
}

function Publish-SmServerPackage {
    <#
    .SYNOPSIS
        Baut das Server-Paket, legt es im Tauschordner ab (grosse Dateien in Teilen) und erzeugt den Einzeiler.
        Liefert Package (Pfad, Sha256), Remote (Datei im Tauschordner) und OneLiner.
    #>
    param([Parameter(Mandatory)]$Share, [Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$OutDir, [scriptblock]$Progress, [switch]$AnyHost)
    $pkg = New-SmServerPackage -RepoRoot $RepoRoot -OutDir $OutDir
    $remote = Send-SmShareFile -Share $Share -Path $pkg.Path -Progress $Progress
    $line = New-SmOneLiner -Link $Share.Link -Sha256 $pkg.Sha256 -AnyHost:$AnyHost
    [IO.File]::WriteAllText((Join-Path $OutDir 'Einzeiler.txt'), $line + "`r`n", [Text.Encoding]::ASCII)
    [pscustomobject]@{ Package = $pkg; Remote = $remote; OneLiner = $line }
}
