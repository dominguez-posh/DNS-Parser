#requires -Version 5.1
<#
.SYNOPSIS
    Prueft Symbole und Schriften in allen XAML- und PowerShell-Dateien (Windows Server 2016 hat weder Segoe Fluent Icons noch Emojis).
    - keine Zeichen ausserhalb der BMP (Surrogatpaare) und keine Emojis
    - Zeichen U+E000 bis U+F8FF (Symbolschrift) nur aus der Liste, die es in Segoe MDL2 Assets gibt, und nur mit der Ressource IconFont
    - Button-Tags sind leer oder genau ein Symbolzeichen (das Theme zeigt den Tag als Symbol)
    - Schriftlisten haben einen Fallback (Segoe UI, Consolas, Segoe MDL2 Assets)
#>
param([string]$Repo, [string]$Work)
$ErrorActionPreference = 'Stop'
if (-not $Repo) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$fails = 0
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name $Detail" -ForegroundColor Red; $script:fails++ } }

# Codepunkte, die in Segoe Fluent Icons UND Segoe MDL2 Assets dasselbe Symbol sind (Erweiterung nur nach Pruefung in beiden Schriften)
$allowed = 0xE70D, 0xE70E, 0xE706, 0xE708, 0xE721, 0xE72C, 0xE73E, 0xE749, 0xE753, 0xE774, 0xE77B, 0xE783, 0xE78C, 0xE7BA, 0xE839, 0xE898, 0xE8BB, 0xE8C8, 0xE8E5, 0xE8F1, 0xE921, 0xE922, 0xE923, 0xE946, 0xE977, 0xE770

$files = @(Get-ChildItem -LiteralPath $Repo -Recurse -File -Include *.xaml, *.ps1, *.psm1 | Where-Object { $_.FullName -notmatch '[\\/](tests|\.git)[\\/]' })
$bad = @{ Surrogate = @(); Emoji = @(); Pua = @(); Tag = @(); Font = @() }
foreach ($f in $files) {
    $t = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8)
    $n = $f.FullName.Substring($Repo.Length + 1)
    foreach ($c in $t.ToCharArray()) {
        $v = [int]$c
        if ($v -ge 0xD800 -and $v -le 0xDFFF) { $bad.Surrogate += $n; break }
    }
    foreach ($c in $t.ToCharArray()) {
        $v = [int]$c
        if (($v -ge 0x2600 -and $v -le 0x27BF) -or ($v -ge 0x2B00 -and $v -le 0x2BFF) -or $v -eq 0xFE0F -or $v -eq 0x200D) { $bad.Emoji += ('{0} U+{1:X4}' -f $n, $v); break }
        # SmUi.ps1 enthaelt den Bereich nur als Zahl in der Pruefung der Prüfsumme/Texte
        if ($v -ge 0xE000 -and $v -le 0xF8FF) { $bad.Pua += ('{0} Zeichen U+{1:X4} im Text (nur als Entity oder [char] mit IconFont)' -f $n, $v) }
    }
    # Entities (&#xE...;) und Zahlen (0xE...) im Symbolbereich
    foreach ($m in [regex]::Matches($t, '&#[xX]([0-9A-Fa-f]{4,6});|(?<![0-9A-Za-z])0x([Ee][0-9A-Fa-f]{3}|[Ff][0-8][0-9A-Fa-f]{2})(?![0-9A-Fa-f])')) {
        $hex = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        $v = [Convert]::ToInt32($hex, 16)
        if ($v -gt 0xFFFF) { $bad.Surrogate += "$n U+$hex"; continue }
        if ($v -ge 0xE000 -and $v -le 0xF8FF -and $allowed -notcontains $v) { $bad.Pua += ('{0} U+{1:X4} nicht auf der Liste' -f $n, $v) }
    }
    # Symbol im XAML nur mit IconFont (Ressource oder Stil) oder als Tag eines Knopfs (Theme setzt IconFont)
    foreach ($m in [regex]::Matches($t, '<(TextBlock|Button|Run)\b[^>]*(Text|Content)="&#[xX][Ee][0-9A-Fa-f]{3};"[^>]*>')) {
        $tag = $m.Value
        if ($tag -notmatch 'IconFont|Style="\{\w+Resource (NavGlyph|BandGlyph|IconButton|ChipIconButton|CaptionButton|CloseCaptionButton)') { $bad.Pua += ("$n Symbol ohne IconFont: " + $tag.Substring(0, [Math]::Min(80, $tag.Length))) }
    }
    # Button-Tags im XAML: leer oder ein Symbolzeichen
    foreach ($m in [regex]::Matches($t, '<Button\b[^>]*\sTag="([^"]*)"')) {
        if ($m.Groups[1].Value -notmatch '^(&#[xX][Ee][0-9A-Fa-f]{3};)?$') { $bad.Tag += ("$n Tag=" + $m.Groups[1].Value) }
    }
    # Button-Tags im Code: Zuweisung muss ein Symbolzeichen sein
    foreach ($m in [regex]::Matches($t, '\$[\w.]*\bBtn\w+\.Tag\s*=\s*([^;\r\n]+)')) {
        if ($m.Groups[1].Value.Trim() -notmatch '^(\$null|\[string\]\[char\]0x[Ee][0-9A-Fa-f]{3})$') { $bad.Tag += "$n $($m.Value)" }
    }
    # Schriftlisten
    foreach ($m in [regex]::Matches($t, 'FontFamily(?:="|">|" Value=")([^"<]*)')) {
        $v = $m.Groups[1].Value
        if ($v -match '^\{') { continue }
        if ($v -match 'Segoe Fluent Icons' -and $v -notmatch 'Segoe MDL2 Assets') { $bad.Font += "$n $v" }
        if ($v -match 'Segoe UI Variable' -and $v -notmatch 'Segoe UI\s*$') { $bad.Font += "$n $v" }
        if ($v -match 'Cascadia' -and $v -notmatch 'Consolas') { $bad.Font += "$n $v" }
        if ($n -ne 'UI\Theme.xaml' -and $v -match 'Segoe Fluent Icons') { $bad.Font += "$n Symbolschrift nur ueber IconFont: $v" }
    }
}
$theme = [IO.File]::ReadAllText((Join-Path $Repo 'UI\Theme.xaml'), [Text.Encoding]::UTF8)
Check 'Theme: IconFont = Segoe Fluent Icons mit Fallback Segoe MDL2 Assets' ($theme -match '<FontFamily x:Key="IconFont">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>')
Check 'Theme: MonoFont = Cascadia Mono mit Fallback Consolas' ($theme -match '<FontFamily x:Key="MonoFont">Cascadia Mono, Consolas</FontFamily>')
Check "Keine Surrogatpaare/Zeichen ausserhalb der BMP ($($files.Count) Dateien)" ($bad.Surrogate.Count -eq 0) ($bad.Surrogate -join '; ')
Check 'Keine Emojis' ($bad.Emoji.Count -eq 0) ($bad.Emoji -join '; ')
Check 'Symbolbereich U+E000..F8FF nur aus der Liste und mit IconFont' ($bad.Pua.Count -eq 0) ($bad.Pua -join '; ')
Check 'Button-Tag ist leer oder ein Symbolzeichen' ($bad.Tag.Count -eq 0) ($bad.Tag -join '; ')
Check 'Schriftlisten haben Fallback (Segoe UI, Consolas, Segoe MDL2 Assets)' ($bad.Font.Count -eq 0) ($bad.Font -join '; ')
Check 'AD-Server: adprep-Phase nicht aus dem Tag' ((Get-Content -LiteralPath (Join-Path $Repo 'server\SmAdServer.ps1') -Raw) -notmatch '\$sender\.Tag')
# Liste gegen die installierte Schrift (Windows 10/11 und Server 2016 haben Segoe MDL2 Assets)
Add-Type -AssemblyName PresentationCore
$mdl = [System.Windows.Media.Fonts]::SystemTypefaces | Where-Object { $_.FontFamily.Source -eq 'Segoe MDL2 Assets' } | Select-Object -First 1
if ($mdl) {
    $g = $null; [void]$mdl.TryGetGlyphTypeface([ref]$g)
    $missing = @($allowed | Where-Object { -not $g.CharacterToGlyphMap.ContainsKey($_) } | ForEach-Object { '{0:X4}' -f $_ })
    Check 'Alle erlaubten Codepunkte existieren in Segoe MDL2 Assets' ($missing.Count -eq 0) ($missing -join ',')
}
else { Write-Host 'SKIP Segoe MDL2 Assets nicht installiert' -ForegroundColor Yellow }
Write-Host ''
Write-Host "Symbole: $fails Fehler"
if ($MyInvocation.InvocationName -eq '&') { return $fails }
exit $fails
