<#
.SYNOPSIS
    DNS-Debug-Log lesen und als CLIXML speichern (duenner Aufsatz auf den neuen Parser in Modules\SmDns.ps1).
.DESCRIPTION
    Der Parser ist ersetzt (Issue #3, Fehler aus #8): Das Datumsformat ist nicht mehr fest dd.MM.yyyy (es wird automatisch erkannt oder
    per -DateFormat angegeben), der Tippfehler bei Query/Respond ist behoben, Namen mit mehrstelligen Laengen (12)... werden richtig
    gelesen, und es gibt keine Array-Verkettung und keine Ausgabe je Zeile. Das Ergebnis hat weiter die Eigenschaften des alten Skripts
    (LogTime, TreadID, Context, ... QuestionName) und liegt wie bisher neben der Datei als <Datei>Parsed.XML.
    Die Auswertung (Clients, DNS-Server, Fehler, Zonen, CSV) macht das Berater-Tool (Start-ServerMigration.ps1, Seite DNS).
.PARAMETER Path
    Eine oder mehrere Log-Dateien. Ohne Angabe oeffnet sich ein Auswahldialog (wie bisher).
.PARAMETER DateFormat
    Datumsmuster des Servers, z. B. dd.MM.yyyy oder M/d/yyyy. Ohne Angabe wird das Format erkannt.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$DateFormat
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Modules\SmDns.ps1')

if (-not $Path) {
    Add-Type -AssemblyName System.Windows.Forms
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.InitialDirectory = 'C:\Temp'
    $dlg.Filter = 'All files (*.*)| *.*'
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $Path = @($dlg.FileNames)
}
$order = ConvertTo-SmDnsDateOrder $DateFormat
if ($DateFormat -and -not $order) { throw "Das Datumsformat '$DateFormat' ist nicht lesbar (erwartet z. B. dd.MM.yyyy, M/d/yyyy oder yyyy-MM-dd)." }

foreach ($file in $Path) {
    Write-Host "Lese $file"
    $log = New-SmDnsLog
    Add-SmDnsLogFile -Log $log -Path $file -Order $order
    $rows = @(Get-SmDnsCompatRows -Log $log)
    $out = $file + 'Parsed.XML'
    $rows | Export-Clixml -Path $out
    Write-Host ('Fertig: {0} Pakete, Datum {1}, gespeichert in {2}' -f $rows.Count, $log.DetectedOrder, $out)
}
