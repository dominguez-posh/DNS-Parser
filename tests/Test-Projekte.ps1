#requires -Version 5.1
<#
.SYNOPSIS
    Checks fuer Phase 2 (Projektliste): Verschluesselung (Rundlauf, Format, falsches Kennwort, manipulierte Datei),
    Datenmodell und Pruefung, Suche, Export und Import, Kennwort merken (DPAPI), die Seite "Projekte" (-ParseOnly)
    und die Ablage ueber einen Freigabelink mit ETag gegen einen nachgebauten SharePoint auf localhost
    (Neuanlage, Lesen, Speichern mit If-Match, Konflikt, Ablageort ohne If-Match-Auswertung).
    Wird von tests\Test-ServerMigration.ps1 aufgerufen und liefert die Zahl der Fehler zurueck. Allein:
    powershell.exe -NoProfile -STA -File tests\Test-Projekte.ps1
    Beispieldaten nur mit contoso. Keine echten Tenants, keine Links ins Netz.
#>
[CmdletBinding()]
param([string]$Repo, [string]$Work)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -eq 5) { $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -notmatch '(?i)[\\/]PowerShell[\\/](7|Modules)' }) -join ';'; Import-Module Microsoft.PowerShell.Utility -Force }
if (-not $Repo) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$ownWork = -not $Work
if (-not $Work) { $Work = Join-Path $env:TEMP ('sm-proj-' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Force $Work | Out-Null }
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "OK   $Name" -ForegroundColor Green } else { Write-Host "FAIL $Name" -ForegroundColor Red; $script:fails++ } }
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }
function ThrowsLike([scriptblock]$Block, [string]$Pattern) { try { & $Block | Out-Null; $false } catch { $_.Exception.Message -match $Pattern } }
function Json($o) { ConvertTo-Json -InputObject (ConvertTo-SmPlain $o) -Depth 32 -Compress }

. (Join-Path $Repo 'Modules\SmShell.ps1')
. (Join-Path $Repo 'Modules\SmTausch.ps1')
. (Join-Path $Repo 'Modules\SmPaket.ps1')
. (Join-Path $Repo 'Modules\SmProjekte.ps1')

$pw = 'Beispiel-Kennwort-123!'
$linkP = 'https://contoso-my.sharepoint.com/:f:/g/personal/max_contoso_com/EaBcD-12_xyz?e=AbC123'
$srv = @([ordered]@{ Name = 'dc01.contoso.local'; Role = 'DC'; Generation = 'alt' }, [ordered]@{ Name = 'dc02.contoso.local'; Role = 'DNS'; Generation = 'neu' })
$p1 = New-SmProject -Name 'Contoso Migration' -Customer 'Contoso GmbH' -Notes ("Zeile 1`r`nZeile 2 mit Umlauten: " + [char]0xE4 + [char]0xF6 + [char]0xFC) -ShareLink $linkP -Servers $srv -Status 'Laufend'

# ---------------------------------------------------------------- 1. Verschluesselung
$list = New-SmProjectList
$list = Set-SmProjectInList -List $list -Project $p1
$enc = Protect-SmProjectData -Data $list -Password $pw
Check 'Datei: Kennung SMPJ und Formatversion 1' ($enc[0] -eq 0x53 -and $enc[1] -eq 0x4D -and $enc[2] -eq 0x50 -and $enc[3] -eq 0x4A -and $enc[4] -eq 1)
$itb = [byte[]]$enc[5..8]; [Array]::Reverse($itb)
Check 'Datei: PBKDF2-Iterationen im Kopf, mindestens 200000' ([BitConverter]::ToInt32($itb, 0) -ge 200000)
Check 'Datei: Laenge = Kopf 41 + Vielfaches von 16 + HMAC 32' ((($enc.Length - 41 - 32) % 16) -eq 0 -and ($enc.Length - 73) -ge 16)
$text = [Text.Encoding]::UTF8.GetString($enc) + [Text.Encoding]::ASCII.GetString($enc)
Check 'Datei ohne Kennwort nicht lesbar: kein Klartext (Name, Kunde, Server, Link, Kennwort)' (($text -notmatch 'Contoso') -and ($text -notmatch 'dc01') -and ($text -notmatch 'sharepoint') -and ($text -notmatch [regex]::Escape($pw)))
$back = Unprotect-SmProjectData -Bytes $enc -Password $pw
Check 'Rundlauf: entschluesselt ergibt denselben Inhalt' ((Json $back) -eq (Json $list))
Check 'Rundlauf: Umlaute und Zeilenumbrueche in den Notizen bleiben' ($back['Projects'][0]['Notes'] -eq $p1['Notes'])
$enc2 = Protect-SmProjectData -Data $list -Password $pw
$salt1 = [Convert]::ToBase64String([byte[]]$enc[9..24]); $salt2 = [Convert]::ToBase64String([byte[]]$enc2[9..24])
$iv1 = [Convert]::ToBase64String([byte[]]$enc[25..40]); $iv2 = [Convert]::ToBase64String([byte[]]$enc2[25..40])
Check 'Salt und IV sind je Datei zufaellig (zwei Dateien gleichen Inhalts unterscheiden sich)' ($salt1 -ne $salt2 -and $iv1 -ne $iv2 -and [Convert]::ToBase64String($enc) -ne [Convert]::ToBase64String($enc2))

# Format unabhaengig nachgerechnet: PBKDF2-SHA256 (64 Byte), HMAC-SHA256 ueber alles vor dem Tag, AES-256-CBC
$salt = [byte[]]$enc[9..24]; $iv = [byte[]]$enc[25..40]; $iter = [BitConverter]::ToInt32($itb, 0)
$kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($pw, $salt, $iter, [Security.Cryptography.HashAlgorithmName]::SHA256)
$kEnc = $kdf.GetBytes(32); $kMac = $kdf.GetBytes(32); $kdf.Dispose()
$hm = New-Object Security.Cryptography.HMACSHA256 (, $kMac)
$tagCalc = $hm.ComputeHash([byte[]]$enc[0..($enc.Length - 33)]); $hm.Dispose()
Check 'Format: HMAC-SHA256 ueber Kopf und Chiffretext stimmt (encrypt-then-MAC)' ([Convert]::ToBase64String($tagCalc) -eq [Convert]::ToBase64String([byte[]]$enc[($enc.Length - 32)..($enc.Length - 1)]))
$aes = [Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $kEnc; $aes.IV = $iv
$cipher = [byte[]]$enc[41..($enc.Length - 33)]
$plainChk = [Text.Encoding]::UTF8.GetString($aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)); $aes.Dispose()
Check 'Format: AES-256-CBC mit dem PBKDF2-Schluessel entschluesselt zu JSON' ($plainChk.StartsWith('{') -and $plainChk -match 'Contoso Migration')

$e = $null; try { Unprotect-SmProjectData -Bytes $enc -Password 'falsches-Kennwort' | Out-Null } catch { $e = $_.Exception.Message }
Check 'Falsches Kennwort: klare Meldung, keine Daten' ($e -match 'Kennwort ist falsch' -and $e -notmatch 'falsches-Kennwort' -and $e -notmatch 'Contoso')
Check 'Falsches Kennwort ohne Unterschied in Gross-/Kleinschreibung abgelehnt' (ThrowsLike { Unprotect-SmProjectData -Bytes $enc -Password $pw.ToUpper() } 'Kennwort ist falsch')
function Flip([byte[]]$b, [int]$i) { $c = [byte[]]$b.Clone(); $c[$i] = $c[$i] -bxor 1; , $c }
Check 'Manipuliert: ein Bit im Chiffretext (HMAC)' (ThrowsLike { Unprotect-SmProjectData -Bytes (Flip $enc 60) -Password $pw } 'veraendert')
Check 'Manipuliert: ein Bit im Salt (HMAC)' (ThrowsLike { Unprotect-SmProjectData -Bytes (Flip $enc 12) -Password $pw } 'veraendert')
Check 'Manipuliert: ein Bit in der IV (HMAC)' (ThrowsLike { Unprotect-SmProjectData -Bytes (Flip $enc 30) -Password $pw } 'veraendert')
Check 'Manipuliert: ein Bit im HMAC selbst' (ThrowsLike { Unprotect-SmProjectData -Bytes (Flip $enc ($enc.Length - 1)) -Password $pw } 'veraendert')
Check 'Manipuliert: Iterationszahl auf einen kleinen Wert gesetzt (Herabstufung)' (ThrowsLike { $c = [byte[]]$enc.Clone(); $c[5] = 0; $c[6] = 0; $c[7] = 0; $c[8] = 10; Unprotect-SmProjectData -Bytes $c -Password $pw } 'Schluesselparameter')
Check 'Manipuliert: Datei gekuerzt' (Throws { Unprotect-SmProjectData -Bytes ([byte[]]$enc[0..($enc.Length - 17)]) -Password $pw })
Check 'Manipuliert: Datei angehaengt' (Throws { Unprotect-SmProjectData -Bytes ($enc + [byte[]](1, 2, 3)) -Password $pw })
Check 'Fremde Datei (falsche Kennung) abgelehnt' (ThrowsLike { Unprotect-SmProjectData -Bytes (New-Object byte[] 200) -Password $pw } 'keine Projektdatei')
Check 'Unbekannte Formatversion klar gemeldet' (ThrowsLike { $c = [byte[]]$enc.Clone(); $c[4] = 2; Unprotect-SmProjectData -Bytes $c -Password $pw } 'Format 2')
Check 'Verschluesseln: zu kurzes Kennwort abgelehnt' (Throws { Protect-SmProjectData -Data $list -Password 'kurz' })
Check 'Kennwort: Mindestlaenge 12 (11 Zeichen abgelehnt, 12 angenommen)' ($script:SmProjMinPassword -eq 12 -and (Throws { Protect-SmProjectData -Data $list -Password ('a' * 11) }) -and -not (Throws { Protect-SmProjectData -Data $list -Password ('a' * 12) }))
Check 'Kennwort-Dialog: Hinweis Passphrase empfohlen vorhanden' ((Get-SmPasswordDialogXaml) -match 'Passphrase empfohlen')
Check 'Seite Projekte: Hinweis auf aeltere Fassung (Rollback) vorhanden' ([IO.File]::ReadAllText((Join-Path $Repo 'UI\Projekte.xaml')) -match ('' + [char]0xE4 + 'ltere Fassung'))
Check 'Verschluesseln: zu wenige Iterationen abgelehnt' (Throws { Protect-SmProjectData -Data $list -Password $pw -Iterations 1000 })
Check 'Entschluesseln: zu grosse Datei abgelehnt' (ThrowsLike { Unprotect-SmProjectData -Bytes (New-Object byte[] (21MB)) -Password $pw } 'zu gross')

# ---------------------------------------------------------------- 2. Datenmodell und Pruefung
Check 'Projekt: Pflichtfelder und Standardwerte' ($p1['Id'] -match '^[0-9a-f-]{36}$' -and $p1['Status'] -eq 'Laufend' -and $p1['Created'] -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$' -and $p1['Servers'].Count -eq 2 -and $p1['Results'] -is [System.Collections.IDictionary])
Check 'Liste: Schemaversion und Art' ($list['Schema'] -eq 1 -and $list['Kind'] -eq 'List')
Check 'Pruefung: Name fehlt' (Throws { New-SmProject -Name '  ' })
Check 'Pruefung: Name zu lang' (Throws { New-SmProject -Name ('x' * 101) })
Check 'Pruefung: Status ausserhalb der Whitelist' (Throws { New-SmProject -Name 'a' -Status 'Egal' })
Check 'Pruefung: Rolle ausserhalb der Whitelist' (Throws { New-SmProject -Name 'a' -Servers @([ordered]@{ Name = 'x1'; Role = 'FTP'; Generation = 'alt' }) })
Check 'Pruefung: alt/neu ausserhalb der Whitelist' (Throws { New-SmProject -Name 'a' -Servers @([ordered]@{ Name = 'x1'; Role = 'DNS'; Generation = 'mittel' }) })
Check 'Pruefung: Servername mit Sonderzeichen' (Throws { New-SmProject -Name 'a' -Servers @([ordered]@{ Name = "x1';calc"; Role = 'DNS'; Generation = 'alt' }) })
Check 'Pruefung: Tauschordner-Link nur https auf sharepoint.com' (Throws { New-SmProject -Name 'a' -ShareLink 'https://evil.example.com/:f:/g/x' })
Check 'Pruefung: Steuerzeichen im Namen' (Throws { New-SmProject -Name ("a" + [char]7 + 'b') })
Check 'Pruefung: doppelte Projekt-Id in der Liste' (Throws { $l = Copy-SmData $list; $l['Projects'] = @($l['Projects'][0], $l['Projects'][0]); ConvertTo-SmProjectList $l })
Check 'Pruefung: neuere Schemaversion klar abgelehnt' (ThrowsLike { $l = Copy-SmData $list; $l['Schema'] = 2; ConvertTo-SmProjectList $l } 'Schema 2')
Check 'Pruefung: Projekt statt Liste abgelehnt' (Throws { ConvertTo-SmProjectList ([ordered]@{ Kind = 'Project'; Schema = 1 }) })

# Erweiterbar: unbekannte Felder und Ergebnisse spaeterer Phasen bleiben durch Speichern, Aendern und Verschluesseln erhalten
$pExt = New-SmProject -Name 'Mit Ergebnissen'
$pExt['Results'] = [ordered]@{ Dns = [ordered]@{ Clients = @([ordered]@{ Ip = '10.0.0.5'; Count = 3 }); Stand = '2026-11-22T10:00:00Z' } }
$pExt['Zukunft'] = 'bleibt'
$lExt = Set-SmProjectInList -List (New-SmProjectList) -Project $pExt
$lExt = Unprotect-SmProjectData -Bytes (Protect-SmProjectData -Data $lExt -Password $pw) -Password $pw
$rExt = ConvertTo-SmProjectList $lExt
Check 'Schema erweiterbar: Results und unbekannte Felder ueberleben Speichern und Verschluesseln' ($rExt['Projects'][0]['Zukunft'] -eq 'bleibt' -and $rExt['Projects'][0]['Results']['Dns']['Clients'][0]['Ip'] -eq '10.0.0.5' -and $rExt['Projects'][0]['Results']['Dns']['Clients'][0]['Count'] -eq 3)

# Anlegen, Bearbeiten, Loeschen, Suche (rein im Speicher)
$l = New-SmProjectList
$a = New-SmProject -Name 'Alpha' -Customer 'Fabrikam' -Servers @([ordered]@{ Name = 'print01.fabrikam.local'; Role = 'Print'; Generation = 'alt' })
$b = New-SmProject -Name 'Beta' -Customer 'Contoso' -Notes 'Standort Hamburg'
$l = Set-SmProjectInList -List $l -Project $a
$l = Set-SmProjectInList -List $l -Project $b
Check 'Anlegen: zwei Projekte' (@($l['Projects']).Count -eq 2)
$a2 = Copy-SmData $a; $a2['Name'] = 'Alpha 2'
$l2 = Set-SmProjectInList -List $l -Project $a2
Check 'Bearbeiten: Name geaendert, Anzahl gleich, Id gleich, Original-Liste unveraendert' (@($l2['Projects']).Count -eq 2 -and (@($l2['Projects'] | Where-Object Id -eq $a['Id'])[0]['Name'] -eq 'Alpha 2') -and (@($l['Projects'] | Where-Object Id -eq $a['Id'])[0]['Name'] -eq 'Alpha'))
$l3 = Remove-SmProjectFromList -List $l2 -Id $a['Id']
Check 'Loeschen: Projekt weg, anderes bleibt' (@($l3['Projects']).Count -eq 1 -and $l3['Projects'][0]['Name'] -eq 'Beta')
Check 'Suche: nach Name' (@(Find-SmProjects -List $l -Text 'alp').Count -eq 1)
Check 'Suche: nach Kunde, ohne Gross-/Kleinschreibung' (@(Find-SmProjects -List $l -Text 'CONTOSO').Count -eq 1)
Check 'Suche: nach Servername' (@(Find-SmProjects -List $l -Text 'print01').Count -eq 1 -and @(Find-SmProjects -List $l -Text 'print01')[0]['Name'] -eq 'Alpha')
Check 'Suche: nach Notiz' (@(Find-SmProjects -List $l -Text 'hamburg').Count -eq 1)
Check 'Suche: leer = alle, sortiert; ohne Treffer = leer' (@(Find-SmProjects -List $l -Text '').Count -eq 2 -and (Find-SmProjects -List $l -Text '')[0]['Name'] -eq 'Alpha' -and @(Find-SmProjects -List $l -Text 'zzz').Count -eq 0)

# ---------------------------------------------------------------- 3. Export und Import eines Projekts
$expPw = 'Export-Kennwort-456'
$file = Join-Path $Work 'projekt.smproj'
[IO.File]::WriteAllBytes($file, (Export-SmProject -Project $p1 -Password $expPw))
$exBytes = [IO.File]::ReadAllBytes($file)
$exText = [Text.Encoding]::UTF8.GetString($exBytes) + [Text.Encoding]::ASCII.GetString($exBytes)
Check 'Export: Datei ist verschluesselt (kein Klartext)' (($exText -notmatch 'Contoso') -and ($exText -notmatch 'sharepoint') -and ($exText -notmatch [regex]::Escape($expPw)))
$imp = Import-SmProject -Bytes $exBytes -Password $expPw
Check 'Import: identischer Stand wie das exportierte Projekt (alle Felder, auch Zeitstempel)' ((Json $imp) -eq (Json $p1))
Check 'Import: Export-Datei mit falschem Kennwort liefert nichts' (ThrowsLike { Import-SmProject -Bytes $exBytes -Password $pw } 'Kennwort ist falsch')
Check 'Import: manipulierte Datei abgelehnt' (Throws { Import-SmProject -Bytes (Flip $exBytes 70) -Password $expPw })
Check 'Import: Projektliste statt Einzelprojekt abgelehnt' (ThrowsLike { Import-SmProject -Bytes $enc -Password $pw } 'keine exportierte Projektdatei')
Check 'Import: Einzelprojekt als Projektliste abgelehnt' (ThrowsLike { ConvertTo-SmProjectList (Unprotect-SmProjectData -Bytes $exBytes -Password $expPw) } 'keine Projektliste')
$lImp = Set-SmProjectInList -List (New-SmProjectList) -Project $imp -KeepModified
Check 'Import in eine Liste: Projekt unveraendert (Modified bleibt)' ((Json $lImp['Projects'][0]) -eq (Json $p1))
# feindliche Datei: gueltig verschluesselt, aber mit boesem Inhalt
$evilObj = [ordered]@{ Kind = 'Project'; Schema = 1; Project = [ordered]@{ Id = [guid]::NewGuid().ToString(); Name = 'x'; ShareLink = 'http://evil.example.com/x'; Status = 'Geplant'; Servers = @() } }
Check 'Import: gueltig verschluesselte Datei mit boesem Link wird geprueft und abgelehnt' (Throws { Import-SmProject -Bytes (Protect-SmProjectData -Data $evilObj -Password $expPw) -Password $expPw })

# ---------------------------------------------------------------- 4. Kennwort merken (DPAPI)
$rem = Join-Path $Work 'verbindung.dat'
Save-SmRemembered -Link $linkP -Password $pw -Path $rem
$remText = [IO.File]::ReadAllText($rem)
Check 'Merken: Datei enthaelt weder Link noch Kennwort im Klartext' ($remText -notmatch 'sharepoint' -and $remText -notmatch [regex]::Escape($pw) -and $remText.Length -gt 100)
$r = Get-SmRemembered -Path $rem
Check 'Merken: Link und Kennwort kommen zurueck' ($r.Link -eq $linkP -and $r.Password -eq $pw)
Clear-SmRemembered -Path $rem
Check 'Vergessen: Datei geloescht, nichts mehr gemerkt' (-not (Test-Path $rem) -and $null -eq (Get-SmRemembered -Path $rem))
[IO.File]::WriteAllText($rem, 'kein-gueltiger-DPAPI-Text')
Check 'Merken: unlesbare Datei gilt als nicht gemerkt (kein Absturz)' ($null -eq (Get-SmRemembered -Path $rem))

Check 'Merken: Standardpfad liegt in LOCALAPPDATA, nicht im Roaming-Profil' ((Get-SmRememberPath).StartsWith($env:LOCALAPPDATA, [StringComparison]::OrdinalIgnoreCase) -and -not (Get-SmRememberPath).StartsWith($env:APPDATA, [StringComparison]::OrdinalIgnoreCase))
$legacy = Join-Path $Work 'alt\ServerMigration\verbindung.dat'
New-Item -ItemType Directory -Force (Split-Path -Parent $legacy) | Out-Null
[IO.File]::WriteAllText($legacy, 'alt')
Check 'Merken: alte Datei in %APPDATA% wird einmalig geloescht' ((Remove-SmLegacyRemembered -Path $legacy) -and -not (Test-Path $legacy) -and -not (Remove-SmLegacyRemembered -Path $legacy))
$srcAll = [IO.File]::ReadAllText((Join-Path $Repo 'Modules\SmProjekte.ps1'))
Check 'Merken: ohne Haken beim Verbinden wird Clear-SmRemembered gerufen (beide Stellen)' ([regex]::Matches($srcAll, 'else \{ try \{ Clear-SmRemembered').Count -eq 2)

# ---------------------------------------------------------------- 4b. Link-Host bestaetigen
Check 'Host: aus dem Link, kleingeschrieben' ((Get-SmShareHost 'https://Contoso-My.SharePoint.com/:f:/g/x') -eq 'contoso-my.sharepoint.com' -and $null -eq (Get-SmShareHost ''))
Check 'Host: Projekt mit Link ist zunaechst nicht bestaetigt, ohne Link immer' (-not (Test-SmShareHostConfirmed $p1) -and (Test-SmShareHostConfirmed (New-SmProject -Name 'ohne')))
$pc = Set-SmShareHostConfirmed $p1
Check 'Host: nach Bestaetigen vermerkt, Original unveraendert' ((Test-SmShareHostConfirmed $pc) -and -not (Test-SmShareHostConfirmed $p1) -and @($pc['ShareHostConfirmed']) -contains 'contoso-my.sharepoint.com')
$lc = Unprotect-SmProjectData -Bytes (Protect-SmProjectData -Data (Set-SmProjectInList -List (New-SmProjectList) -Project $pc) -Password $pw) -Password $pw
Check 'Host: bestaetigter Host steht in der verschluesselten Liste und ueberlebt den Rundlauf' (Test-SmShareHostConfirmed (ConvertTo-SmProjectList $lc)['Projects'][0])
$pOther = Copy-SmData $pc; $pOther['ShareLink'] = 'https://fabrikam-my.sharepoint.com/:f:/g/personal/x/EAbc'
Check 'Host: anderer Host im Link ist wieder unbestaetigt' (-not (Test-SmShareHostConfirmed (ConvertTo-SmProjectRecord $pOther)))
$pBad = Copy-SmData $p1; $pBad['ShareHostConfirmed'] = @('ok.example.com', "evil';calc", 'x y')
Check 'Host: ungueltige Eintraege in ShareHostConfirmed werden verworfen' (@((ConvertTo-SmProjectRecord $pBad)['ShareHostConfirmed']).Count -eq 1)
$pPre = Copy-SmData $p1; $pPre['ShareHostConfirmed'] = @('contoso-my.sharepoint.com')
$impPre = Import-SmProject -Bytes (Export-SmProject -Project $pPre -Password $expPw) -Password $expPw
Check 'Import: mitgebrachte ShareHostConfirmed wird verworfen, Host unbestaetigt' (@($impPre['ShareHostConfirmed']).Count -eq 0 -and -not (Test-SmShareHostConfirmed $impPre))
$infoNew = Get-SmImportInfo -Imported $impPre -Existing $null
Check 'Import-Info: neues Projekt mit Link verlangt Bestaetigung und nennt den Host' ($infoNew.NeedsHostConfirm -and $infoNew.HostNew -eq 'contoso-my.sharepoint.com' -and -not $infoNew.Exists)
$infoSame = Get-SmImportInfo -Imported $impPre -Existing $pc
Check 'Import-Info: gleicher Link, Host beim vorhandenen Projekt schon bestaetigt: keine Rueckfrage' (-not $infoSame.NeedsHostConfirm -and $infoSame.Exists)
$impChanged = Copy-SmData $impPre; $impChanged['ShareLink'] = 'https://fabrikam-my.sharepoint.com/:f:/g/personal/x/EAbc'; $impChanged['Name'] = 'Contoso Neu'
$infoChg = Get-SmImportInfo -Imported (ConvertTo-SmProjectRecord $impChanged) -Existing $pc
Check 'Import-Info: geaenderter Link auf anderen Host verlangt Bestaetigung' ($infoChg.NeedsHostConfirm -and $infoChg.HostOld -eq 'contoso-my.sharepoint.com' -and $infoChg.HostNew -eq 'fabrikam-my.sharepoint.com')
$askTxt = Format-SmImportReplaceText $infoChg
Check 'Ersetzen-Dialog zeigt Name UND Host alt und neu' ($askTxt -match 'Contoso Migration' -and $askTxt -match 'Contoso Neu' -and $askTxt -match 'contoso-my\.sharepoint\.com' -and $askTxt -match 'fabrikam-my\.sharepoint\.com')
Check 'Bestaetigungs-Dialog nennt den Host' ((Format-SmHostConfirmText -HostName 'contoso-my.sharepoint.com' -ProjectName 'X') -match 'contoso-my\.sharepoint\.com')
Check 'Quelltext: Aktivieren fragt bei unbestaetigtem Host, das Berater-Tool uebernimmt den Link nur bestaetigt' ($srcAll -match 'Test-SmShareHostConfirmed \$p' -and [IO.File]::ReadAllText((Join-Path $Repo 'Start-ServerMigration.ps1')) -match 'Test-SmShareHostConfirmed \$project')

# ---------------------------------------------------------------- 4c. Zusammenfuehren
function MkL($ps) { $l = New-SmProjectList; foreach ($x in $ps) { $l = Set-SmProjectInList -List $l -Project $x -KeepModified }; $l }
function Edit($p, $name) { $c = Copy-SmData $p; $c['Name'] = $name; ConvertTo-SmProjectRecord $c }
$mA = New-SmProject -Name 'A'; $mB = New-SmProject -Name 'B'; $mC = New-SmProject -Name 'C'
$baseL = MkL @($mA, $mB, $mC)
function Names($r) { (@($r.List['Projects'] | ForEach-Object { $_['Name'] } | Sort-Object) -join ',') }
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @((Edit $mA 'A-meins'), $mB, $mC)) -Theirs (MkL @($mA, (Edit $mB 'B-deren'), $mC))
Check 'Zusammenfuehren: verschiedene Projekte geaendert -> beides drin, kein Konflikt' ((Names $r) -eq 'A-meins,B-deren,C' -and $r.Conflicts.Count -eq 0)
$mN1 = New-SmProject -Name 'N-meins'; $mN2 = New-SmProject -Name 'N-deren'
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @($mA, $mB, $mC, $mN1)) -Theirs (MkL @($mA, $mB, $mC, $mN2))
Check 'Zusammenfuehren: beide legen ein neues Projekt an -> beide drin' ((Names $r) -eq 'A,B,C,N-deren,N-meins' -and $r.Conflicts.Count -eq 0)
$mine2 = MkL @((Edit $mA 'A-meins'), $mB, $mC); $their2 = MkL @((Edit $mA 'A-deren'), $mB, $mC)
$r = Merge-SmProjectLists -Base $baseL -Mine $mine2 -Theirs $their2
Check 'Zusammenfuehren: dasselbe Projekt verschieden geaendert -> Konflikt gemeldet (ohne Wahl gilt deren Fassung)' ($r.Conflicts.Count -eq 1 -and $r.Conflicts[0].Kind -eq 'Beide' -and $r.Unresolved -eq 1 -and (Names $r) -eq 'A-deren,B,C')
$r = Merge-SmProjectLists -Base $baseL -Mine $mine2 -Theirs $their2 -Choices @{ $mA['Id'] = 'Mine' }
Check 'Zusammenfuehren: Wahl "meine Fassung" -> meine Fassung, aufgeloest' ((Names $r) -eq 'A-meins,B,C' -and $r.Unresolved -eq 0)
$r = Merge-SmProjectLists -Base $baseL -Mine $mine2 -Theirs $their2 -Choices @{ $mA['Id'] = 'Theirs' }
Check 'Zusammenfuehren: Wahl "deren Fassung" -> deren Fassung' ((Names $r) -eq 'A-deren,B,C' -and $r.Unresolved -eq 0)
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @((Edit $mA 'gleich'), $mB, $mC)) -Theirs (MkL @((Edit $mA 'gleich'), $mB, $mC))
Check 'Zusammenfuehren: beide haben dasselbe geaendert -> kein Konflikt' ($r.Conflicts.Count -eq 0 -and (Names $r) -eq 'B,C,gleich')
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @($mB, $mC)) -Theirs (MkL @($mA, (Edit $mB 'B-deren'), $mC))
Check 'Zusammenfuehren: ich loesche A (beim anderen unveraendert), der andere aendert B -> A weg, B-deren da' ((Names $r) -eq 'B-deren,C' -and $r.Conflicts.Count -eq 0)
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @((Edit $mA 'A-meins'), $mB, $mC)) -Theirs (MkL @($mB, $mC))
Check 'Zusammenfuehren: der andere loescht A, ich habe A geaendert -> Konflikt DereLoeschung' ($r.Conflicts.Count -eq 1 -and $r.Conflicts[0].Kind -eq 'DereLoeschung' -and (Names $r) -eq 'B,C')
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @((Edit $mA 'A-meins'), $mB, $mC)) -Theirs (MkL @($mB, $mC)) -Choices @{ $mA['Id'] = 'Mine' }
Check 'Zusammenfuehren: Konflikt Loeschung, Wahl "meine Fassung" behaelt mein A' ((Names $r) -eq 'A-meins,B,C')
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @($mB, $mC)) -Theirs (MkL @((Edit $mA 'A-deren'), $mB, $mC))
Check 'Zusammenfuehren: ich loesche A, der andere hat A geaendert -> Konflikt MeineLoeschung (ohne Wahl bleibt A)' ($r.Conflicts.Count -eq 1 -and $r.Conflicts[0].Kind -eq 'MeineLoeschung' -and (Names $r) -eq 'A-deren,B,C')
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @($mB, $mC)) -Theirs (MkL @((Edit $mA 'A-deren'), $mB, $mC)) -Choices @{ $mA['Id'] = 'Mine' }
Check 'Zusammenfuehren: Konflikt Loeschung, Wahl "meine Fassung" loescht A' ((Names $r) -eq 'B,C')
$r = Merge-SmProjectLists -Base $baseL -Mine (MkL @($mB, $mC)) -Theirs (MkL @($mB, $mC))
Check 'Zusammenfuehren: beide loeschen A -> weg, kein Konflikt' ($r.Conflicts.Count -eq 0 -and (Names $r) -eq 'B,C')
Check 'Zusammenfuehren: Ergebnis ist eine gueltige Liste, Fragetexte nennen Projekt und Seite' ((-not (Throws { ConvertTo-SmProjectList $r.List })) -and (Format-SmMergeQuestion ([pscustomobject]@{ Kind = 'DereLoeschung'; Name = 'A' })) -match 'geloescht' -and (Format-SmMergeQuestion ([pscustomobject]@{ Kind = 'Beide'; Name = 'A' })) -match 'meine Fassung')
Check 'Seite: Konflikt-Feld bietet Zusammenfuehren an' ([IO.File]::ReadAllText((Join-Path $Repo 'UI\Projekte.xaml')) -match 'BtnConflictMerge' -and (Get-SmProjectUiNames) -contains 'BtnConflictMerge')

# ---------------------------------------------------------------- 5. Meldungen ohne Links und Kennwoerter
$msg = Get-SmSafeMessage ("Fehler bei $linkP mit $pw und https://x.sharepoint.com/abc und 'foo.sharepoint.com'") @($linkP, $pw)
Check 'Meldungen: Link, Kennwort und Adressen werden entfernt' ($msg -notmatch 'sharepoint' -and $msg -notmatch [regex]::Escape($pw) -and $msg -notmatch 'https?://')
$src = [IO.File]::ReadAllText((Join-Path $Repo 'Modules\SmProjekte.ps1'))
Check 'Quelltext: kein Write-Host, Write-Output, Out-File, Add-Content, Start-Transcript' ($src -notmatch '(?m)^(?!\s*#).*\b(Write-Host|Write-Output|Out-File|Add-Content|Start-Transcript|Set-Content)\b')
Check 'Quelltext: Dateien schreibt nur das Merken (DPAPI) und der Export' ([regex]::Matches($src, 'WriteAll(Text|Bytes)').Count -eq 2)
Check 'Quelltext: jede Protokollzeile mit einem Fehlertext laeuft durch Get-SmSafeMessage' (@(($src -split "`r?`n") | Where-Object { $_ -match '\.Log \(' -and $_ -match '\$err\b|Exception\.Message' -and $_ -notmatch 'Get-SmSafeMessage' }).Count -eq 0)

# ---------------------------------------------------------------- 6. Seite "Projekte": XAML, Namen, -ParseOnly
$pageXaml = Get-SmProjectPageXaml -Root $Repo
$names = @(Get-SmXamlNames $pageXaml)
$missing = @(Get-SmProjectUiNames | Where-Object { $names -notcontains $_ })
Check ('Seite: alle erwarteten Steuerelemente im XAML ({0}); fehlt: {1}' -f $names.Count, ($missing -join ',')) ($missing.Count -eq 0 -and ($names | Group-Object | Where-Object Count -gt 1).Count -eq 0)
if ([Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $okDlg = try { [xml]$dx = Get-SmPasswordDialogXaml; $dw = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dx)); [bool]($dw.FindName('PwdDlg1') -and $dw.FindName('PwdDlg2') -and $dw.FindName('BtnDlgOk')) } catch { $false }
    Check 'Kennwort-Dialog: XAML laedt, Felder vorhanden' $okDlg
}
else { Write-Host 'INFO Kennwort-Dialog-Test uebersprungen (kein STA)' -ForegroundColor Yellow }
foreach ($mode in 'Light', 'Dark') {
    $out = & powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $Repo 'Start-ServerMigration.ps1') -ParseOnly -Theme $mode 2>&1 | Out-String
    Check ("Berater-Tool mit Seite Projekte -ParseOnly ($mode): $($out.Trim())") ($out.Trim() -eq 'PARSE OK')
}

# ---------------------------------------------------------------- 7. Ablage ueber Freigabelink mit ETag (nachgebauter SharePoint)
$port = Get-Random -Minimum 19100 -Maximum 19900
$base = "http://localhost:$port"
$folder = '/personal/max_contoso_com/Documents/Projektliste Test'
$linkM = "$base/:f:/g/personal/max_contoso_com/EAbcDEF?e=x1Y2z3"
$store = [hashtable]::Synchronized(@{})     # Dateiname -> Bytes
$vers = [hashtable]::Synchronized(@{})      # Dateiname -> Versionszaehler (Teil des ETag)
$flags = [hashtable]::Synchronized(@{ IgnoreIfMatch = $false; Puts = 0; Adds = 0; OmitEtag = $false; LieLength = $false; BigBody = $false; Redirect = $false; RedirHits = 0 })
$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("$base/"); $listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Start()
$rs = [runspacefactory]::CreateRunspace(); $rs.Open()
$server = [powershell]::Create(); $server.Runspace = $rs
[void]$server.AddScript({
        param($listener, $store, $vers, $flags, $base, $folder)
        $web = '/personal/max_contoso_com'
        $ew = [regex]::Escape($web)
        $reMeta = '^' + $ew + '/_api/web/GetFileByServerRelativeUrl\(@f\)\?@f=''(.+)''&\$select=ETag,Length$'
        $reValue = '^' + $ew + '/_api/web/GetFileByServerRelativeUrl\(@f\)/\$value\?@f=''(.+)''$'
        $reAdd = '^' + $ew + '/_api/web/GetFolderByServerRelativeUrl\(@f\)/Files/add\(url=''([^'']+)'',overwrite=(true|false)\)\?@f=''(.+)''$'
        while ($listener.IsListening) {
            try { $c = $listener.GetContext() } catch { break }
            $q = $c.Request; $res = $c.Response
            $raw = [uri]::UnescapeDataString($q.RawUrl)
            if ($q.Url.AbsolutePath -like '/redir/*') { $flags.RedirHits++ }
            $body = $null; $status = 200; $type = 'application/json'; $name = $null
            $guest = $q.Cookies['FedAuth'] -and $q.Cookies['FedAuth'].Value -eq 'gast'
            $etagOf = { param($n) '"{11111111-2222-3333-4444-555555555555},' + $vers[$n] + '"' }
            if ($q.Url.AbsolutePath -eq '/:f:/g/personal/max_contoso_com/EAbcDEF') {
                $res.AddHeader('Set-Cookie', 'FedAuth=gast; path=/')
                $res.StatusCode = 302
                $res.RedirectLocation = "$base$web/_layouts/15/onedrive.aspx?id=" + [uri]::EscapeDataString($folder) + '&ga=1'
                $res.Close(); continue
            }
            elseif ($q.Url.AbsolutePath -eq '/redir/file') { $type = 'application/octet-stream'; $body = [Text.Encoding]::UTF8.GetBytes('umgeleitet') }
            elseif ($q.Url.AbsolutePath -eq "$web/_layouts/15/onedrive.aspx") { $type = 'text/html'; $body = [Text.Encoding]::UTF8.GetBytes('<html>OneDrive</html>') }
            elseif (-not $guest) { $status = 401; $body = [Text.Encoding]::UTF8.GetBytes('{"error":"no guest session"}') }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -eq "$web/_api/contextinfo") { $body = [Text.Encoding]::UTF8.GetBytes('{"FormDigestValue":"digest-123"}') }
            elseif ($q.HttpMethod -eq 'POST' -and $q.Headers['X-RequestDigest'] -ne 'digest-123') { $status = 403 }
            elseif ($q.HttpMethod -eq 'GET' -and $raw -match $reMeta) {
                $name = $Matches[1].Substring([math]::Min($Matches[1].Length, $folder.Length + 1))
                if ($Matches[1].StartsWith($folder + '/') -and $store.ContainsKey($name)) {
                    $body = [Text.Encoding]::UTF8.GetBytes('{"ETag":"' + (& $etagOf $name).Replace('"', '\"') + '","Length":"' + $(if ($flags.LieLength) { 100 } else { $store[$name].Length }) + '"}')
                }
                else { $status = 404; $body = [Text.Encoding]::UTF8.GetBytes('{"error":"not found"}') }
            }
            elseif ($q.HttpMethod -eq 'GET' -and $raw -match $reValue) {
                $name = $Matches[1].Substring([math]::Min($Matches[1].Length, $folder.Length + 1))
                if ($flags.Redirect) { $res.StatusCode = 302; $res.RedirectLocation = "http://127.0.0.1:$($q.Url.Port)/redir/file"; $res.Close(); continue }
                if ($Matches[1].StartsWith($folder + '/') -and $store.ContainsKey($name)) { $type = 'application/octet-stream'; $body = if ($flags.BigBody) { New-Object byte[] (21MB) } else { $store[$name] } } else { $status = 404 }
            }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -match $reValue) {
                $name = $Matches[1].Substring([math]::Min($Matches[1].Length, $folder.Length + 1))
                if (-not $Matches[1].StartsWith($folder + '/') -or -not $store.ContainsKey($name)) { $status = 404 }
                elseif ($q.Headers['X-HTTP-Method'] -ne 'PUT') { $status = 405 }
                elseif (-not $flags.IgnoreIfMatch -and $q.Headers['If-Match'] -ne (& $etagOf $name)) { $status = 412; $body = [Text.Encoding]::UTF8.GetBytes('{"error":"precondition failed"}') }
                else {
                    $ms = New-Object IO.MemoryStream; $q.InputStream.CopyTo($ms)
                    $store[$name] = $ms.ToArray(); $vers[$name] = $vers[$name] + 1; $flags.Puts++
                }
            }
            elseif ($q.HttpMethod -eq 'POST' -and $raw -match $reAdd) {
                $name = $Matches[1]; $overwrite = $Matches[2] -eq 'true'
                if ($Matches[3] -ne $folder) { $status = 403 }
                elseif ($store.ContainsKey($name) -and -not $overwrite) { $status = 500; $body = [Text.Encoding]::UTF8.GetBytes('{"error":"file already exists"}') }
                else {
                    $ms = New-Object IO.MemoryStream; $q.InputStream.CopyTo($ms)
                    $store[$name] = $ms.ToArray(); $vers[$name] = 1; $flags.Adds++
                    $body = [Text.Encoding]::UTF8.GetBytes('{"Name":"' + $name + '"}')
                }
            }
            else { $status = 404 }
            if ($name -and -not $flags.OmitEtag -and $q.HttpMethod -eq 'POST' -and $status -eq 200 -and $store.ContainsKey($name)) { $res.AddHeader('ETag', (& $etagOf $name)) }
            $res.StatusCode = $status; $res.ContentType = $type
            if ($body) { $res.OutputStream.Write($body, 0, $body.Length) }
            $res.Close()
        }
    }).AddArgument($listener).AddArgument($store).AddArgument($vers).AddArgument($flags).AddArgument($base).AddArgument($folder)
$serverHandle = $server.BeginInvoke()
$fname = $script:SmProjFileName

try {
    $share = Connect-SmShare -Link $linkM -AnyHost
    Check 'Ablage: Freigabelink verbunden' ($share.Folder -eq $folder)
    $r0 = Read-SmProjectStore -Share $share -Password $pw
    Check 'Ablage: noch keine Datei -> Exists false, leere Liste' (-not $r0.Exists -and $null -eq $r0.ETag -and @($r0.List['Projects']).Count -eq 0)

    $s1 = Save-SmProjectStore -Share $share -Password $pw -List $list -ETag $null
    Check 'Neuanlage: gespeichert, ETag zurueckgegeben' ($s1.Ok -and -not $s1.Conflict -and $s1.ETag -match '^"\{[0-9A-F-]+\},1"$' -and $flags.Adds -eq 1)
    $stored = [byte[]]$store[$fname]
    $storedText = [Text.Encoding]::UTF8.GetString($stored) + [Text.Encoding]::ASCII.GetString($stored)
    Check 'Neuanlage: im Ablageort liegt nur verschluesselter Inhalt (SMPJ, kein Klartext)' ($stored[0] -eq 0x53 -and $storedText -notmatch 'Contoso' -and $storedText -notmatch 'sharepoint' -and $storedText -notmatch [regex]::Escape($pw))
    $r1 = Read-SmProjectStore -Share $share -Password $pw
    Check 'Lesen: gleicher Inhalt, ETag gleich dem beim Speichern' ($r1.Exists -and $r1.ETag -eq $s1.ETag -and (Json $r1.List) -eq (Json $list))

    $dup = Save-SmProjectStore -Share $share -Password $pw -List (New-SmProjectList) -ETag $null
    Check 'Neuanlage ueber vorhandene Datei: Konflikt, nichts ueberschrieben' ($dup.Conflict -and -not $dup.Ok -and [Convert]::ToBase64String($store[$fname]) -eq [Convert]::ToBase64String($stored))

    $listB = Set-SmProjectInList -List $r1.List -Project $b
    $s2 = Save-SmProjectStore -Share $share -Password $pw -List $listB -ETag $r1.ETag
    Check 'Speichern mit aktuellem ETag: Ok, neuer ETag, If-Match akzeptiert' ($s2.Ok -and $s2.ETag -match ',2"$' -and $s2.ETag -ne $r1.ETag -and $flags.Puts -eq 1)
    $r2 = Read-SmProjectStore -Share $share -Password $pw
    Check 'Lesen nach Speichern: zwei Projekte' (@($r2.List['Projects']).Count -eq 2 -and $r2.ETag -eq $s2.ETag)

    # Jemand anderes speichert dazwischen (gleicher Ablageort, anderes Projekt)
    $foreign = Set-SmProjectInList -List $r2.List -Project (New-SmProject -Name 'Von anderem Berater')
    $foreignBytes = Protect-SmProjectData -Data $foreign -Password $pw
    $store[$fname] = $foreignBytes; $vers[$fname] = $vers[$fname] + 1
    $mine = Set-SmProjectInList -List $r2.List -Project (New-SmProject -Name 'Meine Aenderung')
    $putsBefore = $flags.Puts
    $s3 = Save-SmProjectStore -Share $share -Password $pw -List $mine -ETag $r2.ETag
    Check 'ETag-Konflikt: erkannt und gemeldet, es wurde nichts geschrieben' ($s3.Conflict -and -not $s3.Ok -and $flags.Puts -eq $putsBefore -and [Convert]::ToBase64String($store[$fname]) -eq [Convert]::ToBase64String($foreignBytes))
    # If-Match allein (ohne Vorab-Pruefung): der Ablageort lehnt den alten Stand mit 412 ab
    $direct = Send-SmProjectBytes -Share $share -Bytes (Protect-SmProjectData -Data $mine -Password $pw) -ETag $r2.ETag
    Check 'If-Match: alter ETag wird vom Ablageort mit 412 abgelehnt, als Konflikt gemeldet, Datei unveraendert' ($direct.Conflict -and -not $direct.Ok -and [Convert]::ToBase64String($store[$fname]) -eq [Convert]::ToBase64String($foreignBytes))
    # Ablageort wertet If-Match nicht aus: die Vorab-Pruefung faengt den Konflikt trotzdem
    $flags.IgnoreIfMatch = $true
    $s4 = Save-SmProjectStore -Share $share -Password $pw -List $mine -ETag $r2.ETag
    Check 'Vorab-Pruefung: Konflikt auch, wenn der Ablageort If-Match ignoriert' ($s4.Conflict -and [Convert]::ToBase64String($store[$fname]) -eq [Convert]::ToBase64String($foreignBytes))
    $flags.IgnoreIfMatch = $false

    # neu laden, Aenderung noch einmal anwenden (zusammenfuehren): beides ist danach drin
    $r3 = Read-SmProjectStore -Share $share -Password $pw
    Check 'Neu laden: Stand des anderen Beraters sichtbar' (@($r3.List['Projects'] | Where-Object Name -eq 'Von anderem Berater').Count -eq 1)
    $merged = Set-SmProjectInList -List $r3.List -Project (New-SmProject -Name 'Meine Aenderung')
    $s5 = Save-SmProjectStore -Share $share -Password $pw -List $merged -ETag $r3.ETag
    $r4 = Read-SmProjectStore -Share $share -Password $pw
    Check 'Nach dem Neuladen speichern: Ok, beide Aenderungen sind in der Liste' ($s5.Ok -and @($r4.List['Projects']).Count -eq 4 -and @($r4.List['Projects'] | Where-Object Name -in 'Von anderem Berater', 'Meine Aenderung').Count -eq 2)

    # Falsches Kennwort und manipulierte Datei beim Lesen
    $m = $null; try { Read-SmProjectStore -Share $share -Password 'falsches-Kennwort' | Out-Null } catch { $m = $_.Exception.Message }
    Check 'Lesen mit falschem Kennwort: klare Meldung, kein Kennwort in der Meldung, Datei unveraendert' ($m -match 'Kennwort ist falsch' -and $m -notmatch 'falsches-Kennwort' -and $m -notmatch 'localhost')
    $good = [byte[]]$store[$fname].Clone()
    $store[$fname] = (Flip $good 80)
    Check 'Lesen einer manipulierten Datei im Ablageort: abgelehnt (HMAC)' (ThrowsLike { Read-SmProjectStore -Share $share -Password $pw } 'veraendert')
    $store[$fname] = $good

    # Ablageort ohne ETag-Angabe darf nie stillschweigend speichern
    $vers2 = $vers[$fname]
    # ETag aus der Antwort des PUT; fehlt er dort: $null, keine zweite Abfrage
    $rE = Read-SmProjectStore -Share $share -Password $pw
    $putOk = Save-SmProjectStore -Share $share -Password $pw -List $rE.List -ETag $rE.ETag
    Check 'PUT: ETag kommt aus der Antwort des Schreibens und passt zum Stand im Ablageort' ($putOk.Ok -and $putOk.ETag -eq ('"{11111111-2222-3333-4444-555555555555},' + $vers[$fname] + '"'))
    $flags.OmitEtag = $true
    $rE = Read-SmProjectStore -Share $share -Password $pw
    $putNo = Save-SmProjectStore -Share $share -Password $pw -List $rE.List -ETag $rE.ETag
    Check 'PUT ohne ETag in der Antwort: gespeichert, ETag = $null (vor dem naechsten Speichern wird neu geladen)' ($putNo.Ok -and $null -eq $putNo.ETag)
    $flags.OmitEtag = $false
    $rF = Read-SmProjectStore -Share $share -Password $pw
    Check 'Nach einem Speichern ohne ETag liefert das Neuladen wieder einen ETag' ($rF.Exists -and $rF.ETag -and (Json $rF.List) -eq (Json $rE.List))

    # Weiterleitungsziel und Groesse beim Lesen
    $flags.Redirect = $true
    Check 'Lesen: Weiterleitung auf anderes Ziel wird abgelehnt' (ThrowsLike { Read-SmProjectStore -Share $share -Password $pw } 'unerlaubten Ziel')
    Check 'Lesen: das verbotene Weiterleitungsziel wurde nie angefragt (Pruefung vor dem Laden)' ($flags.RedirHits -eq 0)
    $flags.Redirect = $false
    $flags.LieLength = $true; $flags.BigBody = $true
    Check 'Lesen: tatsaechlich grosser Body (21 MB) wird trotz kleiner Laengenangabe abgelehnt' (ThrowsLike { Read-SmProjectStore -Share $share -Password $pw } 'ungewoehnlich gross')
    $flags.LieLength = $false; $flags.BigBody = $false
    Check 'Lesen: nach den Fehlerfaellen wieder normal' ((Read-SmProjectStore -Share $share -Password $pw).Exists)
    Check 'Weiterleitungsziel: https auf *.sharepoint.com erlaubt, alles andere nicht' ((Test-SmFinalHost -Final ([uri]'https://contoso-my.sharepoint.com/x')) -and -not (Test-SmFinalHost -Final ([uri]'http://contoso-my.sharepoint.com/x')) -and -not (Test-SmFinalHost -Final ([uri]'https://evil.example.com/x')) -and -not (Test-SmFinalHost -Final ([uri]'https://sharepoint.com.evil.net/x')))

    $vers2 = $vers[$fname]
    Check 'Speichern ohne ETag auf vorhandener Datei: Konflikt' ((Save-SmProjectStore -Share $share -Password $pw -List $list -ETag $null).Conflict -and $vers[$fname] -eq $vers2)
}
finally {
    $listener.Stop(); $listener.Close()
    try { [void]$server.EndInvoke($serverHandle) } catch { }
    $server.Dispose(); $rs.Dispose()
}

Write-Host "Projektliste: $fails Fehler"
if ($ownWork) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
if ($MyInvocation.InvocationName -eq '&') { return $fails }   # von der Suite aufgerufen
exit $fails
