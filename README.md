# Server-Migration

Werkzeug für die Migration von Windows-Servern: DNS, DHCP, Printserver und Active Directory. Es ist noch im Aufbau.

## Starten ohne Herunterladen

Die folgende Zeile in **Windows PowerShell** einfügen:

```powershell
irm https://raw.githubusercontent.com/dominguez-posh/DNS-Parser/main/get.ps1 | iex
```

Aus `cmd`, über Win+R oder als Verknüpfung (startet die Windows PowerShell selbst, ohne Profil, Scriptfreigabe nur für diesen Prozess):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dominguez-posh/DNS-Parser/main/get.ps1 | iex"
```

Die Zeile lädt das neueste Release nach `%LOCALAPPDATA%\ServerMigration\<Version>` und startet das Tool. Gibt es noch kein Release, nimmt sie den Stand von `main`. Die Scriptfreigabe (`-ExecutionPolicy Bypass`) gilt nur für diesen einen Prozess, am System wird nichts umgestellt.

Für eine bestimmte Version vorher `$env:TOOL_REF = 'v1.0.0'` setzen.
