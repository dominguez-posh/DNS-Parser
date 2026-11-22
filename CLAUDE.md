# Server-Migration (Repo DNS-Parser)

Werkzeug für die Migration von DNS, DHCP, Printserver und AD.

- Das Repo ist öffentlich. `.claude/` (Team) und `docs/plans/` (Plan und Entscheidungen) bleiben nur lokal im Haupt-Clone und stehen in der `.gitignore`. Worktrees haben sie nicht, Agents lesen sie aus dem Haupt-Clone.
- Plan: `docs/plans/server-migration.md`. Team: `.claude/team/README.md` und `.claude/team/RULES.md`.
- PowerShell: Ziel ist Windows PowerShell 5.1, WPF. Look: `UI/Theme.xaml` (eigene Titelleiste, Navigation links, hell/dunkel).
- Keine Kundendaten, Links, Kennwörter oder internen Adressen ins Repo. Tests nur mit Beispieldaten (contoso.local).
- Akzeptiertes Risiko: Tauschordner-Link in History/Logs des Kundenservers.
- Sicherheit: `docs/security-checklist.md` vor jeder Änderung am Einzeiler, Paket oder Tauschordner prüfen.
