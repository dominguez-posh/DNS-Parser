# Design-Regeln

Beide Fenster (Berater-Tool, Server-Fenster) teilen `UI/Theme.xaml`. Farben sind Tokens, hell und dunkel entstehen aus derselben Datei (`Modules/SmTheme.ps1`). Neue Farben nur als Token (oder Literal, das in der Farbtabelle von SmTheme steht). Bausteine in `Modules/SmUi.ps1`. Abnahme: beide Themes ansehen.

Technik: Keine Eigenschaften von Basisklassen (TextBoxBase, ButtonBase) in Styles abgeleiteter Typen und kein XAML ab .NET 4.7.2, die Server können älter sein. Schreibschutz und Scrollbalken der Codefelder setzt `Initialize-SmCodeBoxes` im Code.

## Karten
- `CardBox` mit Padding 20,16, Abstand 16 zwischen Karten, Titel `CardTitle`, Erklärung darunter als `Hint`.
- Eine Karte, eine Hauptaktion: ein `PrimaryButton` (bei der wichtigsten Aktion der Seite `PrimaryLarge`). Rest sind normale Knöpfe oder `LinkButton`.
- Mehrschrittige Seiten: `StepBadge` links vom Titel; offen = Zahl, erledigt = Haken auf grünem Grund (`Set-SmStepState`).

## Knöpfe
- Kopieren bestätigt am Knopf selbst: "Kopiert" mit Haken für 2 s (`Show-SmCopied`), kein Toast.
- Kopier-Symbol in Chips: `ChipIconButton`, mit Tooltip.

## Codefelder
- Lange Befehle und Ausgaben stehen im `CodeBox` (Mono 12, umbrochen, ruhiger Hintergrund, nur senkrechter Scrollbalken). Leer = unsichtbar.
- Sehr lange Befehle sind standardmäßig eingeklappt: einzeilige Vorschau (`CodeLine` + `CodeText`, gekürzt mit "…") und Link "Befehl anzeigen" (`Set-SmOneLiner`).
- Felder zum Einfügen einer Prüfsumme: `HashInput` (Mono 12), Beschriftung `SmallLabel` darüber. Bei DHCP und Print gleich.

## Chips
- Prüfsummen als Chip "SHA256 C5AA1F5E…DF57" (`Chip`, `ChipLabel`, `ChipValue`), Kopier-Symbol im Chip, voller Wert im Tooltip und im Tag (`Set-SmHashChip`). Nie als Fließtext. Ausnahme: Zwei Werte zum Kopieren (Print-Export) stehen im `CodeBox`.

## Hinweisbänder
- Keine freien farbigen Texte. `WarnBand` (Vorsicht, Datenschutz, fehlende Rechte), `InfoBand`, `ErrorBand`: Farbstreifen links, Symbol (`BandGlyph`: Warnung E7BA, Info E946, Fehler E783), Text `BandText` in normaler Textfarbe.
- Gefahrenkästen mit eigener Aktion (z. B. Seize in AD) behalten ihre rote Fläche.

## Protokoll
- Immer die einklappbare Karte aus `Get-SmLogCardXaml`, gefüllt über `Add-SmLogLine`. Zeit in Mono und gedimmt, Meldung normal, Symbol und Farbe nur bei Erfolg (Haken), Hinweis (Warnung), Fehler. Werte ab 40 Hexzeichen und lange Links werden gekürzt (voller Text im Tooltip). "Kopieren" holt das ganze Protokoll.
