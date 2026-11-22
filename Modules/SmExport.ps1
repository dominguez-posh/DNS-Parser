<#
.SYNOPSIS
    Export-SmTable: eine Tabelle als CSV oder echte Excel-Datei (xlsx) schreiben. Gemeinsam fuer alle Bereiche (DNS, DHCP, Print).
.DESCRIPTION
    Export-SmTable -Rows <object[]> -Path <string>. Die Endung entscheidet: .csv (Semikolon, UTF-8 mit BOM, CRLF) oder .xlsx.
    Die xlsx wird ohne Fremdmodul als OpenXML-ZIP mit System.IO.Compression gebaut: eine Tabelle (Blatt "Tabelle"), Kopfzeile fett
    und fixiert, AutoFilter, Texte als Inline-Strings, Zahlen als Zahl, Datum und Uhrzeit als Text (yyyy-MM-dd HH:mm:ss).
    Formel-Injection (Checkliste 7): Texte, die mit = + - @ Tab oder CR beginnen, bekommen in beiden Formaten ein einfaches
    Anfuehrungszeichen davor, in der xlsx wird nie ein Formel-Element geschrieben. Zahlen (auch negative) bleiben unveraendert.
    Die Spalten kommen aus dem ersten Objekt (Eigenschaften, bei Hashtables die Schluessel). Kopfzeilen werden an Gross-/Kleinschreibung
    getrennt (ErsteAnfrage -> Erste Anfrage). Rows darf auch eine Aufzaehlung sein (wird nicht in ein Array kopiert, wichtig bei Millionen Zeilen).
    Die Funktion liefert die Zahl der geschriebenen Zeilen. Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmExportCSharp = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

public static class SmTable
{
    public const int MaxXlsxRows = 1048576;      // inklusive Kopfzeile
    public const int MaxXlsxColumns = 16384;
    public const int MaxCellChars = 32767;

    private sealed class Col
    {
        public string Name; public object Key; public PropertyInfo Prop;
    }

    private sealed class Shape
    {
        public int Mode;   // 0 Dictionary, 1 PSObject-Eigenschaften, 2 Reflection
        public List<Col> Cols = new List<Col>();
    }

    private static object Unwrap(object o)
    {
        PSObject p = o as PSObject;
        return p != null ? p.BaseObject : o;
    }

    private static Shape MakeShape(object first)
    {
        Shape s = new Shape();
        object b = Unwrap(first);
        IDictionary d = b as IDictionary;
        if (d != null)
        {
            s.Mode = 0;
            foreach (object k in d.Keys) { Col c = new Col(); c.Key = k; c.Name = Convert.ToString(k, CultureInfo.InvariantCulture); s.Cols.Add(c); }
            return s;
        }
        if (b is PSCustomObject)
        {
            s.Mode = 1;
            PSObject pso = PSObject.AsPSObject(first);
            foreach (PSPropertyInfo pi in pso.Properties) { Col c = new Col(); c.Name = pi.Name; s.Cols.Add(c); }
            return s;
        }
        s.Mode = 2;
        foreach (PropertyInfo pi in b.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (pi.GetIndexParameters().Length != 0 || !pi.CanRead) continue;
            Col c = new Col(); c.Name = pi.Name; c.Prop = pi; s.Cols.Add(c);
        }
        return s;
    }

    private static object Get(Shape s, Col c, object row)
    {
        if (row == null) return null;
        try
        {
            if (s.Mode == 0)
            {
                IDictionary d = Unwrap(row) as IDictionary;
                return d != null && d.Contains(c.Key) ? d[c.Key] : null;
            }
            if (s.Mode == 1)
            {
                PSObject pso = row as PSObject ?? PSObject.AsPSObject(row);
                PSPropertyInfo pi = pso.Properties[c.Name];
                return pi == null ? null : pi.Value;
            }
            object b = Unwrap(row);
            return c.Prop.DeclaringType.IsInstanceOfType(b) ? c.Prop.GetValue(b, null) : null;
        }
        catch (Exception) { return null; }
    }

    public static string Header(string name)
    {
        return Regex.Replace(name ?? "", "(?<=[a-z])(?=[A-Z])", " ");
    }

    // Ergebnis einer Zelle: Kind 0 leer, 1 Zahl (Text unveraendert), 2 Text
    private struct Cell { public int Kind; public string Text; }

    private static bool IsNumber(object v)
    {
        return v is sbyte || v is byte || v is short || v is ushort || v is int || v is uint || v is long || v is ulong
            || v is float || v is double || v is decimal;
    }

    private static string Num(object v, CultureInfo ci)
    {
        if (v is double) return ((double)v).ToString("R", ci);
        if (v is float) return ((float)v).ToString("R", ci);
        return Convert.ToString(v, ci);
    }

    private static string Flat(object v)
    {
        object b = Unwrap(v);
        if (b == null) return "";
        string s = b as string;
        if (s != null) return s;
        if (b is DateTime) return ((DateTime)b).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (b is DateTimeOffset) return ((DateTimeOffset)b).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        IFormattable f = b as IFormattable;
        if (f != null) return f.ToString(null, CultureInfo.InvariantCulture);
        return Convert.ToString(b, CultureInfo.InvariantCulture);
    }

    private static Cell MakeCell(object value, CultureInfo numCulture)
    {
        Cell c = new Cell();
        object v = Unwrap(value);
        if (v == null || v is DBNull) return c;
        string s = v as string;
        if (s == null)
        {
            if (IsNumber(v))
            {
                if ((v is double && (double.IsNaN((double)v) || double.IsInfinity((double)v))) || (v is float && (float.IsNaN((float)v) || float.IsInfinity((float)v)))) { s = Convert.ToString(v, CultureInfo.InvariantCulture); }
                else { c.Kind = 1; c.Text = Num(v, numCulture); return c; }
            }
            else if (v is DateTime || v is DateTimeOffset) s = Flat(v);                // Datum immer als ISO-Text
            else if (v is IEnumerable)
            {
                StringBuilder sb = new StringBuilder(); int n = 0;
                foreach (object it in (IEnumerable)v) { if (n++ > 0) sb.Append(", "); sb.Append(Flat(it)); if (sb.Length > MaxCellChars) break; }
                s = sb.ToString();
            }
            else s = Flat(v);
        }
        if (s.Length == 0) return c;
        c.Kind = 2; c.Text = Guard(s); return c;
    }

    // Formel-Injection: gefaehrlicher Anfang bekommt ein einfaches Anfuehrungszeichen davor
    public static string Guard(string s)
    {
        if (s.Length == 0) return s;
        char c = s[0];
        if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r') return "'" + s;
        return s;
    }

    private static string CsvQuote(string s, char delim)
    {
        if (s.IndexOf(delim) >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\r') >= 0 || s.IndexOf('\n') >= 0) s = "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    public static long WriteCsv(IEnumerable rows, string path, char delim)
    {
        long n = 0;
        Shape shape = null;
        CultureInfo ci = delim == ';' ? CultureInfo.CurrentCulture : CultureInfo.InvariantCulture;
        using (StreamWriter w = new StreamWriter(path, false, new UTF8Encoding(true), 65536))
        {
            StringBuilder sb = new StringBuilder();
            foreach (object row in rows)
            {
                if (row == null) continue;
                if (shape == null)
                {
                    shape = MakeShape(row);
                    for (int i = 0; i < shape.Cols.Count; i++) { if (i > 0) sb.Append(delim); sb.Append(CsvQuote(Guard(Header(shape.Cols[i].Name)), delim)); }
                    sb.Append("\r\n"); w.Write(sb.ToString());
                }
                sb.Length = 0;
                for (int i = 0; i < shape.Cols.Count; i++)
                {
                    if (i > 0) sb.Append(delim);
                    Cell c = MakeCell(Get(shape, shape.Cols[i], row), ci);
                    if (c.Kind == 1) sb.Append(CsvQuote(c.Text, delim));
                    else if (c.Kind == 2) sb.Append(CsvQuote(c.Text, delim));
                }
                sb.Append("\r\n"); w.Write(sb.ToString());
                n++;
            }
            if (shape == null) w.Write("\r\n");
        }
        return n;
    }

    // ---------------------------------------------------------------- xlsx
    private static string ColName(int index)   // 0 -> A
    {
        string s = "";
        index++;
        while (index > 0) { int m = (index - 1) % 26; s = (char)('A' + m) + s; index = (index - m) / 26; }
        return s;
    }

    private static void XmlText(StringBuilder sb, string s)
    {
        if (s.Length > MaxCellChars) s = s.Substring(0, MaxCellChars);
        for (int i = 0; i < s.Length; i++)
        {
            char ch = s[i];
            if (ch == '&') sb.Append("&amp;");
            else if (ch == '<') sb.Append("&lt;");
            else if (ch == '>') sb.Append("&gt;");
            else if (ch == '"') sb.Append("&quot;");
            else if (ch == '\t' || ch == '\n') sb.Append(ch);
            else if (ch == '\r') sb.Append("&#13;");
            else if (ch < 0x20 || ch == 0xFFFE || ch == 0xFFFF) sb.Append('?');
            else if (char.IsHighSurrogate(ch))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(ch); sb.Append(s[i + 1]); i++; } else sb.Append('?');
            }
            else if (char.IsLowSurrogate(ch)) sb.Append('?');
            else sb.Append(ch);
        }
    }

    private static void AppendCell(StringBuilder sb, string refName, Cell c, int style)
    {
        if (c.Kind == 0) return;
        if (c.Kind == 1) { sb.Append("<c r=\"").Append(refName).Append("\"><v>").Append(c.Text).Append("</v></c>"); return; }
        sb.Append("<c r=\"").Append(refName).Append("\" t=\"inlineStr\"");
        if (style != 0) sb.Append(" s=\"").Append(style).Append("\"");
        sb.Append("><is><t xml:space=\"preserve\">");
        XmlText(sb, c.Text);
        sb.Append("</t></is></c>");
    }

    private static void AddText(ZipArchive zip, string name, string text)
    {
        ZipArchiveEntry e = zip.CreateEntry(name, CompressionLevel.Optimal);
        using (Stream s = e.Open()) { byte[] b = new UTF8Encoding(false).GetBytes(text); s.Write(b, 0, b.Length); }
    }

    private const string Decl = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

    public static long WriteXlsx(IEnumerable rows, string path)
    {
        long n = 0;
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create, false, new UTF8Encoding(false)))
        {
            AddText(zip, "[Content_Types].xml", Decl +
                "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
                "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
                "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
                "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
                "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>" +
                "<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>" +
                "</Types>");
            AddText(zip, "_rels/.rels", Decl +
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
                "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>" +
                "</Relationships>");
            AddText(zip, "xl/workbook.xml", Decl +
                "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
                "<sheets><sheet name=\"Tabelle\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>");
            AddText(zip, "xl/_rels/workbook.xml.rels", Decl +
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
                "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>" +
                "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>" +
                "</Relationships>");
            AddText(zip, "xl/styles.xml", Decl +
                "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">" +
                "<fonts count=\"2\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts>" +
                "<fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills>" +
                "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>" +
                "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>" +
                "<cellXfs count=\"2\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/></cellXfs>" +
                "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>" +
                "</styleSheet>");

            ZipArchiveEntry se = zip.CreateEntry("xl/worksheets/sheet1.xml", CompressionLevel.Optimal);
            int colCount = 0;
            using (StreamWriter w = new StreamWriter(se.Open(), new UTF8Encoding(false), 65536))
            {
                w.Write(Decl);
                w.Write("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">");
                Shape shape = null;
                StringBuilder sb = new StringBuilder();
                long rowNo = 0;
                foreach (object row in rows)
                {
                    if (row == null) continue;
                    if (shape == null)
                    {
                        shape = MakeShape(row);
                        colCount = shape.Cols.Count;
                        if (colCount > MaxXlsxColumns) throw new InvalidOperationException("Excel kann hoechstens 16384 Spalten.");
                        if (colCount > 0)
                        {
                            w.Write("<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>");
                            w.Write("<cols><col min=\"1\" max=\"" + colCount + "\" width=\"22\" customWidth=\"1\"/></cols>");
                        }
                        w.Write("<sheetData>");
                        sb.Length = 0;
                        sb.Append("<row r=\"1\">");
                        for (int i = 0; i < colCount; i++)
                        {
                            Cell h = new Cell(); h.Kind = 2; h.Text = Guard(Header(shape.Cols[i].Name));
                            if (h.Text.Length > 0) AppendCell(sb, ColName(i) + "1", h, 1);
                        }
                        sb.Append("</row>"); w.Write(sb.ToString());
                        rowNo = 1;
                    }
                    rowNo++;
                    if (rowNo > MaxXlsxRows) throw new InvalidOperationException("Excel kann hoechstens 1.048.575 Datenzeilen. Bitte als CSV speichern oder den Filter enger setzen.");
                    sb.Length = 0;
                    sb.Append("<row r=\"").Append(rowNo).Append("\">");
                    for (int i = 0; i < colCount; i++) AppendCell(sb, ColName(i) + rowNo, MakeCell(Get(shape, shape.Cols[i], row), CultureInfo.InvariantCulture), 0);
                    sb.Append("</row>"); w.Write(sb.ToString());
                    n++;
                }
                if (shape == null) w.Write("<sheetData>");
                w.Write("</sheetData>");
                if (shape != null && colCount > 0) w.Write("<autoFilter ref=\"A1:" + ColName(colCount - 1) + (n + 1) + "\"/>");
                w.Write("</worksheet>");
            }
        }
        return n;
    }
}
'@

function Initialize-SmExportEngine {
    <# Uebersetzt den C#-Teil einmal je Prozess. #>
    if (-not ('SmTable' -as [type])) {
        Add-Type -TypeDefinition $script:SmExportCSharp -Language CSharp -ErrorAction Stop -ReferencedAssemblies @([psobject].Assembly.Location, 'System.IO.Compression', 'System.IO.Compression.FileSystem')
    }
}

function Export-SmTable {
    <#
    .SYNOPSIS
        Schreibt Zeilen (Objekte oder Hashtables) als CSV oder xlsx. Die Endung von Path entscheidet. Liefert die Zahl der Datenzeilen.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]$Rows,   # object[] oder Aufzaehlung
        [Parameter(Mandatory)][string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Kein Dateipfad angegeben.' }
    $full = [IO.Path]::GetFullPath($Path)
    $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
    if ($ext -notin '.csv', '.xlsx') { throw 'Die Datei muss auf .csv oder .xlsx enden.' }
    $dir = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Der Ordner existiert nicht: $dir" }
    Initialize-SmExportEngine
    if ($null -eq $Rows) { $Rows = @() }
    $ok = $false
    try {
        $n = if ($ext -eq '.csv') { [SmTable]::WriteCsv($Rows, $full, [char]';') } else { [SmTable]::WriteXlsx($Rows, $full) }
        $ok = $true
        $n
    }
    finally { if (-not $ok) { Remove-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue } }
}
