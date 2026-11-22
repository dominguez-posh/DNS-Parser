<#
.SYNOPSIS
    DNS-Debug-Log: schneller Parser und Auswertung (Clients, DNS-Server-Erkennung, Fehler, Namen, Zonen, Typen, Updates/Notify, Rohdaten, CSV).
.DESCRIPTION
    Wird per Dot-Source geladen. Der Parser ist in C# geschrieben (Add-Type, kompiliert beim ersten Aufruf), damit 500 MB Log in
    wenigen Minuten verarbeitet werden: Streaming mit StreamReader, ein kompiliertes Regex, keine Arrays mit +=, keine Ausgabe je Zeile.
    Das Datum wird per Formatangabe (aus der Metadatei des Servers) gelesen, sonst automatisch erkannt (dd.MM.yyyy, M/d/yyyy,
    yyyy-MM-dd, mit und ohne AM/PM). Daten aus dem Tauschordner gelten als feindlich: Groessenlimits, ZIP-Inhalt nur als Leaf-Namen
    (es wird nie nach Eintragsnamen entpackt, die Eintraege werden direkt gelesen), JSON nur als Daten, CSV ohne Formel-Injection.
    Windows PowerShell 5.1. Datei bleibt ASCII.
#>

$script:SmDnsLimits = @{
    MaxZipEntries = 50
    MaxLogBytes   = 4GB      # je Log (entpackt, wird beim Lesen erzwungen, nicht nur aus der Angabe im ZIP)
    MaxTotalBytes = 6GB      # alle Logs zusammen
    MaxMetaBytes  = 2MB
    MaxZipBytes   = 2GB      # Groesse der ZIP-Datei selbst
    MaxRows       = 12000000 # Zeilen im Speicher (je ca. 40 Byte)
}

$script:SmDnsCSharp = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

public interface ISmDnsItem { string SearchText(); }

public sealed class SmDnsTable
{
    private readonly List<string> items = new List<string>();
    private readonly Dictionary<string, int> map = new Dictionary<string, int>();
    private readonly int max;
    public SmDnsTable(int max, string first) { this.max = max; items.Add(first); }
    public int Count { get { return items.Count; } }
    public string this[int i] { get { return items[i]; } }
    public int Intern(string s)
    {
        int id;
        if (map.TryGetValue(s, out id)) return id;
        if (items.Count >= max) return 0;
        id = items.Count; items.Add(s); map[s] = id; return id;
    }
    public int Find(string s) { int id; return map.TryGetValue(s, out id) ? id : -1; }
}

public struct SmDnsRow
{
    public long Ticks; public ulong Context; public int Ip; public int Name; public int Thread;
    public ushort Xid; public ushort FlagsHex; public byte Type; public byte Op; public byte Rcode; public byte Bits;
}

public sealed class SmDnsRows
{
    private const int Shift = 16; private const int Size = 1 << 16; private const int Mask = Size - 1;
    private readonly List<SmDnsRow[]> chunks = new List<SmDnsRow[]>();
    private long count;
    public long Count { get { return count; } }
    public void Add(SmDnsRow r)
    {
        int c = (int)(count >> Shift);
        if (c == chunks.Count) chunks.Add(new SmDnsRow[Size]);
        chunks[c][(int)(count & Mask)] = r; count++;
    }
    public void Each(Action<SmDnsRow> a)
    {
        long left = count;
        for (int c = 0; c < chunks.Count && left > 0; c++)
        {
            SmDnsRow[] ch = chunks[c]; int n = (int)Math.Min(left, (long)Size);
            for (int j = 0; j < n; j++) a(ch[j]);
            left -= n;
        }
    }
    public IEnumerable<SmDnsRow> All()
    {
        long left = count;
        for (int c = 0; c < chunks.Count && left > 0; c++)
        {
            SmDnsRow[] ch = chunks[c]; int n = (int)Math.Min(left, (long)Size);
            for (int j = 0; j < n; j++) yield return ch[j];
            left -= n;
        }
    }
}

public sealed class SmLimitStream : Stream
{
    private readonly Stream inner; private readonly long limit; private long read;
    public SmLimitStream(Stream inner, long limit) { this.inner = inner; this.limit = limit; }
    public override int Read(byte[] buffer, int offset, int count)
    {
        int n = inner.Read(buffer, offset, count);
        read += n;
        if (read > limit) throw new InvalidDataException("Eintrag ist entpackt groesser als das Limit.");
        return n;
    }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override void Flush() { }
    public override long Seek(long o, SeekOrigin so) { throw new NotSupportedException(); }
    public override void SetLength(long v) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}

public static class SmCsv
{
    // Formel-Injection (Checkliste 7): Zellen, die mit = + - @ Tab oder CR beginnen, bekommen ein einfaches Anfuehrungszeichen davor.
    public static string Escape(string s, char delim)
    {
        if (string.IsNullOrEmpty(s)) return "";
        char c = s[0];
        if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r') s = "'" + s;
        if (s.IndexOf(delim) >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\r') >= 0 || s.IndexOf('\n') >= 0)
            s = "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
    public static string Header(string name)
    {
        return Regex.Replace(name, "(?<=[a-z])(?=[A-Z])", " ");
    }
    public static string Value(object v, char delim)
    {
        if (v == null) return "";
        string s = v as string;
        if (s != null) return Escape(s, delim);
        IFormattable f = v as IFormattable;
        if (f != null) return Quote(f.ToString(null, delim == ';' ? CultureInfo.CurrentCulture : CultureInfo.InvariantCulture), delim);   // Zahlen und Zeiten: keine Formel
        return Escape(v.ToString(), delim);
    }
    private static string Quote(string s, char delim)
    {
        if (s.IndexOf(delim) >= 0 || s.IndexOf('"') >= 0 || s.IndexOf((char)13) >= 0 || s.IndexOf((char)10) >= 0) s = "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
    public static long Write(IEnumerable items, string path, char delim)
    {
        long n = 0;
        PropertyInfo[] props = null;
        using (StreamWriter w = new StreamWriter(path, false, new UTF8Encoding(true), 65536))
        {
            foreach (object it in items)
            {
                if (props == null)
                {
                    props = it.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);
                    StringBuilder h = new StringBuilder();
                    for (int i = 0; i < props.Length; i++) { if (i > 0) h.Append(delim); h.Append(Escape(Header(props[i].Name), delim)); }
                    w.Write(h.ToString()); w.Write("\r\n");
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < props.Length; i++)
                {
                    if (i > 0) sb.Append(delim);
                    sb.Append(Value(props[i].GetValue(it, null), delim));
                }
                w.Write(sb.ToString()); w.Write("\r\n");
                n++;
            }
            if (props == null) w.Write("\r\n");
        }
        return n;
    }
}

public sealed class SmClientStat : ISmDnsItem
{
    public string Ip { get; set; }
    public string Name { get; set; }
    public string Rolle { get; set; }
    public long Anzahl { get; set; }
    public string ErsteAnfrage { get; set; }
    public string LetzteAnfrage { get; set; }
    public int Namen { get; set; }
    public string TopNamen { get; set; }
    public int Updates { get; set; }
    public string Hinweis { get; set; }
    public string SearchText() { return (Ip + " " + Name + " " + Rolle + " " + TopNamen + " " + Hinweis).ToLowerInvariant(); }
}

public sealed class SmErrorStat : ISmDnsItem
{
    public string Antwort { get; set; }
    public string Name { get; set; }
    public string Client { get; set; }
    public string Typ { get; set; }
    public long Anzahl { get; set; }
    public string Erste { get; set; }
    public string Letzte { get; set; }
    public string SearchText() { return (Antwort + " " + Name + " " + Client + " " + Typ).ToLowerInvariant(); }
}

public sealed class SmNameStat : ISmDnsItem
{
    public string Name { get; set; }
    public string Zone { get; set; }
    public long Anzahl { get; set; }
    public int Clients { get; set; }
    public string Typen { get; set; }
    public string Erste { get; set; }
    public string Letzte { get; set; }
    public string SearchText() { return (Name + " " + Zone + " " + Typen).ToLowerInvariant(); }
}

public sealed class SmZoneStat : ISmDnsItem
{
    public string Zone { get; set; }
    public string Herkunft { get; set; }
    public long Anzahl { get; set; }
    public int Namen { get; set; }
    public int Clients { get; set; }
    public string SearchText() { return (Zone + " " + Herkunft).ToLowerInvariant(); }
}

public sealed class SmTypeStat : ISmDnsItem
{
    public string Typ { get; set; }
    public long Anzahl { get; set; }
    public double AnteilProzent { get; set; }
    public string SearchText() { return Typ.ToLowerInvariant(); }
}

public sealed class SmUpdateStat : ISmDnsItem
{
    public string Art { get; set; }
    public string Client { get; set; }
    public string Name { get; set; }
    public long Anzahl { get; set; }
    public long Fehlerantworten { get; set; }
    public string Erste { get; set; }
    public string Letzte { get; set; }
    public string SearchText() { return (Art + " " + Client + " " + Name).ToLowerInvariant(); }
}

public sealed class SmRawRow : ISmDnsItem
{
    public string Zeit { get; set; }
    public string Richtung { get; set; }
    public string Protokoll { get; set; }
    public string Ip { get; set; }
    public string Art { get; set; }
    public string Opcode { get; set; }
    public string Flags { get; set; }
    public string FlagsHex { get; set; }
    public string Rcode { get; set; }
    public string Typ { get; set; }
    public string Name { get; set; }
    public string Xid { get; set; }
    public string Thread { get; set; }
    public string Kontext { get; set; }
    public string SearchText() { return (Ip + " " + Name + " " + Typ + " " + Rcode + " " + Opcode + " " + Richtung + " " + Protokoll + " " + Art).ToLowerInvariant(); }
}

public sealed class SmDnsViewResult { public IList Items; public long Total; public bool Cut; }

public struct SmK3 : IEquatable<SmK3>
{
    public int A, B, C;
    public SmK3(int a, int b, int c) { A = a; B = b; C = c; }
    public bool Equals(SmK3 o) { return A == o.A && B == o.B && C == o.C; }
    public override bool Equals(object o) { return o is SmK3 && Equals((SmK3)o); }
    public override int GetHashCode() { unchecked { return (A * 397 ^ B) * 397 ^ C; } }
}

public sealed class SmDnsLog
{
    private const int MaxLine = 4096;
    private const int SampleSize = 3000;
    private const byte BitTcp = 1, BitSnd = 2, BitResp = 4;
    private static readonly Regex Rx = new Regex(
        @"^\s*(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})\s+(\d{1,2}:\d{2}:\d{2})(?:\s*([AaPp]\.?[Mm]\.?))?\s+([0-9A-Fa-f]+)\s+PACKET\s+([0-9A-Fa-f]+)\s+(UDP|TCP)\s+(Snd|Rcv)\s+([0-9A-Fa-f:.%]+)\s+([0-9A-Fa-f]{4})\s+(R)?\s*([A-Z?])\s+\[([0-9A-Fa-f]{4})\s+([A-Za-z ]*?)\s*([A-Za-z0-9_]+)\s*\]\s+(\S+)\s+(\S.*?)\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public readonly SmDnsTable Ips = new SmDnsTable(int.MaxValue, "");
    public readonly SmDnsTable Names = new SmDnsTable(int.MaxValue, "");
    public readonly SmDnsTable Types = new SmDnsTable(255, "(andere)");
    public readonly SmDnsTable Rcodes = new SmDnsTable(255, "(andere)");
    public readonly SmDnsRows Rows = new SmDnsRows();
    public long MaxRows = 12000000;
    public long Lines, Packets, Skipped, BytesDone, BytesTotal;
    public long MinTicks = long.MaxValue, MaxTicks = long.MinValue;
    public bool Truncated;
    public volatile bool Cancel;
    public string DetectedOrder = "";
    public readonly List<string> Sources = new List<string>();
    public readonly Dictionary<string, string> Known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, string> ReverseNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public readonly HashSet<string> Zones = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> rawNames = new Dictionary<string, int>();
    private readonly Dictionary<string, int> rawIps = new Dictionary<string, int>();
    private readonly Dictionary<string, long>[] dayCache = new Dictionary<string, long>[] { new Dictionary<string, long>(), new Dictionary<string, long>(), new Dictionary<string, long>() };
    private readonly Dictionary<string, object> cache = new Dictionary<string, object>();

    // Zustand je Datei
    private List<string> sample; private bool orderKnown; private string hint; private int ord; private bool stop;

    public static readonly string[] OrderNames = new string[] { "DMY", "MDY", "YMD" };

    public bool HasData { get { return MinTicks != long.MaxValue; } }
    public string FirstText { get { return HasData ? Fmt(MinTicks) : ""; } }
    public string LastText { get { return HasData ? Fmt(MaxTicks) : ""; } }
    public long RowCount { get { return Rows.Count; } }

    public static string Fmt(long ticks) { return new DateTime(ticks).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture); }

    public void Invalidate() { cache.Clear(); }

    private static string NormIp(string ip)
    {
        int p = ip.IndexOf('%'); if (p >= 0) ip = ip.Substring(0, p);
        return ip.Trim().ToLowerInvariant();
    }
    public void AddKnown(string ip, string label)
    {
        string k = NormIp(ip);
        if (k.Length == 0) return;
        if (!Known.ContainsKey(k)) Known[k] = label;
        Invalidate();
    }
    public void AddZone(string zone)
    {
        string z = (zone ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (z.Length > 0) Zones.Add(z);
        Invalidate();
    }
    public void SetReverse(string ip, string name) { ReverseNames[NormIp(ip)] = name; Invalidate(); }

    // ---------------------------------------------------------------- Namen
    private static string Clean(string s)
    {
        StringBuilder sb = null;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] < 0x20) { if (sb == null) { sb = new StringBuilder(s); } sb[i] = '?'; }
        }
        return sb == null ? s : sb.ToString();
    }
    // (3)www(7)contoso(3)com(0) -> www.contoso.com ; Laengen mit einer oder zwei Stellen
    public static string DecodeName(string raw)
    {
        if (raw == null) return "";
        int n = raw.Length;
        if (n == 0 || raw[0] != '(') return Clean(raw);
        StringBuilder sb = new StringBuilder(n);
        int i = 0; bool first = true;
        while (i < n)
        {
            if (raw[i] != '(') return Clean(raw);
            int close = raw.IndexOf(')', i + 1);
            int digits = close - i - 1;
            if (close < 0 || digits < 1 || digits > 3) return Clean(raw);
            int len = 0;
            for (int k = i + 1; k < close; k++) { char c = raw[k]; if (c < '0' || c > '9') return Clean(raw); len = len * 10 + (c - '0'); }
            i = close + 1;
            if (len == 0) break;
            int take = Math.Min(len, n - i);
            if (!first) sb.Append('.');
            sb.Append(raw, i, take);
            first = false;
            i += take;
        }
        if (sb.Length == 0) return ".";
        return Clean(sb.ToString());
    }

    // ---------------------------------------------------------------- Datum und Zeit
    private static long ParseDay(string s, int o)
    {
        int[] p = new int[3]; int pc = 0, cur = 0; bool inNum = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c >= '0' && c <= '9') { cur = cur * 10 + (c - '0'); inNum = true; if (cur > 100000) return -1; }
            else { if (!inNum || pc >= 3) return -1; p[pc++] = cur; cur = 0; inNum = false; }
        }
        if (inNum) { if (pc >= 3) return -1; p[pc++] = cur; }
        if (pc != 3) return -1;
        int d, m, y;
        if (o == 0) { d = p[0]; m = p[1]; y = p[2]; }
        else if (o == 1) { m = p[0]; d = p[1]; y = p[2]; }
        else { y = p[0]; m = p[1]; d = p[2]; }
        if (y < 100) y += 2000;
        if (y < 1990 || y > 2100 || m < 1 || m > 12 || d < 1 || d > DateTime.DaysInMonth(y, m)) return -1;
        return new DateTime(y, m, d).Ticks;
    }
    private long DayTicks(string date, int o)
    {
        long v; Dictionary<string, long> c = dayCache[o];
        if (c.TryGetValue(date, out v)) return v;
        v = ParseDay(date, o);
        if (c.Count > 20000) c.Clear();
        c[date] = v; return v;
    }
    private static long TimeTicks(string t, string ap)
    {
        int c1 = t.IndexOf(':'); if (c1 < 1) return -1;
        int c2 = t.IndexOf(':', c1 + 1); if (c2 < 0) return -1;
        int h = 0, m = 0, s = 0;
        for (int i = 0; i < c1; i++) h = h * 10 + (t[i] - '0');
        for (int i = c1 + 1; i < c2; i++) m = m * 10 + (t[i] - '0');
        for (int i = c2 + 1; i < t.Length; i++) s = s * 10 + (t[i] - '0');
        if (ap.Length > 0)
        {
            char a = char.ToUpperInvariant(ap[0]);
            if (h < 1 || h > 12) return -1;
            if (a == 'P') { if (h < 12) h += 12; } else { if (h == 12) h = 0; }
        }
        if (h > 23 || m > 59 || s > 59) return -1;
        return ((h * 60L + m) * 60L + s) * TimeSpan.TicksPerSecond;
    }
    private static int OrdFromHint(string h)
    {
        if (h == null) return -1;
        h = h.ToUpperInvariant();
        for (int i = 0; i < 3; i++) if (h == OrderNames[i]) return i;
        return -1;
    }

    private void Decide()
    {
        List<string> dates = new List<string>(sample.Count);
        foreach (string l in sample) { Match m = Rx.Match(l); if (m.Success) dates.Add(m.Groups[1].Value); }
        int[] valid = new int[3]; int[] back = new int[3];
        for (int o = 0; o < 3; o++)
        {
            long prev = -1;
            foreach (string d in dates)
            {
                long t = DayTicks(d, o); if (t < 0) continue;
                valid[o]++; if (prev >= 0 && t < prev) back[o]++; prev = t;
            }
        }
        int h = OrdFromHint(hint);
        int pick = -1;
        if (h >= 0 && dates.Count > 0 && valid[h] * 10 >= dates.Count * 9) pick = h;
        else
        {
            int bestValid = -1, bestBack = int.MaxValue; List<int> tied = new List<int>();
            for (int o = 0; o < 3; o++)
            {
                if (valid[o] > bestValid || (valid[o] == bestValid && back[o] < bestBack)) { bestValid = valid[o]; bestBack = back[o]; tied.Clear(); tied.Add(o); }
                else if (valid[o] == bestValid && back[o] == bestBack) tied.Add(o);
            }
            pick = tied[0];
            if (tied.Count > 1 && dates.Count > 0)
            {
                string d0 = dates[0]; int fp = 0; while (fp < d0.Length && char.IsDigit(d0[fp])) fp++;
                char sep = fp < d0.Length ? d0[fp] : '.';
                int pref = fp == 4 ? 2 : (sep == '/' ? 1 : 0);
                if (tied.Contains(pref)) pick = pref;
            }
        }
        ord = pick; DetectedOrder = OrderNames[pick]; orderKnown = true;
        List<string> s = sample; sample = new List<string>();
        foreach (string l in s) { Process(l); if (stop) break; }
    }

    // ---------------------------------------------------------------- Parser
    public void ParseFile(string path, string orderHint)
    {
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            ParseStream(fs, orderHint, fs.Length, Path.GetFileName(path));
    }

    public void ParseStream(Stream s, string orderHint, long totalBytes, string sourceName)
    {
        long l0 = Lines, p0 = Packets, k0 = Skipped, r0 = Rows.Count;
        BytesTotal += totalBytes;
        sample = new List<string>(); orderKnown = false; hint = orderHint; stop = false; ord = 0;
        using (StreamReader sr = new StreamReader(s, new UTF8Encoding(false), true, 1 << 16))
        {
            char[] buf = new char[1 << 16]; char[] line = new char[MaxLine]; int ll = 0; bool over = false; int n;
            while (!stop && (n = sr.Read(buf, 0, buf.Length)) > 0)
            {
                BytesDone += n;
                if (Cancel) throw new OperationCanceledException("Abgebrochen.");
                for (int i = 0; i < n; i++)
                {
                    char c = buf[i];
                    if (c == '\n')
                    {
                        if (over) { Lines++; Skipped++; } else Feed(new string(line, 0, ll));
                        ll = 0; over = false;
                        if (stop) break;
                    }
                    else if (c != '\r' && !over)
                    {
                        if (ll < MaxLine) line[ll++] = c; else over = true;
                    }
                }
            }
            if (!stop && ll > 0 && !over) Feed(new string(line, 0, ll));
        }
        if (!orderKnown && !stop) Decide();
        Invalidate();
        Sources.Add(string.Format(CultureInfo.InvariantCulture, "{0}: {1} Zeilen, {2} Pakete, {3} uebersprungen, Datum {4}", sourceName, Lines - l0, Rows.Count - r0, Skipped - k0, DetectedOrder));
        Packets = Rows.Count;
    }

    private void Feed(string l)
    {
        Lines++;
        if (l.Length < 40 || l.IndexOf(" PACKET ", StringComparison.Ordinal) < 0) return;
        if (!orderKnown) { sample.Add(l); if (sample.Count >= SampleSize) Decide(); return; }
        Process(l);
    }

    private static ulong HexU(string s)
    {
        if (s.Length > 16) return 0;
        ulong v = 0;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i]; int d = c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
            v = (v << 4) | (uint)d;
        }
        return v;
    }

    private void Process(string l)
    {
        Match m = Rx.Match(l);
        if (!m.Success) { Skipped++; return; }
        long day = DayTicks(m.Groups[1].Value, ord);
        if (day < 0) { Skipped++; return; }
        long tt = TimeTicks(m.Groups[2].Value, m.Groups[3].Value);
        if (tt < 0) { Skipped++; return; }
        if (Rows.Count >= MaxRows) { Truncated = true; stop = true; return; }
        long ticks = day + tt;
        if (ticks < MinTicks) MinTicks = ticks;
        if (ticks > MaxTicks) MaxTicks = ticks;
        SmDnsRow r = new SmDnsRow();
        r.Ticks = ticks;
        r.Thread = (int)HexU(m.Groups[4].Value);
        r.Context = HexU(m.Groups[5].Value);
        byte bits = 0;
        if (m.Groups[6].Value[0] == 'T') bits |= BitTcp;
        if (m.Groups[7].Value[0] == 'S') bits |= BitSnd;
        if (m.Groups[10].Success && m.Groups[10].Length > 0) bits |= BitResp;
        r.Bits = bits;
        string ipRaw = m.Groups[8].Value; int ip;
        if (!rawIps.TryGetValue(ipRaw, out ip)) { ip = Ips.Intern(NormIp(ipRaw)); rawIps[ipRaw] = ip; }
        r.Ip = ip;
        r.Xid = (ushort)HexU(m.Groups[9].Value);
        r.Op = (byte)m.Groups[11].Value[0];
        r.FlagsHex = (ushort)HexU(m.Groups[12].Value);
        r.Rcode = (byte)Rcodes.Intern(m.Groups[14].Value.ToUpperInvariant());
        r.Type = (byte)Types.Intern(m.Groups[15].Value.ToUpperInvariant());
        string nameRaw = m.Groups[16].Value; int nm;
        if (!rawNames.TryGetValue(nameRaw, out nm)) { nm = Names.Intern(DecodeName(nameRaw).ToLowerInvariant()); rawNames[nameRaw] = nm; }
        r.Name = nm;
        Rows.Add(r);
    }

    // ---------------------------------------------------------------- Auswertung
    private static string OpName(byte op)
    {
        switch ((char)op) { case 'Q': return "Query"; case 'N': return "Notify"; case 'U': return "Update"; case 'I': return "IQuery"; case 'S': return "Status"; default: return "Unknown"; }
    }
    private static string FlagChars(ushort f)
    {
        StringBuilder sb = new StringBuilder();
        // Windows schreibt die Kopfzeilen-Flags mit vertauschten Bytes: 0x0001 RD (D), 0x0002 TC (T), 0x0004 AA (A), 0x8000 RA (R), 0x0080 QR, Opcode in 0x0078
        if ((f & 0x0004) != 0) sb.Append('A'); if ((f & 0x0002) != 0) sb.Append('T'); if ((f & 0x0001) != 0) sb.Append('D'); if ((f & 0x8000) != 0) sb.Append('R');
        return sb.ToString();
    }
    private string Role(string ip, out string hintText)
    {
        string label;
        hintText = "";
        if (Known.TryGetValue(ip, out label))
        {
            hintText = label;
            return label.StartsWith("Dieser Server") ? "Dieser Server" : "DNS-Server (bekannt)";
        }
        if (ip == "::1" || ip.StartsWith("127.")) { hintText = "Loopback"; return "Dieser Server"; }
        return null;
    }

    private List<SmClientStat> BuildClients()
    {
        int ni = Ips.Count, nn = Names.Count;
        long[] cnt = new long[ni], first = new long[ni], last = new long[ni], rd0 = new long[ni], nsq = new long[ni];
        int[] distinct = new int[ni], upd = new int[ni], notif = new int[ni];
        for (int i = 0; i < ni; i++) { first[i] = long.MaxValue; last[i] = long.MinValue; }
        Dictionary<long, int> pairs = new Dictionary<long, int>();
        int tNs = Types.Find("NS"), tDs = Types.Find("DS"), tKey = Types.Find("DNSKEY");
        Rows.Each(delegate(SmDnsRow r)
        {
            if ((r.Bits & (BitSnd | BitResp)) != 0) return;   // nur eingehende Anfragen
            int ip = r.Ip;
            if (r.Ticks < first[ip]) first[ip] = r.Ticks;
            if (r.Ticks > last[ip]) last[ip] = r.Ticks;
            char op = (char)r.Op;
            if (op == 'U') { upd[ip]++; return; }
            if (op == 'N') { notif[ip]++; return; }
            cnt[ip]++;
            if ((r.FlagsHex & 0x0001) == 0) rd0[ip]++;   // Rekursion nicht gewuenscht: so fragen DNS-Server, die selbst aufloesen
            if (r.Type == tNs || r.Type == tDs || r.Type == tKey) nsq[ip]++;
            long key = ((long)ip << 32) | (uint)r.Name; int c;
            if (pairs.TryGetValue(key, out c)) pairs[key] = c + 1; else { pairs[key] = 1; distinct[ip]++; }
        });
        int[][] topN = new int[ni][]; int[][] topC = new int[ni][];
        foreach (KeyValuePair<long, int> kv in pairs)
        {
            int ip = (int)(kv.Key >> 32), name = (int)(kv.Key & 0xFFFFFFFFL), c = kv.Value;
            if (topN[ip] == null) { topN[ip] = new int[5]; topC[ip] = new int[5]; }
            int[] tn = topN[ip], tc = topC[ip];
            if (c <= tc[4]) continue;
            int p = 4; while (p > 0 && tc[p - 1] < c) { tn[p] = tn[p - 1]; tc[p] = tc[p - 1]; p--; }
            tn[p] = name; tc[p] = c;
        }
        List<SmClientStat> list = new List<SmClientStat>();
        for (int ip = 1; ip < ni; ip++)
        {
            if (cnt[ip] + upd[ip] + notif[ip] == 0) continue;
            string ipText = Ips[ip], hintText; string role = Role(ipText, out hintText); string rev;
            ReverseNames.TryGetValue(ipText, out rev);
            if (role == null)
            {
                List<string> why = new List<string>();
                if (notif[ip] > 0) why.Add("sendet Notify (" + notif[ip] + ")");
                if (rd0[ip] >= 20 && rd0[ip] * 10 >= cnt[ip] * 3) why.Add("rekursive Muster: " + rd0[ip] + " Anfragen ohne Rekursionswunsch");
                if (nsq[ip] >= 10) why.Add(nsq[ip] + " Anfragen nach NS/DS/DNSKEY");
                if (distinct[ip] >= 2000 && cnt[ip] >= 5000) why.Add(distinct[ip] + " verschiedene Namen");
                if (why.Count > 0) { role = "DNS-Server (vermutet)"; hintText = string.Join("; ", why.ToArray()); }
                else role = "Client";
            }
            StringBuilder top = new StringBuilder();
            if (topN[ip] != null)
                for (int k = 0; k < 5; k++) { if (topC[ip][k] == 0) break; if (top.Length > 0) top.Append("; "); top.Append(Names[topN[ip][k]]).Append(" (").Append(topC[ip][k]).Append(')'); }
            SmClientStat s = new SmClientStat();
            s.Ip = ipText; s.Name = rev ?? ""; s.Rolle = role; s.Anzahl = cnt[ip];
            s.ErsteAnfrage = Fmt(first[ip]); s.LetzteAnfrage = Fmt(last[ip]);
            s.Namen = distinct[ip]; s.TopNamen = top.ToString(); s.Updates = upd[ip]; s.Hinweis = hintText;
            list.Add(s);
        }
        list.Sort(delegate(SmClientStat a, SmClientStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
        return list;
    }

    private string ZoneOf(string name, out bool own)
    {
        own = false;
        string c = name;
        while (true)
        {
            if (Zones.Contains(c)) { own = true; return c; }
            int d = c.IndexOf('.'); if (d < 0) break;
            c = c.Substring(d + 1);
        }
        string[] labels = name.Split('.');
        if (labels.Length <= 2) return name;
        return labels[labels.Length - 2] + "." + labels[labels.Length - 1];
    }

    private void BuildNames(out List<SmNameStat> names, out List<SmZoneStat> zones, out List<SmTypeStat> types)
    {
        int nn = Names.Count, nt = Types.Count;
        long[] cnt = new long[nn], first = new long[nn], last = new long[nn], tcount = new long[nt];
        for (int i = 0; i < nn; i++) { first[i] = long.MaxValue; last[i] = long.MinValue; }
        HashSet<long> pairs = new HashSet<long>();
        int[] clients = new int[nn];
        Dictionary<long, int> nameType = new Dictionary<long, int>();
        long total = 0;
        Rows.Each(delegate(SmDnsRow r)
        {
            if ((r.Bits & (BitSnd | BitResp)) != 0 || r.Op != (byte)'Q') return;
            int nm = r.Name; cnt[nm]++; total++; tcount[r.Type]++;
            if (r.Ticks < first[nm]) first[nm] = r.Ticks;
            if (r.Ticks > last[nm]) last[nm] = r.Ticks;
            if (pairs.Add(((long)r.Ip << 32) | (uint)nm)) clients[nm]++;
            long key = ((long)nm << 8) | r.Type; int c;
            if (nameType.TryGetValue(key, out c)) nameType[key] = c + 1; else nameType[key] = 1;
        });
        // Typen je Name (die haeufigsten drei)
        string[] typeText = new string[nn];
        Dictionary<int, List<KeyValuePair<int, int>>> per = new Dictionary<int, List<KeyValuePair<int, int>>>();
        foreach (KeyValuePair<long, int> kv in nameType)
        {
            int nm = (int)(kv.Key >> 8), ty = (int)(kv.Key & 0xFF);
            List<KeyValuePair<int, int>> l; if (!per.TryGetValue(nm, out l)) { l = new List<KeyValuePair<int, int>>(); per[nm] = l; }
            l.Add(new KeyValuePair<int, int>(ty, kv.Value));
        }
        foreach (KeyValuePair<int, List<KeyValuePair<int, int>>> kv in per)
        {
            kv.Value.Sort(delegate(KeyValuePair<int, int> a, KeyValuePair<int, int> b) { return b.Value.CompareTo(a.Value); });
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < kv.Value.Count && i < 3; i++) { if (i > 0) sb.Append(", "); sb.Append(Types[kv.Value[i].Key]).Append(" (").Append(kv.Value[i].Value).Append(')'); }
            typeText[kv.Key] = sb.ToString();
        }
        names = new List<SmNameStat>();
        Dictionary<string, SmZoneStat> zs = new Dictionary<string, SmZoneStat>();
        Dictionary<string, HashSet<int>> zoneClients = new Dictionary<string, HashSet<int>>();
        string[] zoneOfName = new string[nn]; bool[] zoneOwn = new bool[nn];
        for (int nm = 1; nm < nn; nm++)
        {
            if (cnt[nm] == 0) continue;
            bool own; string z = ZoneOf(Names[nm], out own); zoneOfName[nm] = z; zoneOwn[nm] = own;
            SmNameStat s = new SmNameStat();
            s.Name = Names[nm]; s.Zone = z; s.Anzahl = cnt[nm]; s.Clients = clients[nm]; s.Typen = typeText[nm] ?? "";
            s.Erste = Fmt(first[nm]); s.Letzte = Fmt(last[nm]);
            names.Add(s);
            SmZoneStat zr; if (!zs.TryGetValue(z, out zr)) { zr = new SmZoneStat(); zr.Zone = z; zr.Herkunft = own ? "Zone dieses Servers" : "andere Zone"; zs[z] = zr; zoneClients[z] = new HashSet<int>(); }
            zr.Anzahl += cnt[nm]; zr.Namen++;
        }
        foreach (long key in pairs)
        {
            int nm = (int)(key & 0xFFFFFFFFL), ip = (int)(key >> 32);
            if (zoneOfName[nm] != null) zoneClients[zoneOfName[nm]].Add(ip);
        }
        foreach (KeyValuePair<string, SmZoneStat> kv in zs) kv.Value.Clients = zoneClients[kv.Key].Count;
        names.Sort(delegate(SmNameStat a, SmNameStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
        zones = new List<SmZoneStat>(zs.Values);
        zones.Sort(delegate(SmZoneStat a, SmZoneStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
        types = new List<SmTypeStat>();
        for (int t = 0; t < nt; t++)
        {
            if (tcount[t] == 0) continue;
            SmTypeStat s = new SmTypeStat(); s.Typ = Types[t]; s.Anzahl = tcount[t]; s.AnteilProzent = total == 0 ? 0 : Math.Round(100.0 * tcount[t] / total, 1);
            types.Add(s);
        }
        types.Sort(delegate(SmTypeStat a, SmTypeStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
    }

    private sealed class Acc { public long Count, Err, First = long.MaxValue, Last = long.MinValue; public int Type; }

    private List<SmErrorStat> BuildErrors()
    {
        int ok = Rcodes.Find("NOERROR");
        Dictionary<SmK3, Acc> d = new Dictionary<SmK3, Acc>();
        Rows.Each(delegate(SmDnsRow r)
        {
            if ((r.Bits & (BitSnd | BitResp)) != (BitSnd | BitResp) || r.Rcode == ok || r.Op != (byte)'Q') return;
            SmK3 k = new SmK3(r.Rcode, r.Name, r.Ip); Acc a;
            if (!d.TryGetValue(k, out a)) { a = new Acc(); d[k] = a; }
            a.Count++; a.Type = r.Type;
            if (r.Ticks < a.First) a.First = r.Ticks;
            if (r.Ticks > a.Last) a.Last = r.Ticks;
        });
        List<SmErrorStat> list = new List<SmErrorStat>(d.Count);
        foreach (KeyValuePair<SmK3, Acc> kv in d)
        {
            SmErrorStat s = new SmErrorStat();
            s.Antwort = Rcodes[kv.Key.A]; s.Name = Names[kv.Key.B]; s.Client = Ips[kv.Key.C]; s.Typ = Types[kv.Value.Type];
            s.Anzahl = kv.Value.Count; s.Erste = Fmt(kv.Value.First); s.Letzte = Fmt(kv.Value.Last);
            list.Add(s);
        }
        list.Sort(delegate(SmErrorStat a, SmErrorStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
        return list;
    }

    private List<SmUpdateStat> BuildUpdates()
    {
        int ok = Rcodes.Find("NOERROR");
        Dictionary<SmK3, Acc> d = new Dictionary<SmK3, Acc>();
        Rows.Each(delegate(SmDnsRow r)
        {
            if (r.Op != (byte)'U' && r.Op != (byte)'N') return;
            SmK3 k = new SmK3(r.Op, r.Name, r.Ip); Acc a;
            if (!d.TryGetValue(k, out a)) { a = new Acc(); d[k] = a; }
            if ((r.Bits & BitSnd) == 0 && (r.Bits & BitResp) == 0)
            {
                a.Count++;
                if (r.Ticks < a.First) a.First = r.Ticks;
                if (r.Ticks > a.Last) a.Last = r.Ticks;
            }
            else if ((r.Bits & (BitSnd | BitResp)) == (BitSnd | BitResp) && r.Rcode != ok) a.Err++;
        });
        List<SmUpdateStat> list = new List<SmUpdateStat>();
        foreach (KeyValuePair<SmK3, Acc> kv in d)
        {
            if (kv.Value.Count == 0) continue;
            SmUpdateStat s = new SmUpdateStat();
            s.Art = OpName((byte)kv.Key.A); s.Client = Ips[kv.Key.C]; s.Name = Names[kv.Key.B]; s.Anzahl = kv.Value.Count; s.Fehlerantworten = kv.Value.Err;
            s.Erste = Fmt(kv.Value.First); s.Letzte = Fmt(kv.Value.Last);
            list.Add(s);
        }
        list.Sort(delegate(SmUpdateStat a, SmUpdateStat b) { return b.Anzahl.CompareTo(a.Anzahl); });
        return list;
    }

    private IList Cached(string view)
    {
        object o;
        if (cache.TryGetValue(view, out o)) return (IList)o;
        IList res;
        switch (view)
        {
            case "Clients": res = BuildClients(); break;
            case "DnsServer":
                {
                    List<SmClientStat> all = (List<SmClientStat>)Cached("Clients"); List<SmClientStat> l = new List<SmClientStat>();
                    foreach (SmClientStat c in all) if (c.Rolle != "Client") l.Add(c);
                    res = l; break;
                }
            case "Fehler": res = BuildErrors(); break;
            case "Updates": res = BuildUpdates(); break;
            case "Namen": case "Zonen": case "Typen":
                {
                    List<SmNameStat> n; List<SmZoneStat> z; List<SmTypeStat> t; BuildNames(out n, out z, out t);
                    cache["Namen"] = n; cache["Zonen"] = z; cache["Typen"] = t; return (IList)cache[view];
                }
            default: throw new ArgumentException("Unbekannte Ansicht: " + view);
        }
        cache[view] = res; return res;
    }

    private static string[] Tokens(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return new string[0];
        return filter.ToLowerInvariant().Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
    }

    private SmRawRow ToRaw(SmDnsRow r)
    {
        SmRawRow s = new SmRawRow();
        s.Zeit = Fmt(r.Ticks); s.Richtung = (r.Bits & BitSnd) != 0 ? "Snd" : "Rcv"; s.Protokoll = (r.Bits & BitTcp) != 0 ? "TCP" : "UDP";
        s.Ip = Ips[r.Ip]; s.Art = (r.Bits & BitResp) != 0 ? "Antwort" : "Anfrage"; s.Opcode = OpName(r.Op); s.Flags = FlagChars(r.FlagsHex); s.FlagsHex = r.FlagsHex.ToString("X4", CultureInfo.InvariantCulture);
        s.Rcode = Rcodes[r.Rcode]; s.Typ = Types[r.Type]; s.Name = Names[r.Name];
        s.Xid = r.Xid.ToString("x4", CultureInfo.InvariantCulture); s.Thread = r.Thread.ToString("X", CultureInfo.InvariantCulture); s.Kontext = r.Context.ToString("X", CultureInfo.InvariantCulture);
        return s;
    }

    private IEnumerable<object> RawIter(string filter)
    {
        string[] tk = Tokens(filter);
        int T = tk.Length;
        bool[][] ipHit = new bool[T][], nameHit = new bool[T][], typeHit = new bool[T][], rcHit = new bool[T][];
        sbyte[][] fix = new sbyte[T][]; int[] xidTok = new int[T];
        for (int t = 0; t < T; t++)
        {
            ushort xv; xidTok[t] = (tk[t].Length == 4 && ushort.TryParse(tk[t], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out xv)) ? xv : -1;
            ipHit[t] = Hits(Ips, tk[t]); nameHit[t] = Hits(Names, tk[t]); typeHit[t] = Hits(Types, tk[t]); rcHit[t] = Hits(Rcodes, tk[t]);
            fix[t] = new sbyte[8 * 256];
        }
        foreach (SmDnsRow r in Rows.All())
        {
            bool okRow = true;
            for (int t = 0; t < T && okRow; t++)
            {
                if (ipHit[t][r.Ip] || nameHit[t][r.Name] || typeHit[t][r.Type] || rcHit[t][r.Rcode] || (xidTok[t] >= 0 && r.Xid == xidTok[t])) continue;
                int fk = (r.Bits & 7) * 256 + r.Op; sbyte v = fix[t][fk];
                if (v == 0)
                {
                    string st = (((r.Bits & BitSnd) != 0) ? "snd" : "rcv") + " " + (((r.Bits & BitTcp) != 0) ? "tcp" : "udp") + " " + (((r.Bits & BitResp) != 0) ? "antwort" : "anfrage") + " " + OpName(r.Op).ToLowerInvariant();
                    v = (sbyte)(st.Contains(tk[t]) ? 1 : -1); fix[t][fk] = v;
                }
                if (v < 0) okRow = false;
            }
            if (okRow) yield return ToRaw(r);
        }
    }
    private static bool[] Hits(SmDnsTable table, string token)
    {
        bool[] h = new bool[table.Count];
        for (int i = 0; i < h.Length; i++) h[i] = table[i].IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
        return h;
    }

    public static string[] Views = new string[] { "Clients", "DnsServer", "Fehler", "Namen", "Zonen", "Typen", "Updates", "Roh" };

    public IEnumerable<object> Query(string view, string filter)
    {
        if (view == "Roh") return RawIter(filter);
        return FilterItems(Cached(view), filter);
    }
    private static IEnumerable<object> FilterItems(IList items, string filter)
    {
        string[] tk = Tokens(filter);
        foreach (object o in items)
        {
            if (tk.Length > 0)
            {
                string s = ((ISmDnsItem)o).SearchText(); bool ok = true;
                foreach (string t in tk) if (s.IndexOf(t, StringComparison.Ordinal) < 0) { ok = false; break; }
                if (!ok) continue;
            }
            yield return o;
        }
    }
    private static Type ItemType(string view)
    {
        switch (view)
        {
            case "Clients": case "DnsServer": return typeof(SmClientStat);
            case "Fehler": return typeof(SmErrorStat);
            case "Namen": return typeof(SmNameStat);
            case "Zonen": return typeof(SmZoneStat);
            case "Typen": return typeof(SmTypeStat);
            case "Updates": return typeof(SmUpdateStat);
            case "Roh": return typeof(SmRawRow);
            default: throw new ArgumentException("Unbekannte Ansicht: " + view);
        }
    }
    // Eine Seite fuer die Anzeige (typisierte Liste, damit die Tabelle die Spalten findet). Total = alle Treffer.
    public SmDnsViewResult GetPage(string view, string filter, int limit)
    {
        IList list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(ItemType(view)));
        long total = 0;
        if (view == "Roh" && string.IsNullOrWhiteSpace(filter))
        {
            foreach (object o in RawIter("")) { list.Add(o); if (list.Count >= limit) break; }
            total = Rows.Count;
        }
        else
        {
            foreach (object o in Query(view, filter)) { total++; if (list.Count < limit) list.Add(o); }
        }
        SmDnsViewResult r = new SmDnsViewResult(); r.Items = list; r.Total = total; r.Cut = total > list.Count; return r;
    }
    public long Export(string view, string filter, string path, char delim)
    {
        return SmCsv.Write(Query(view, filter), path, delim);
    }
}
'@

function Initialize-SmDnsEngine {
    <# Uebersetzt den C#-Teil einmal je Prozess. Mehrere Runspaces teilen sich den Typ. #>
    if (-not ('SmDnsLog' -as [type])) {
        Add-Type -TypeDefinition $script:SmDnsCSharp -Language CSharp -ErrorAction Stop
    }
}

function New-SmDnsLog {
    param([long]$MaxRows = $script:SmDnsLimits.MaxRows)
    Initialize-SmDnsEngine
    $l = New-Object SmDnsLog
    $l.MaxRows = $MaxRows
    $l
}

function ConvertFrom-SmDnsName {
    <# (3)www(7)contoso(5)local(0) -> www.contoso.local #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Raw)
    Initialize-SmDnsEngine
    [SmDnsLog]::DecodeName($Raw)
}

function ConvertTo-SmDnsDateOrder {
    <# Reihenfolge von Tag, Monat, Jahr aus einem Datumsmuster (z. B. dd.MM.yyyy -> DMY). $null, wenn das Muster nicht passt. #>
    param([AllowNull()][AllowEmptyString()][string]$Pattern)
    if ([string]::IsNullOrWhiteSpace($Pattern) -or $Pattern.Length -gt 40) { return $null }
    $idx = @{}
    foreach ($c in 'd', 'M', 'y') { $i = $Pattern.IndexOf($c); if ($i -lt 0) { return $null }; $idx[$c] = $i }
    $o = ($idx.GetEnumerator() | Sort-Object Value | ForEach-Object { $_.Key }) -join ''
    switch ($o) { 'dMy' { 'DMY' } 'Mdy' { 'MDY' } 'yMd' { 'YMD' } 'ydM' { $null } default { $null } }
}

function ConvertFrom-SmDnsMeta {
    <#
    .SYNOPSIS
        Liest die Metadatei (JSON) des Servers nur als Daten. Jeder Wert wird geprueft und bereinigt, nichts wird ausgefuehrt oder uebernommen.
    #>
    param([Parameter(Mandatory)][string]$Json)
    if ($Json.Length -gt $script:SmDnsLimits.MaxMetaBytes) { throw 'Metadatei ist zu gross.' }
    $o = $Json | ConvertFrom-Json
    $text = { param($v, $max) if ($null -eq $v) { return '' }; $s = [string]$v; $s = $s -replace '[^\w .\-/:+()]', ''; if ($s.Length -gt $max) { $s.Substring(0, $max) } else { $s } }
    $ips = {
        param($v)
        foreach ($x in @($v)) {
            $addr = $null
            if ($null -ne $x -and ([string]$x).Length -le 64 -and ([string]$x) -match '[.:]' -and [ipaddress]::TryParse(([string]$x).Trim(), [ref]$addr)) { $addr.ToString() }
        }
    }
    $host_ = & $text $o.Server 63
    $meta = [ordered]@{
        Server       = $host_
        TimeZone     = & $text $o.TimeZone 80
        Culture      = & $text $o.Culture 20
        SystemLocale = & $text $o.SystemLocale 20
        DateFormat   = ''
        TimeFormat   = & $text $o.TimeFormat 30
        OwnIps       = @(& $ips $o.OwnIps)
        Forwarders   = @(& $ips $o.Forwarders)
        ConditionalForwarders = @()
        SecondaryServers      = @()
        DomainControllers     = @()
        Zones        = @()
    }
    $df = [string]$o.DateFormat
    if ($df -match '^[dMyHhmstT/.\- :,]{4,30}$') { $meta.DateFormat = $df }
    $meta.ConditionalForwarders = @(@($o.ConditionalForwarders) | Where-Object { $_ } | Select-Object -First 500 | ForEach-Object { [pscustomobject]@{ Zone = (& $text $_.Zone 253); Servers = @(& $ips $_.Servers) } })
    $meta.SecondaryServers = @(@($o.SecondaryServers) | Where-Object { $_ } | Select-Object -First 2000 | ForEach-Object { [pscustomobject]@{ Zone = (& $text $_.Zone 253); Servers = @(& $ips $_.Servers) } })
    $meta.DomainControllers = @(@($o.DomainControllers) | Where-Object { $_ } | Select-Object -First 500 | ForEach-Object { [pscustomobject]@{ Name = (& $text $_.Name 253); Ips = @(& $ips $_.Ips) } })
    $meta.Zones = @(@($o.Zones) | Where-Object { $_ } | Select-Object -First 5000 | ForEach-Object { [pscustomobject]@{ Name = (& $text $_.Name 253); Type = (& $text $_.Type 30) } })
    [pscustomobject]$meta
}

function Add-SmDnsMetaToLog {
    <# Traegt DCs, Forwarder, Sekundaerserver, eigene IPs und Zonen aus der Metadatei fuer die Server-Erkennung ein. #>
    param([Parameter(Mandatory)]$Log, [Parameter(Mandatory)]$Meta)
    $who = if ($Meta.Server) { $Meta.Server } else { 'unbekannt' }
    foreach ($ip in $Meta.OwnIps) { $Log.AddKnown($ip, "Dieser Server ($who), eigene IP") }
    foreach ($dc in $Meta.DomainControllers) { foreach ($ip in $dc.Ips) { $Log.AddKnown($ip, "Domaenencontroller $($dc.Name)") } }
    foreach ($ip in $Meta.Forwarders) { $Log.AddKnown($ip, "Forwarder von $who") }
    foreach ($cf in $Meta.ConditionalForwarders) { foreach ($ip in $cf.Servers) { $Log.AddKnown($ip, "Bedingter Forwarder ($($cf.Zone))") } }
    foreach ($sec in $Meta.SecondaryServers) { foreach ($ip in $sec.Servers) { $Log.AddKnown($ip, "Sekundaerserver ($($sec.Zone))") } }
    foreach ($z in $Meta.Zones) { if ($z.Name) { $Log.AddZone($z.Name) } }
}

function Import-SmDnsZip {
    <#
    .SYNOPSIS
        Liest ein DNS-ZIP (dns.log und meta.json) in ein SmDnsLog. Die Eintraege werden direkt aus dem ZIP gelesen, nie entpackt.
    .DESCRIPTION
        Nur Leaf-Namen, die der Whitelist entsprechen: *.log und meta.json. Eintraege in Unterordnern, mit Pfadanteilen oder
        fremden Namen werden uebersprungen. Limits (Anzahl, Groesse) werden beim Lesen erzwungen. Liefert Meta (oder $null) und Warnungen.
        Progress bekommt (BytesDone, BytesTotal).
    #>
    param([Parameter(Mandatory)]$Log, [Parameter(Mandatory)][string]$Path, [string]$DateFormat, [scriptblock]$Progress)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $lim = $script:SmDnsLimits
    $warn = New-Object System.Collections.Generic.List[string]
    $full = [IO.Path]::GetFullPath($Path)
    if ((Get-Item -LiteralPath $full).Length -gt $lim.MaxZipBytes) { throw 'Die ZIP-Datei ist zu gross.' }
    $zip = [IO.Compression.ZipFile]::OpenRead($full)
    $meta = $null
    try {
        if ($zip.Entries.Count -gt $lim.MaxZipEntries) { throw "Das ZIP hat zu viele Eintraege ($($zip.Entries.Count))." }
        $good = @()
        foreach ($e in $zip.Entries) {
            $leaf = $e.Name
            if (-not $leaf) { continue }                                     # Ordnereintrag
            if ($e.FullName -ne $leaf) { $warn.Add("Eintrag in Unterordner uebersprungen: $($e.FullName -replace '[^\w .\-/\\]', '?')"); continue }
            if ($leaf -notmatch '^[\w.\-]+$') { $warn.Add('Eintrag mit unerlaubtem Namen uebersprungen.'); continue }
            if ($leaf -ieq 'meta.json' -or $leaf -match '(?i)\.log$') { $good += $e } else { $warn.Add("Eintrag uebersprungen: $leaf") }
        }
        $metaEntry = $good | Where-Object { $_.Name -ieq 'meta.json' } | Select-Object -First 1
        if ($metaEntry) {
            if ($metaEntry.Length -gt $lim.MaxMetaBytes) { $warn.Add('meta.json ist zu gross und wurde nicht gelesen.') }
            else {
                $st = New-Object SmLimitStream -ArgumentList $metaEntry.Open(), $lim.MaxMetaBytes
                try {
                    $sr = New-Object IO.StreamReader($st, [Text.Encoding]::UTF8)
                    try { $json = $sr.ReadToEnd() } finally { $sr.Dispose() }
                    $meta = ConvertFrom-SmDnsMeta -Json $json
                    Add-SmDnsMetaToLog -Log $Log -Meta $meta
                }
                catch { $warn.Add('meta.json ist ungueltig und wurde nicht verwendet.'); $meta = $null }
                finally { $st.Dispose() }
            }
        }
        $order = ConvertTo-SmDnsDateOrder $DateFormat
        if (-not $order -and $meta) { $order = ConvertTo-SmDnsDateOrder $meta.DateFormat }
        $declared = ($good | Where-Object { $_.Name -match '(?i)\.log$' } | Measure-Object -Property Length -Sum).Sum
        if ($declared -gt $lim.MaxTotalBytes) { throw 'Die Logs im ZIP sind zusammen zu gross.' }
        foreach ($e in ($good | Where-Object { $_.Name -match '(?i)\.log$' })) {
            if ($e.Length -gt $lim.MaxLogBytes) { $warn.Add("Log zu gross, uebersprungen: $($e.Name)"); continue }
            $st = New-Object SmLimitStream -ArgumentList $e.Open(), $lim.MaxLogBytes
            try {
                Read-SmDnsStream -Log $Log -Stream $st -Length $e.Length -Order $order -Name $e.Name -Progress $Progress
            }
            finally { $st.Dispose() }
        }
    }
    finally { $zip.Dispose() }
    [pscustomobject]@{ Meta = $meta; Warnings = @($warn) }
}

function Read-SmDnsStream {
    param([Parameter(Mandatory)]$Log, [Parameter(Mandatory)][IO.Stream]$Stream, [long]$Length, [string]$Order, [string]$Name = 'stream', [scriptblock]$Progress)
    $Log.ParseStream($Stream, $Order, $Length, $Name)
}

function Add-SmDnsLogFile {
    <# Liest eine einzelne Log-Datei (lokal) in ein SmDnsLog. Order: DMY, MDY, YMD oder leer fuer Automatik. #>
    param([Parameter(Mandatory)]$Log, [Parameter(Mandatory)][string]$Path, [string]$Order)
    $full = [IO.Path]::GetFullPath($Path)
    if ((Get-Item -LiteralPath $full).Length -gt $script:SmDnsLimits.MaxLogBytes) { throw 'Die Log-Datei ist zu gross.' }
    $Log.ParseFile($full, $Order)
}

function Resolve-SmDnsReverse {
    <# Optional: Reverse-Namen fuer IPs, parallel mit Gesamtzeitlimit. Liefert IP -> Name. #>
    param([Parameter(Mandatory)][string[]]$Ips, [int]$TimeoutSec = 15)
    $tasks = @{}
    foreach ($ip in $Ips) {
        $a = $null
        if ([ipaddress]::TryParse($ip, [ref]$a)) { try { $tasks[$ip] = [Net.Dns]::GetHostEntryAsync($a) } catch { } }
    }
    try { [void][Threading.Tasks.Task]::WaitAll(@($tasks.Values | ForEach-Object { [Threading.Tasks.Task]$_ }), $TimeoutSec * 1000) } catch { }
    $res = @{}
    foreach ($k in $tasks.Keys) {
        $t = $tasks[$k]
        if ($t.Status -eq 'RanToCompletion' -and $t.Result.HostName) {
            $n = ([string]$t.Result.HostName) -replace '[^\w.\-]', ''
            if ($n.Length -gt 253) { $n = $n.Substring(0, 253) }
            if ($n -and $n -ne $k) { $res[$k] = $n }
        }
    }
    $res
}

function Export-SmCsv {
    <# Schreibt Objekte als CSV (UTF-8 mit BOM, Trenner ; fuer deutsches Excel). Texte, die mit = + - @ Tab oder CR beginnen, bekommen ein ' davor (Formel-Injection). #>
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string]$Path, [char]$Delimiter = ';')
    Initialize-SmDnsEngine
    $first = $Items | Select-Object -First 1
    $props = if ($first) { @($first.PSObject.Properties | ForEach-Object Name) } else { @() }
    $enc = New-Object Text.UTF8Encoding $true
    $w = New-Object IO.StreamWriter($Path, $false, $enc)
    $n = 0
    try {
        $w.Write((($props | ForEach-Object { [SmCsv]::Escape([SmCsv]::Header($_), $Delimiter) }) -join $Delimiter) + "`r`n")
        foreach ($it in $Items) {
            $w.Write((($props | ForEach-Object { [SmCsv]::Value($it.$_, $Delimiter) }) -join $Delimiter) + "`r`n")
            $n++
        }
    }
    finally { $w.Dispose() }
    $n
}

function Get-SmDnsCompatRows {
    <# Zeilen im Format des alten DNSParser.ps1 (gleiche Eigenschaften), damit alte Auswertungen weiter laufen. #>
    param([Parameter(Mandatory)]$Log)
    foreach ($r in $Log.Query('Roh', '')) {
        [pscustomobject]@{
            LogTime                  = [datetime]::ParseExact($r.Zeit, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
            TreadID                  = $r.Thread
            Context                  = 'PACKET'
            InternalPacketIdentifier = $r.Kontext
            TCPUDPIDENTIFIER         = $r.Protokoll
            SendReceiveIdentifier    = $r.Richtung
            RemoteIP                 = $r.Ip
            Xid                      = $r.Xid
            QueryOrRespond           = if ($r.Art -eq 'Antwort') { 'Respond' } else { 'Query' }
            Opcode                   = if ($r.Opcode -eq 'Query') { 'StandardQuery' } else { $r.Opcode }
            FlagsHex                 = $r.FlagsHex
            FlagsCharCodes           = $r.Flags
            Responsecode             = $r.Rcode
            QuestionType             = $r.Typ
            QuestionName             = $r.Name
        }
    }
}
