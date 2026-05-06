using System.Reflection;
using Google.Protobuf;
using Google.Protobuf.Reflection;

static string? GetArg(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    return null;
}

var asmPath = GetArg(args, "--asm")
             ?? @"C:\Users\fabia\Downloads\cpp2il_out_dofus_v39_il_full\Ankama.Dofus.Protocol.Game.dll";
var refDir = GetArg(args, "--refdir")
             ?? @"C:\Users\fabia\Downloads\cpp2il_out_dofus_v39_il_full";
var needle = GetArg(args, "--needle") ?? "iso";

Console.WriteLine("Loading: " + asmPath);
Console.WriteLine("RefDir: " + refDir);
Console.WriteLine("Needle: " + needle);

// Ensure dependencies resolve (Ankama.* / Google.Protobuf etc.)
AppDomain.CurrentDomain.AssemblyResolve += (_, e) =>
{
    try
    {
        var name = new AssemblyName(e.Name).Name;
        if (string.IsNullOrEmpty(name)) return null;
        var cand = Path.Combine(refDir, name + ".dll");
        if (File.Exists(cand))
            return Assembly.LoadFrom(cand);
    }
    catch { }
    return null;
};

var asm = Assembly.LoadFrom(asmPath);
var iMessage = typeof(IMessage);

var fileByName = new Dictionary<string, FileDescriptorProto>(StringComparer.OrdinalIgnoreCase);
var msgHits = new List<(string file, string pkg, string msg, List<(int num, string name, string label, string type, string typeName)> fields)>();

foreach (var t in asm.GetTypes())
{
    if (!t.IsClass || t.IsAbstract) continue;
    if (!iMessage.IsAssignableFrom(t)) continue;

    var descProp = t.GetProperty("Descriptor", BindingFlags.Public | BindingFlags.Static);
    if (descProp == null) continue;

    MessageDescriptor? md = null;
    try { md = descProp.GetValue(null) as MessageDescriptor; } catch { }
    if (md == null) continue;

    var fd = md.File;
    if (fd == null) continue;
    FileDescriptorProto? fdp = null;
    try { fdp = fd.ToProto(); } catch { }
    if (fdp == null) continue;
    var key = fdp.Name ?? "(unnamed)";
    if (!fileByName.ContainsKey(key))
        fileByName[key] = fdp;
}

Console.WriteLine("FileDescriptorProto unique: " + fileByName.Count);

foreach (var kv in fileByName.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
{
    var f = kv.Value;
    var fname = f.Name ?? "";
    var pkg = f.Package ?? "";
    foreach (var m in f.MessageType)
    {
        var mname = m.Name ?? "";
        var full = string.IsNullOrEmpty(pkg) ? mname : pkg + "." + mname;
        if (full.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0
            && mname.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0
            && fname.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0)
            continue;

        var fields = new List<(int, string, string, string, string)>();
        foreach (var fld in m.Field.OrderBy(x => x.Number))
        {
            fields.Add((
                fld.Number,
                fld.Name ?? "",
                fld.Label.ToString(),
                fld.Type.ToString(),
                fld.TypeName ?? ""
            ));
        }
        msgHits.Add((fname, pkg, full, fields));
    }
}

Console.WriteLine();
Console.WriteLine("=== Hits ===");
Console.WriteLine("Count: " + msgHits.Count);
foreach (var h in msgHits.Take(50))
{
    Console.WriteLine();
    Console.WriteLine("File: " + h.file);
    Console.WriteLine("Msg: " + h.msg);
    foreach (var f in h.fields)
    {
        var type = f.type + (string.IsNullOrEmpty(f.typeName) ? "" : (" " + f.typeName));
        Console.WriteLine($"  {f.num} {f.name} [{f.label}] {type}");
    }
}

