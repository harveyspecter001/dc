using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

namespace ProtoDump
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Uso:");
                Console.WriteLine("  ProtoDump.exe <Game.dll> <Google.Protobuf.dll> [filtro]");
                Console.WriteLine();
                Console.WriteLine("Ejemplos:");
                Console.WriteLine("  ProtoDump.exe Ankama.Dofus.Protocol.Game.dll Google.Protobuf.dll iso");
                Console.WriteLine("  ProtoDump.exe Ankama.Dofus.Protocol.Game.dll Google.Protobuf.dll --dump-descriptors iso");
                return 2;
            }

            var gameDll = args[0];
            var protobufDll = args[1];
            var dumpDescriptors = args.Skip(2).Any(a => string.Equals(a, "--dump-descriptors", StringComparison.OrdinalIgnoreCase));
            var targetMsg = args.Length >= 3 ? args[2] : null;
            if (dumpDescriptors && string.Equals(targetMsg, "--dump-descriptors", StringComparison.OrdinalIgnoreCase))
                targetMsg = args.Length >= 4 ? args[3] : null;

            if (!File.Exists(gameDll) || !File.Exists(protobufDll))
            {
                Console.WriteLine("DLL no encontrada.");
                Console.WriteLine("game: " + gameDll);
                Console.WriteLine("protobuf: " + protobufDll);
                return 3;
            }

            // Cargar Protobuf oficial primero.
            Assembly.LoadFrom(protobufDll);

            // Cargar dependencias cercanas (Ankama.*.dll) para evitar fallas en static ctors de Descriptors.
            try
            {
                var baseDir = Path.GetDirectoryName(gameDll) ?? "";
                if (Directory.Exists(baseDir))
                {
                    foreach (var dep in Directory.GetFiles(baseDir, "Ankama*.dll"))
                    {
                        try { Assembly.LoadFrom(dep); } catch { }
                    }
                }
            }
            catch { }

            var asm = Assembly.LoadFrom(gameDll);

            if (dumpDescriptors)
            {
                return DumpDescriptorsFromIl(asm, targetMsg);
            }

            Type iMessage = null;
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    var t = a.GetType("Google.Protobuf.IMessage", throwOnError: false);
                    if (t != null)
                    {
                        iMessage = t;
                        break;
                    }
                }
                catch { }
            }
            if (iMessage == null)
            {
                Console.WriteLine("No se pudo resolver Google.Protobuf.IMessage. ¿Google.Protobuf.dll correcto?");
                return 4;
            }

            var msgTypes = asm
                .GetTypes()
                .Where(t => t.IsClass && !t.IsAbstract && iMessage.IsAssignableFrom(t))
                .ToArray();

            Console.WriteLine("Assembly: " + asm.FullName);
            Console.WriteLine("IMessage types: " + msgTypes.Length);

            foreach (var t in msgTypes.OrderBy(t => t.FullName, StringComparer.Ordinal))
            {
                var descProp = t.GetProperty("Descriptor", BindingFlags.Public | BindingFlags.Static);
                if (descProp == null) continue;

                object descObj = null;
                try { descObj = descProp.GetValue(null); } catch { /* ignore */ }
                if (descObj == null) continue;

                var nameProp = descObj.GetType().GetProperty("Name", BindingFlags.Public | BindingFlags.Instance);
                var fullNameProp = descObj.GetType().GetProperty("FullName", BindingFlags.Public | BindingFlags.Instance);
                var fileProp = descObj.GetType().GetProperty("File", BindingFlags.Public | BindingFlags.Instance);

                var name = (nameProp != null ? (nameProp.GetValue(descObj) as string) : null) ?? "";
                var fullName = (fullNameProp != null ? (fullNameProp.GetValue(descObj) as string) : null) ?? "";

                if (!string.IsNullOrEmpty(targetMsg))
                {
                    var tm = targetMsg;
                    var ok = string.Equals(name, tm, StringComparison.OrdinalIgnoreCase)
                             || string.Equals(fullName, tm, StringComparison.OrdinalIgnoreCase)
                             || (name.IndexOf(tm, StringComparison.OrdinalIgnoreCase) >= 0)
                             || (fullName.IndexOf(tm, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!ok) continue;
                }

                Console.WriteLine();
                Console.WriteLine("=== Message: " + name + " (" + fullName + ") ===");
                Console.WriteLine("CLR: " + t.FullName);

                // Imprimir field numbers (const int).
                var constInts = t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                    .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(int))
                    .OrderBy(f => (int)f.GetRawConstantValue())
                    .ToArray();

                Console.WriteLine("FieldNumbers (const int):");
                foreach (var f in constInts)
                {
                    Console.WriteLine("  " + f.Name + " = " + f.GetRawConstantValue());
                }

                // Intentar imprimir info del FileDescriptor (nombre/paquete) si está disponible.
                try
                {
                    var fileObj = fileProp != null ? fileProp.GetValue(descObj) : null;
                    if (fileObj != null)
                    {
                        var fdNameProp = fileObj.GetType().GetProperty("Name");
                        var pkgProp = fileObj.GetType().GetProperty("Package");
                        Console.WriteLine("FileDescriptor:");
                        Console.WriteLine("  Name: " + (fdNameProp != null ? (fdNameProp.GetValue(fileObj) as string) : null));
                        Console.WriteLine("  Package: " + (pkgProp != null ? (pkgProp.GetValue(fileObj) as string) : null));
                    }
                }
                catch { }
            }

            return 0;
        }

        private static int DumpDescriptorsFromIl(Assembly asm, string filter)
        {
            Console.WriteLine("Modo: dump-descriptors (IL → FileDescriptorProto)");
            Console.WriteLine("Assembly: " + asm.FullName);

            var opcodeMap = BuildOpcodeMap();
            var hits = 0;
            var parsed = 0;

            foreach (var t in SafeGetTypes(asm))
            {
                var cctor = t.GetConstructor(BindingFlags.Static | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
                if (cctor == null) continue;
                byte[] il;
                try
                {
                    var body = cctor.GetMethodBody();
                    if (body == null) continue;
                    il = body.GetILAsByteArray();
                }
                catch { continue; }
                if (il == null || il.Length < 16) continue;

                // Extraer arrays de bytes construidos en el .cctor
                var arrays = ExtractStaticByteArraysFromCctorIl(il, cctor.Module, opcodeMap);
                if (arrays.Count == 0) continue;

                foreach (var kv in arrays)
                {
                    var fieldName = kv.Key;
                    var bytes = kv.Value;
                    if (bytes == null || bytes.Length < 64) continue;

                    // Filtrado rápido por ASCII si piden algo (ej: "iso")
                    if (!string.IsNullOrEmpty(filter))
                    {
                        var f = filter;
                        var ascii = System.Text.Encoding.ASCII.GetBytes(f);
                        if (IndexOf(bytes, ascii) < 0)
                        {
                            continue;
                        }
                    }

                    hits++;

                    // Intentar parsear como FileDescriptorProto
                    try
                    {
                        object fdObj;
                        if (!TryParseFileDescriptorProto(bytes, out fdObj))
                            continue;
                        parsed++;

                        var fdName = GetPropString(fdObj, "Name");
                        var fdPkg = GetPropString(fdObj, "Package");
                        var msgList = GetPropEnumerable(fdObj, "MessageType").ToArray();
                        var msgNames = msgList.Select(m => GetPropString(m, "Name")).ToArray();
                        if (!string.IsNullOrEmpty(filter))
                        {
                            if (!msgNames.Any(n => n != null && n.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0) &&
                                (fdName == null || fdName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) &&
                                (fdPkg == null || fdPkg.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0))
                            {
                                continue;
                            }
                        }

                        Console.WriteLine();
                        Console.WriteLine("=== FileDescriptorProto ===");
                        Console.WriteLine("Field: " + fieldName);
                        Console.WriteLine("Name: " + fdName);
                        Console.WriteLine("Package: " + fdPkg);
                        Console.WriteLine("Messages: " + string.Join(", ", msgNames.Take(24)) + (msgNames.Length > 24 ? ", ..." : ""));

                        // Si el filtro coincide con algún mensaje, volcar sus fields
                        foreach (var m in msgList)
                        {
                            if (string.IsNullOrEmpty(filter) ||
                                ((GetPropString(m, "Name") ?? "").IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0))
                            {
                                var mName = GetPropString(m, "Name");
                                Console.WriteLine("  - message " + mName);
                                var fields = GetPropEnumerable(m, "Field")
                                    .OrderBy(x => GetPropInt(x, "Number"));
                                foreach (var f in fields)
                                {
                                    var num = GetPropInt(f, "Number");
                                    var n = GetPropString(f, "Name");
                                    var typ = GetPropObj(f, "Type");
                                    var lab = GetPropObj(f, "Label");
                                    Console.WriteLine("      " + num + " " + n + " (Type=" + typ + ", Label=" + lab + ")");
                                }
                            }
                        }
                    }
                    catch
                    {
                        // no es descriptor proto
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("Candidatos (ASCII match): " + hits);
            Console.WriteLine("Parsed FileDescriptorProto: " + parsed);
            return 0;
        }

        private static IEnumerable<Type> SafeGetTypes(Assembly asm)
        {
            try { return asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { return ex.Types.Where(x => x != null); }
            catch { return new Type[0]; }
        }

        private static Dictionary<ushort, OpCode> BuildOpcodeMap()
        {
            var map = new Dictionary<ushort, OpCode>();
            foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (f.FieldType != typeof(OpCode)) continue;
                var op = (OpCode)f.GetValue(null);
                map[(ushort)op.Value] = op;
            }
            return map;
        }

        private static Dictionary<string, byte[]> ExtractStaticByteArraysFromCctorIl(byte[] il, Module module, Dictionary<ushort, OpCode> opcodeMap)
        {
            var result = new Dictionary<string, byte[]>();
            var stack = new Stack<object>();
            byte[] currentArray = null;

            int i = 0;
            while (i < il.Length)
            {
                OpCode op;
                ushort code = il[i++];
                if (code == 0xFE)
                {
                    if (i >= il.Length) break;
                    code = (ushort)(0xFE00 | il[i++]);
                }
                if (!opcodeMap.TryGetValue(code, out op))
                {
                    break;
                }

                object operand = null;
                int operandSize = 0;
                switch (op.OperandType)
                {
                    case OperandType.InlineNone:
                        break;
                    case OperandType.ShortInlineI:
                        operand = (sbyte)il[i];
                        operandSize = 1;
                        break;
                    case OperandType.InlineI:
                        operand = BitConverter.ToInt32(il, i);
                        operandSize = 4;
                        break;
                    case OperandType.InlineMethod:
                    case OperandType.InlineField:
                    case OperandType.InlineType:
                    case OperandType.InlineString:
                    case OperandType.InlineTok:
                        operand = BitConverter.ToInt32(il, i);
                        operandSize = 4;
                        break;
                    case OperandType.ShortInlineBrTarget:
                        operandSize = 1;
                        break;
                    case OperandType.InlineBrTarget:
                        operandSize = 4;
                        break;
                    case OperandType.ShortInlineVar:
                        operandSize = 1;
                        break;
                    case OperandType.InlineVar:
                        operandSize = 2;
                        break;
                    default:
                        // no soportado en este mini-parser
                        break;
                }
                i += operandSize;

                // Interpretar subset de IL para construir byte[]
                if (op == OpCodes.Ldstr)
                {
                    try
                    {
                        var s = module.ResolveString((int)operand);
                        stack.Push(s);
                    }
                    catch
                    {
                        stack.Push(null);
                    }
                }
                else if (op == OpCodes.Call || op == OpCodes.Callvirt)
                {
                    MethodBase mb = null;
                    try { mb = module.ResolveMethod((int)operand); } catch { }
                    if (mb != null)
                    {
                        var dt = mb.DeclaringType != null ? mb.DeclaringType.FullName : "";
                        var mn = mb.Name ?? "";
                        // Convert.FromBase64String(string)
                        if (dt == "System.Convert" && mn == "FromBase64String")
                        {
                            if (stack.Count >= 1)
                            {
                                var s = stack.Pop() as string;
                                try
                                {
                                    var b = s != null ? Convert.FromBase64String(s) : null;
                                    stack.Push(b);
                                }
                                catch
                                {
                                    stack.Push(null);
                                }
                            }
                        }
                    }
                }
                if (op == OpCodes.Ldc_I4_M1) stack.Push(-1);
                else if (op == OpCodes.Ldc_I4_0) stack.Push(0);
                else if (op == OpCodes.Ldc_I4_1) stack.Push(1);
                else if (op == OpCodes.Ldc_I4_2) stack.Push(2);
                else if (op == OpCodes.Ldc_I4_3) stack.Push(3);
                else if (op == OpCodes.Ldc_I4_4) stack.Push(4);
                else if (op == OpCodes.Ldc_I4_5) stack.Push(5);
                else if (op == OpCodes.Ldc_I4_6) stack.Push(6);
                else if (op == OpCodes.Ldc_I4_7) stack.Push(7);
                else if (op == OpCodes.Ldc_I4_8) stack.Push(8);
                else if (op == OpCodes.Ldc_I4_S) stack.Push((int)(sbyte)operand);
                else if (op == OpCodes.Ldc_I4) stack.Push((int)operand);
                else if (op == OpCodes.Newarr)
                {
                    // operand es token de tipo
                    int len = stack.Count > 0 ? Convert.ToInt32(stack.Pop()) : 0;
                    currentArray = new byte[Math.Max(0, len)];
                    stack.Push(currentArray);
                }
                else if (op == OpCodes.Dup)
                {
                    if (stack.Count > 0) stack.Push(stack.Peek());
                }
                else if (op == OpCodes.Stelem_I1)
                {
                    if (stack.Count < 3) continue;
                    int val = Convert.ToInt32(stack.Pop());
                    int idx = Convert.ToInt32(stack.Pop());
                    var arrObj = stack.Pop() as byte[];
                    if (arrObj != null && idx >= 0 && idx < arrObj.Length)
                    {
                        arrObj[idx] = (byte)(val & 0xFF);
                    }
                }
                else if (op == OpCodes.Stsfld)
                {
                    // operand es token field
                    if (stack.Count < 1) continue;
                    var arrObj = stack.Pop() as byte[];
                    if (arrObj == null) continue;
                    try
                    {
                        var f = module.ResolveField((int)operand);
                        var key = (f.DeclaringType != null ? f.DeclaringType.FullName : "?") + "::" + f.Name;
                        result[key] = arrObj;
                    }
                    catch { }
                }
            }

            return result;
        }

        private static int IndexOf(byte[] hay, byte[] needle)
        {
            if (hay == null || needle == null || needle.Length == 0 || hay.Length < needle.Length) return -1;
            for (int i = 0; i <= hay.Length - needle.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (hay[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }

        private static bool TryParseFileDescriptorProto(byte[] bytes, out object fdObj)
        {
            fdObj = null;
            try
            {
                var asm = AppDomain.CurrentDomain.GetAssemblies()
                    .FirstOrDefault(a => string.Equals(a.GetName().Name, "Google.Protobuf", StringComparison.OrdinalIgnoreCase));
                if (asm == null) return false;

                var fdType = asm.GetType("Google.Protobuf.Reflection.FileDescriptorProto", throwOnError: false);
                if (fdType == null) return false;

                var parserProp = fdType.GetProperty("Parser", BindingFlags.Public | BindingFlags.Static);
                var parser = parserProp != null ? parserProp.GetValue(null) : null;
                if (parser == null) return false;

                var parseFrom = parser.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .FirstOrDefault(m => m.Name == "ParseFrom" && m.GetParameters().Length == 1 && m.GetParameters()[0].ParameterType == typeof(byte[]));
                if (parseFrom == null) return false;

                fdObj = parseFrom.Invoke(parser, new object[] { bytes });
                return fdObj != null;
            }
            catch
            {
                return false;
            }
        }

        private static string GetPropString(object obj, string prop)
        {
            var v = GetPropObj(obj, prop);
            return v as string;
        }

        private static int GetPropInt(object obj, string prop)
        {
            var v = GetPropObj(obj, prop);
            if (v == null) return 0;
            return Convert.ToInt32(v);
        }

        private static object GetPropObj(object obj, string prop)
        {
            if (obj == null) return null;
            try
            {
                var p = obj.GetType().GetProperty(prop, BindingFlags.Public | BindingFlags.Instance);
                return p != null ? p.GetValue(obj) : null;
            }
            catch { return null; }
        }

        private static IEnumerable<object> GetPropEnumerable(object obj, string prop)
        {
            var v = GetPropObj(obj, prop) as System.Collections.IEnumerable;
            if (v == null) yield break;
            foreach (var x in v) yield return x;
        }
    }
}

