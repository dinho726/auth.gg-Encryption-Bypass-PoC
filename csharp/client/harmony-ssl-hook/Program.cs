using HarmonyLib;
using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace harmony_ssl_hook
{
    internal class Program
    {
        private static string AssemblyLoad = "";

        private static string sslKey = "3082010A0282010100ABDA0F3E94C51EDC5DC15E65D0DD98B6AC90EA1F712D1318A081700F5C06B50638456378F97D828D8A7CDFF6907D9A064E1182B62B16B3F4F8D125F8BA1279B42C18D7B14A3356E0F3E0907BBD1B287E33292260E5EBB8B050293AB11E63FEDEFDAFAA6A5DD15EF125832A20A5760BC76B6D10FD3DAAEFDC70924353D699A5C2DD8EF78D1AA5A9F9EFA7EDE7B8DBD893579B2A8EA87FCFF2F50D7E43F75EF8C9D0B01C5D1FB0E9C8E30FFA83AD5BE4A46BD7C707B2B027E5CAA96EF6386617186EFB22ACD2F1231228E75465546DE24C4D54032C3C44594CEC39302FCAD12AE784ACC73FD9E2D43A452A01ABF9ACCE8E124601DD11AFBF43089F636FDB730D270203010001";

        private static Random random = new Random();

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static bool IsDotNetAssembly(string path, out string reason)
        {
            reason = "";
            try
            {
                byte[] b = File.ReadAllBytes(path);
                if (b.Length < 0x40 || b[0] != 0x4D || b[1] != 0x5A) { reason = "Not a PE file (missing MZ)"; return false; }
                int pe = BitConverter.ToInt32(b, 0x3C);
                if (pe <= 0 || pe + 6 > b.Length) { reason = "Invalid PE offset"; return false; }
                if (b[pe] != 0x50 || b[pe + 1] != 0x45) { reason = "Missing PE signature"; return false; }
                ushort magic = BitConverter.ToUInt16(b, pe + 24);
                int ddOff = (magic == 0x20b) ? pe + 24 + 112 : pe + 24 + 96;
                if (ddOff + 14 * 8 + 8 > b.Length) { reason = "PE too small for data directories"; return false; }
                uint cliRva = BitConverter.ToUInt32(b, ddOff + 14 * 8);
                uint cliSize = BitConverter.ToUInt32(b, ddOff + 14 * 8 + 4);
                if (cliRva == 0 || cliSize == 0) { reason = "CLI header absent (native C++ / Qt / IL2CPP)"; return false; }
                // Also try AssemblyName to confirm manifest
                try { AssemblyName.GetAssemblyName(path); } catch (BadImageFormatException ex) { reason = "No assembly manifest: " + ex.Message; return false; }
                return true;
            }
            catch (Exception ex) { reason = ex.Message; return false; }
        }

        static void PrintNativeHelp(string path)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[!] This file is NOT a .NET assembly.");
            Console.WriteLine("    harmony-ssl-hook only works for C# (managed) auth.gg programs.");
            Console.ResetColor();
            Console.WriteLine($"\n    File: {path}");
            try
            {
                var fi = new FileInfo(path);
                Console.WriteLine($"    Size: {fi.Length / 1024 / 1024} MB  Arch: x64 (detected via PE header)");
            }
            catch { }
            Console.WriteLine("\n    Detected: native Qt/C++ (x64) - CLI header absent.");
            Console.WriteLine("\n    For C++ auth.gg programs, use the OTHER bypass:");
            Console.WriteLine("      1) Host cpp/index.php on a web server (or php -S localhost:80)");
            Console.WriteLine("      2) Redirect the auth.gg API domain to your server via:");
            Console.WriteLine("         - hosts file (C:\\Windows\\System32\\drivers\\etc\\hosts)");
            Console.WriteLine("         - or HTTP Debugger / Fiddler (Tools -> Hosts)");
            Console.WriteLine("         - or mitmproxy / Burp");
            Console.WriteLine("\n    The C++ server (cpp/index.php) expects:");
            Console.WriteLine("      POST a=start&e=KEY:IV  -> returns Enabled|Enabled|...");
            Console.WriteLine("      POST a=login&b=...&d=...&e=KEY:IV -> returns success|HWID|...");
            Console.WriteLine("\n    To find the real domain/IP:");
            Console.WriteLine("      - Run the program with HTTP Debugger / Fiddler / Wireshark");
            Console.WriteLine("      - Look for POST to api.auth.gg or similar, then add to hosts:");
            Console.WriteLine("        127.0.0.1  api.auth.gg");
            Console.WriteLine("\n    This native .exe cannot be loaded with Assembly.LoadFile.");
            Console.WriteLine("    If your target WAS supposed to be C#, verify you dragged the correct .exe");
            Console.WriteLine("    (some launchers are native wrappers that unpack a .NET DLL nearby).");
        }

        static void Main(string[] args)
        {
            // check if a valid file was dragged into application
            try
            {
                if (args.Length > 0) AssemblyLoad = args[0].Trim('"', '\'');
            }
            catch { }

            while (string.IsNullOrWhiteSpace(AssemblyLoad) || !File.Exists(AssemblyLoad) || new FileInfo(AssemblyLoad).Extension.ToLower() != ".exe")
            {
                try { Console.Clear(); } catch { }
                Console.WriteLine("Please provide a valid executable File [.EXE]: ");
                string input = Console.ReadLine();
                if (input != null) AssemblyLoad = input.Trim('"', '\'', ' ');
                if (string.IsNullOrWhiteSpace(AssemblyLoad)) continue;
                if (File.Exists(AssemblyLoad)) break;
                // also allow without extension check for drag-drop quirks
                string withQuote = AssemblyLoad.Trim();
                if (File.Exists(withQuote)) { AssemblyLoad = withQuote; break; }
            }
            AssemblyLoad = Path.GetFullPath(AssemblyLoad.Trim('"', '\'', ' '));
            try { Console.Clear(); } catch { }
            Console.WriteLine($"Target: {AssemblyLoad}");

            // pre-flight: is it .NET?
            string reason;
            if (!IsDotNetAssembly(AssemblyLoad, out reason))
            {
                PrintNativeHelp(AssemblyLoad);
                Console.WriteLine($"\n    Technical reason: {reason}");
                Console.WriteLine("\nPress ENTER to exit...");
                Console.ReadLine();
                return;
            }

            // load the file and patch it
            try
            {
                object[] parameters = null;
                var assembly = Assembly.LoadFile(AssemblyLoad);
                if (assembly.EntryPoint == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: Assembly has no EntryPoint (maybe a DLL, not an EXE).");
                    Console.ResetColor();
                    Console.ReadLine();
                    return;
                }
                var paraminfo = assembly.EntryPoint.GetParameters();
                parameters = new object[paraminfo.Length];
                Harmony patch = new Harmony(RandomString(15));
                patch.PatchAll(Assembly.GetExecutingAssembly());
                Console.WriteLine("Patch applied, invoking target...");
                assembly.EntryPoint.Invoke(null, parameters);
            }
            catch (BadImageFormatException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[BadImageFormatException] Could not load {AssemblyLoad}");
                Console.ResetColor();
                Console.WriteLine(ex.ToString());
                // 0x80131018 = no manifest, 0x8007000B = x86/x64 mismatch
                if (ex.HResult == unchecked((int)0x80131018))
                {
                    PrintNativeHelp(AssemblyLoad);
                }
                else if (ex.HResult == unchecked((int)0x8007000B))
                {
                    Console.WriteLine("\n[!] Architecture mismatch: you are running an x86 loader against an x64 .NET assembly (or vice-versa).");
                    Console.WriteLine("    Try the Release build (AnyCPU) or run the correct bitness build.");
                }
                else
                {
                    Console.WriteLine("\n[!] This usually means the target is native C++ or packed/obfuscated and not a plain .NET exe.");
                    PrintNativeHelp(AssemblyLoad);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not load {AssemblyLoad}\n{ex}");
            }

            Console.WriteLine("\nPress ENTER to exit...");
            Console.ReadLine();
        }

        [HarmonyPatch(typeof(System.Security.Cryptography.X509Certificates.X509Certificate), nameof(System.Security.Cryptography.X509Certificates.X509Certificate.GetPublicKeyString))]
        class X509Certificate
        {
            [STAThread]
            static bool Prefix(ref string __result)
            {
                Console.WriteLine("SSL key changed!");
                __result = sslKey;
                return false;
            }
        }
    }
}
