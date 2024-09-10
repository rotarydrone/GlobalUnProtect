using System;
using System.Collections.Generic;
using System.IO;

namespace GlobalUnProtect.Utilities
{
    public class ConfigFinder
    {
        public static List<string> Search()
        {
            string[] possiblePaths = new string[]
            {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Palo Alto Networks", "GlobalProtect"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Palo Alto Networks", "GlobalProtect")
            };

            // check to see if either/both paths exists
            List<string> globalprotectPaths = new List<string>();
            foreach (string dir in possiblePaths)
            {
                if (Directory.Exists(dir))
                {
                    globalprotectPaths.Add(dir);
                }
            }

            // if none were found, we're done here
            if (globalprotectPaths.Count < 1)
            {
                Console.WriteLine("[-] No GlobalProtect profile paths were found, nothing to do.");
            }

            // find the .dat files in any found directory
            List<string> datFiles = new List<string>();
            foreach (string dir in globalprotectPaths)
            {
                string[] foundFiles = Directory.GetFiles(dir, "*.dat", SearchOption.TopDirectoryOnly);
                if (foundFiles.Length > 0)
                {
                    datFiles.AddRange(foundFiles);
                }
            }

            if (datFiles.Count < 1)
            {
                Console.WriteLine("[-] No .dat files found in GlobalProtect paths, nothing to do.");
            }

            return datFiles;
        }

    }
}
