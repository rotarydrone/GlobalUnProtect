using Microsoft.Win32;

namespace GlobalUnProtect.Utilities
{
    internal class RegistryRead
    {
        public static string GetGPStringRegistryValue(string valueName)
        {
            string registryKeyPath = @"Software\Palo Alto Networks\GlobalProtect\Settings";

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryKeyPath))
            {
                if (key != null)
                {
                    object value = key.GetValue(valueName);
                    if (value != null && value is string)
                    {
                        return (string)value;
                    }
                    else
                    {
                        return "empty";
                    }
                }
                else
                {
                    return "empty";
                }
            }
        }
    }
}
