using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace GlobalUnProtect.Utilities
{
    public class KeyDerivation
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private enum POLICY_INFORMATION_CLASS
        {
            PolicyAccountDomainInformation = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POLICY_ACCOUNT_DOMAIN_INFO
        {
            public LSA_UNICODE_STRING DomainName;
            public IntPtr DomainSid;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint LsaQueryInformationPolicy(
            IntPtr PolicyHandle,
            POLICY_INFORMATION_CLASS InformationClass,
            out IntPtr Buffer
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;

        private static bool NT_SUCCESS(uint status)
        {
            return status >= 0;
        }

        public static byte[] GetComputerSID()
        {
            LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
            IntPtr policyHandle;

            LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();

            uint status = LsaOpenPolicy(ref systemName, ref objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, out policyHandle);
            if (!NT_SUCCESS(status))
            {
                throw new Exception($"LsaOpenPolicy failed: 0x{LsaNtStatusToWinError(status):X}");
            }

            IntPtr accountDomainInfoPtr;
            status = LsaQueryInformationPolicy(policyHandle, POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation, out accountDomainInfoPtr);
            if (!NT_SUCCESS(status))
            {
                LsaClose(policyHandle);
                throw new Exception($"LsaQueryInformationPolicy failed: 0x{LsaNtStatusToWinError(status):X}");
            }

            POLICY_ACCOUNT_DOMAIN_INFO accountDomainInfo = Marshal.PtrToStructure<POLICY_ACCOUNT_DOMAIN_INFO>(accountDomainInfoPtr);

            SecurityIdentifier sid = new SecurityIdentifier(accountDomainInfo.DomainSid);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            LsaFreeMemory(accountDomainInfoPtr);
            LsaClose(policyHandle);

            StringBuilder sidString = new StringBuilder(sidBytes.Length * 2);

            foreach (byte b in sidBytes)
            {
                sidString.Append(b.ToString("X2"));
            }

            Console.WriteLine($"\t[*] Computer SID (Hex) : {sidString}");

            return sidBytes;
        }

        private static byte[] GetMD5Hash(byte[] input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(input);
                return hashBytes;

            }
        }

        private static byte[] ConcatByteArrays(params byte[][] arrays)
        {
            return arrays.SelectMany(x => x).ToArray();
        }

        private static string BytesToString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();

        }

        public static byte[] GetKey()
        {
            Console.WriteLine($"[*] Deriving AES key from computer SID");

            byte[] panMD5 = GetMD5Hash(Encoding.ASCII.GetBytes("pannetwork"));
            byte[] sidBytes = GetComputerSID();
            byte[] combinedBytes = ConcatByteArrays(sidBytes, panMD5);

            byte[] md5Key = GetMD5Hash(combinedBytes);
            byte[] finalKey = ConcatByteArrays(md5Key, md5Key);

            Console.WriteLine($"\t[*] Derived AES Key: {BytesToString(finalKey)}");

            return finalKey;
        }

    }
}
