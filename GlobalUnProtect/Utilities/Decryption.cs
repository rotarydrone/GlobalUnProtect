using System.IO;
using System.Security.Cryptography;

namespace GlobalUnProtect.Utilities
{
    public class Decryption
    {

        public static byte[] DPAPIUnprotect(string filePath)
        {
            byte[] encryptedBytes = File.ReadAllBytes(filePath);
            byte[] decryptedBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.CurrentUser);
            return decryptedBytes;
        } 

        public static byte[] AESDecrypt(byte[] encrpyedBytes, byte[] aesKey)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = aesKey;
                aes.IV = new byte[16];

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream msDecrypt = new MemoryStream(encrpyedBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (MemoryStream msPlain = new MemoryStream())
                            {
                                csDecrypt.CopyTo(msPlain);
                                byte[] decryptedData = msPlain.ToArray();
                                return decryptedData;
                            }
                        }
                    }
                }
            }
        }
    }
}
