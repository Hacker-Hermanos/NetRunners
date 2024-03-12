using System;
using System.IO;
using System.Security.Cryptography;

namespace NetRunners.Decryptors
{
    /// <summary>
    /// This class includes decryption routines to be used by runners when decrypting the payload at runtime.
    /// CaesarKey is retrieved from Shellcode class
    /// </summary>
    public static class Decryptors
    {
        /// <summary>
        /// This Function Takes in an AES Encrypted Buffer and The Key/IV Used in Encryption and Returns The Decrypted Buffer
        /// </summary>
        /// <param name="EncryptedBytes"></param>
        /// <param name="AesKey"></param>
        /// <param name="AesIV"></param>
        /// <returns>The Decrypted Data</returns>
        public static byte[] DecryptBytesToBytes_Aes(byte[] EncryptedBufferWithIV, byte[] AesKey, byte[] AesIV)
        {

            Array.Copy(EncryptedBufferWithIV, 0, AesIV, 0, AesIV.Length);

            // The actual encrypted data starts after the IV
            byte[] EncryptedBuffer = new byte[EncryptedBufferWithIV.Length - AesIV.Length];
            Array.Copy(EncryptedBufferWithIV, AesIV.Length, EncryptedBuffer, 0, EncryptedBuffer.Length);

            using (AesManaged aes = new AesManaged())
            {
                aes.Key = AesKey;
                aes.IV = AesIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7; // This should match the padding used in encryption

                ICryptoTransform aes_decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream Encryptedms = new MemoryStream(EncryptedBuffer))
                {
                    using (MemoryStream Decryptedms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(Encryptedms, aes_decryptor, CryptoStreamMode.Read))
                        {
                            cs.CopyTo(Decryptedms);
                        }

                        byte[] decrypted_buff = Decryptedms.ToArray();
                        return decrypted_buff;
                    }
                }
            }
        }
    }
}
