using System;
using System.IO;
using System.Security.Cryptography;

namespace NetRunners.Encryptor.EncryptionAlgorithms
{
    public static class Encryptor
    {
        // Generates an Initialization Vector (IV) for aes encryption
        public static byte[] GenerateIV_Aes()
        {
            try
            {
                using (AesManaged aesAlg = new AesManaged())
                {
                    aesAlg.GenerateIV();
                    byte[] IV = aesAlg.IV;

                    return IV;
                }
            }
            catch (Exception e)
            {
                throw new InvalidOperationException("Failed generating IV.", e);
            }
        }
        // Generates a valid aes key for aes encryption
        public static byte[] GenerateKey_Aes()
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[32];
                random.GetBytes(key);

                return key;
            }
        }
        // Aes Encrypt Byte Arrays
        public static byte[] EncryptBytesToBytes_Aes(byte[] plainBytes, byte[] AesKey, byte[] AesIV)
        {
            try
            {
                byte[] encrypted;

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = AesKey;
                    aesAlg.IV = AesIV;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            // Write all data to the stream.
                            csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                var combinedIvCt = new byte[AesIV.Length + encrypted.Length];
                Array.Copy(AesIV, 0, combinedIvCt, 0, AesIV.Length);
                Array.Copy(encrypted, 0, combinedIvCt, AesIV.Length, encrypted.Length);

                // Return the encrypted bytes from the memory stream.
                return combinedIvCt;
            }
            catch (Exception e)
            {

                throw new InvalidOperationException("Failed encrypting payload.", e);
            }
        }
        // Used for Caesar Encryption (for vba)
        public static byte[] EncryptBytesToBytes_Caesar(byte[] buf, int CaesarKey)
        {
            // encrypt payload using key
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + CaesarKey) & 0xFF);
            }
            return encoded;
        }

        // Used for XOR encryption (for vba)
        public static byte[] EncryptBytesToBytes_Xor(byte[] data, byte[] key)
        {
            int dataLength = data.Length;
            int keyLength = key.Length;

            byte[] decryptedData = new byte[dataLength];

            for (int i = 0; i < dataLength; i++)
            {
                decryptedData[i] = (byte)(data[i] ^ key[i % keyLength]);
            }

            return decryptedData;
        }
    }
}