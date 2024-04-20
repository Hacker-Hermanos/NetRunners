using System;
using static NetRunners.Delegates.Delegate;

namespace NetRunners.Heuristics
{
    public static class NonEmulatedApiHeuristic
    {
        /// <summary>
        /// execute a non-emulated api, if memory address is null, the binary is being emulated by AV
        /// </summary>
		public static bool Check()
        {
            bool result;
            IntPtr pMemory;
            IntPtr checkPtr;

            pMemory = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            checkPtr = FlsAlloc(IntPtr.Zero);
            result = (pMemory == null || checkPtr == null)
                ? false
                : true;

            Console.WriteLine("[+] VirtualAllocExNuma Check :   Success!");
            Console.WriteLine("[+] FlsAlloc Check           :   Success!");

            return result;
        }
    }
}