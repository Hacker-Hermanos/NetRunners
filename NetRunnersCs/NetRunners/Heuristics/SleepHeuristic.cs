using System;
using System.Threading;
using NetRunners.Interfaces;
using static NetRunners.Delegates.Delegate;

namespace NetRunners.Heuristics
{
    public static class SleepHeuristic
    {
        /// <summary>
        /// Perform a sleep function, if this func is skipped the binary is being emulated by AV
        /// </summary>
		public static bool Check()
		{
			bool result;
            double t2;
            DateTime t1;
            int seconds = 2000;

            Console.WriteLine($"[+] Sleeping {seconds /1000 }\"...");

			t1 = DateTime.Now;
			Thread.Sleep(seconds);
			t2 = DateTime.Now.Subtract(t1).TotalSeconds;

			result = (t2 < 1.5)
			    ? false
                : true;

            Console.WriteLine("[+] Sleep Check              :   Success!");
            return result;
        }
    }
}
