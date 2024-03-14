using System;
using static Printers.Printer;
using static Encryptors.Encryptor;
using static Encryptors.Data.Data;
using System.Text;

namespace Encryptors
{
    /// <summary>
    /// Entry point for this Encryptor, checks for arguments, prints decryption key and encrypted data.
    /// Supports one or zero arguments. If no arguments are specified. If no argument is supplied, program prints data in csharp format for use within netrunners.
    /// </summary>
    /// <param name="-vba">Shellcode gets formated in decimal notation for use in VBA macro</param>
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
                    PrintBytesToDec(buf);
                    break;
                // csharp
                default:
                    byte[] AesIV = GenerateIV_Aes();
                    byte[] AesKey = GenerateKey_Aes();

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
