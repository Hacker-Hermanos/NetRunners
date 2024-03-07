using System;
using static ShellcodeEncryptor.Encryptors;
using static ShellcodeEncryptor.Shellcode;

namespace ShellcodeEncryptor
{
    /// <summary>
    /// Entry point for this program, checks for arguments, prints decryption key and payload.
    /// Supports one or zero arguments. If no arguments are specified, shellcode gets encrypted in csharp format.
    /// </summary>
    /// <param name="-vba">Shellcode gets formated in decimal notation for VBA macros</param>
    class Program
    {
        [STAThreadAttribute]    // keep compiler happy 
        static void Main(string[] args)
        {

            // check args number
            if (args.Length > 1)
            {
                Console.WriteLine("Error: Only one argument is allowed max.");
                return;
            }

            // Determine the function call based on the argument provided, case insensitive
            string call = args.Length == 1 ? args[0] : string.Empty;
            switch (call.ToLower())
            {
                // print visualbasic encoded payload
                case "-vba":
                    vbCaesar(buf);
                    break;
                // print csharp encoded payload
                default:
                    Caesar(buf);
                    break;
            }
        }
    }
}
