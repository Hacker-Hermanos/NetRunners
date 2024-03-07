using System;

namespace ShellcodeEncryptor
{
    /// <summary>
    /// Contains print methods to output correctly formated shellcode, ready to paste.
    /// </summary>
    class Print
    {
        // prints output and copy to clipboard (csharp)
        public static void csPrint(string subKey, string hex)
        {
            // remove trailing comma to decimal payload
            hex = hex.Substring(0, hex.Length - 2);
            // print key
            Console.WriteLine($"public static int subKey = {subKey};");
            // print payload
            Console.WriteLine("public static byte[] buf = new byte[]" + "{" + hex + "};");
        }

        // prints output and copy to clipboard (vba)
        public static void vbPrint(string subKey, string hex)
        {
            // remove trailing comma to decimal payload
            hex = hex.Substring(0, hex.Length - 2);

            // print key
            Console.WriteLine($"key = {subKey}");
            // print payload
            Console.WriteLine($"buf = Array({hex})"); 
        }
    }
}
