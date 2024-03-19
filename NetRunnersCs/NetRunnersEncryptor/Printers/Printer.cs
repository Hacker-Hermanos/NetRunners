using System;
using System.Text;

namespace NetRunners.Encryptor.Printers
{
    public static class Printer
    {
        // print byte array in hexadecimal format
        public static void PrintBytesToHex(byte[] data)
        {
            // format and print data
            StringBuilder hex = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            Console.Write("{ ");
            for (int i = 0; i < data.Length; i++)
            {
                Console.Write("0x{0:X2}", data[i]);
                if (i < data.Length - 1) Console.Write(", ");
            }
            Console.WriteLine(" };");
        }

        // prints output and copy to clipboard (vba format, caesar encryption)
        public static void PrintBytesToDec(byte[] data)
        {
            // format and print data
            StringBuilder dec = new StringBuilder(data.Length * 2);
            uint counter = 0;
            foreach (byte b in data)
            {
                dec.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    dec.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            // remove trailing comma to decimal payload
            dec.Remove(dec.Length - 2, 2); // Removes the last comma and space

            // print data
            Console.WriteLine($"Array({dec})");
        }
    }
}
