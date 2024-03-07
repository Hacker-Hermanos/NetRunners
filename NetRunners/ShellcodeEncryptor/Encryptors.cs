using System;
using System.Text;
using static ShellcodeEncryptor.Print;

namespace ShellcodeEncryptor
{
    /// <summary>
    /// Contains various encryption rotuines to treat unencrypted shellcode.
    /// </summary>
    public static class Encryptors
    {
        // generate random substitution key
        static Random rnd = new Random();
        static int subKey = rnd.Next(10, 101);

        // caesar encryption routine to decimal for Csharp shellcode runner
        public static void Caesar(byte[] buf)
        {
            // encrypt payload
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + subKey) & 0xFF);
            }
            // format and print encrypted payload
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }
            
            csPrint(subKey.ToString(), hex.ToString());
            return;
        }
        public static void vbCaesar(byte[] buf)
        {
            // caesar encryption routine to decimal for visual basic shellcode runner
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + subKey) & 0xFF);
            }

            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }

            vbPrint(subKey.ToString(), hex.ToString());
            return;
        }
    }
}
