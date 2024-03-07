using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace NetRunnersClm
{
    public static class Command
    {
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
    }
}
