using Microsoft.Win32;

namespace NetRunnersUac
{
    public static class Check
    {
        public static void CheckAlwaysNotify()
        {
            RegistryKey alwaysNotify = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            string consentPrompt = alwaysNotify.GetValue("ConsentPromptBehaviorAdmin").ToString();
            string secureDesktopPrompt = alwaysNotify.GetValue("PromptOnSecureDesktop").ToString();
            alwaysNotify.Close();

            if (consentPrompt == "2" & secureDesktopPrompt == "1")
            {
                System.Console.WriteLine("UAC is set to 'Always Notify'. Exiting...");
                System.Environment.Exit(1);
            }
        }
    }
}
