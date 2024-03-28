using System.ServiceProcess;

namespace NetRunners.Svc
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new Service1()      // Select your runner in this function
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}