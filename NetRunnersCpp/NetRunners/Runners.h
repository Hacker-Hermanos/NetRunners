#pragma once
#ifndef RUNNERS_H
#define RUNNERS_H
#include "pch.h"

namespace runner
{
	class Runner
	{
	public:
		static int Run(void);
		static int piRun(void);
		static int epsRun(void);
	};
	class Helper
	{
	public:
		static int getPID(const wchar_t* procname);
	};
}

#endif // !RUNNERS_H
