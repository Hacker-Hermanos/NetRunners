#pragma once
#ifndef HEURISTICS_H
#define HEURISTICS_H
#include "pch.h"

namespace heuristic
{
	class Heuristic
	{
	public:
		static bool CheckSleep(void);
		static bool NoEmulate(void);
	};
}


#endif // !HEURISTICS_H
