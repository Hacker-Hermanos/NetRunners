using System;
using System.Runtime.InteropServices;

namespace NetRunners.Data
{
	/// <summary>
	/// This class contains structures needed to call certain win32 apis.
	/// </summary>
    public static class Structures
    {
		// define startupinfo struct for createprocess
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct STARTUPINFO
		{
			public Int32 cb;
			public IntPtr lpReserved;
			public IntPtr lpDesktop;
			public IntPtr lpTitle;
			public Int32 dwX;
			public Int32 dwY;
			public Int32 dwXSize;
			public Int32 dwYSize;
			public Int32 dwXCountChars;
			public Int32 dwYCountChars;
			public Int32 dwFillAttribute;
			public Int32 dwFlags;
			public Int16 wShowWindow;
			public Int16 cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		// define process_information struct for createprocess
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}
		// define process_basic_information for zwqueryinformationprocess
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr Reserved1;
			public IntPtr PebAddress;
			public IntPtr Reserved2;
			public IntPtr Reserved3;
			public IntPtr UniquePid;
			public IntPtr MoreReserved;
		}
        // netresource for SMB retriever
        [StructLayout(LayoutKind.Sequential)]
        public class NETRESOURCE /* Its Not a Typo, Its Meant To Be Defined as a Class */
        {
            public int dwScope = 0;
            public int dwType = 0;
            public int dwDisplayType = 0;
            public int dwUsage = 0;
            public string lpLocalName = "";
            public string lpRemoteName = "";
            public string lpComment = "";
            public string lpProvider = "";
        }
        // event descriptor for etweventwrite
        // Event Descriptor Structure
        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }
        // Event Data Descriptor Structure for etweventwrite
        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_DATA_DESCRIPTOR
        {
            public IntPtr DataPtr;
            public uint Size;
            public uint Reserved;
        }
    }
}
