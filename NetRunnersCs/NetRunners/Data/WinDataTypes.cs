// Aliases for pointer types
global using LPVOID = System.IntPtr;
global using LPCVOID = System.IntPtr;
global using LPCSTR = System.IntPtr;
global using LPCTSTR = System.IntPtr;
global using LPWSTR = System.IntPtr;
global using LPCWSTR = System.IntPtr;
global using HANDLE = System.IntPtr;
global using HMODULE = System.IntPtr;
global using HINSTANCE = System.IntPtr;
global using HWND = System.IntPtr;
global using HKEY = System.IntPtr;
global using HRESULT = System.Int32;

// Aliases for string types (Note: Managed strings in .NET are Unicode, so careful conversion is needed)
global using LPSTR = System.String;
global using LPTSTR = System.String;

// Aliases for integral types
global using DWORD = System.UInt32;
global using BOOL = System.Int32;          // Note: In WinAPI, BOOL is actually an int, TRUE = 1, FALSE = 0
global using BYTE = System.Byte;
global using WORD = System.UInt16;
global using SHORT = System.Int16;
global using USHORT = System.UInt16;
global using LONG = System.Int32;
global using ULONG = System.UInt32;
global using INT = System.Int32;
global using UINT = System.UInt32;
global using LONGLONG = System.Int64;
global using ULONGLONG = System.UInt64;

// Special types
global using SIZE_T = System.UIntPtr;      // Use UIntPtr for SIZE_T to handle 32-bit and 64-bit appropriately
global using WPARAM = System.UIntPtr;      // Similar reasoning as SIZE_T
global using LPARAM = System.IntPtr;       // Often used as a pointer to a structure or other data type

// Other common types
global using COLORREF = System.UInt32;
global using HDC = System.IntPtr;
global using HICON = System.IntPtr;
global using HBRUSH = System.IntPtr;
