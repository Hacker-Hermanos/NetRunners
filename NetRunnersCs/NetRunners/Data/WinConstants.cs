namespace NetRunners.Data 
{
    public static class WinConstants
    {
        // memory allocation types
        public const uint MEM_COMMIT_RESERVE = 0x00001000 | 0x00002000;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;

        // memory protection constants
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_WRITECOPY = 0x08;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint PAGE_WRITECOMBINE = 0x400;

        // thread access rigths
        public const uint THREAD_TERMINATE = 0x0001;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint THREAD_SET_INFORMATION = 0x0020;
        public const uint THREAD_SET_THREAD_TOKEN = 0x0080;
        public const uint THREAD_IMPERSONATE = 0x0100;
        public const uint THREAD_DIRECT_IMPERSONATION = 0x0200;
        public const uint THREAD_ALL_ACCESS = 0x1F03FF;

        // Process access rights
        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_SET_SESSIONID = 0x0004;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_CREATE_PROCESS = 0x0080;
        public const uint PROCESS_SET_QUOTA = 0x0100;
        public const uint PROCESS_SET_INFORMATION = 0x0200;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_SUSPEND_RESUME = 0x0800;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_SYNCHRONIZE = 0x00100000;
        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    }
}
