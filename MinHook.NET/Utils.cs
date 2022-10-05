using System;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;
using Native = DInvoke.Data.Native;

namespace MinHook;

internal static class Utils
{
    public enum MemoryState : uint
    {
        Commited = 0x1000,
        Free = 0x10000,
        Reserved = 0x2000
    }

    private enum MEMORY_INFO_CLASS
    {
        MemoryBasicInformation = 0,
        MemoryWorkingSetList,
        MemorySectionName,
        MemoryBasicVlmInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public MemoryState State;
        public uint Protect;
        public uint Type;
    }

    [Flags]
    public enum AllocationType
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        internal ushort wProcessorArchitecture;
        internal ushort wReserved;
        internal uint dwPageSize;
        internal IntPtr lpMinimumApplicationAddress;
        internal IntPtr lpMaximumApplicationAddress;
        internal IntPtr dwActiveProcessorMask;
        internal uint dwNumberOfProcessors;
        internal uint dwProcessorType;
        internal uint dwAllocationGranularity;
        internal ushort wProcessorLevel;
        internal ushort wProcessorRevision;
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = 0x0001,
        SUSPEND_RESUME = 0x0002,
        GET_CONTEXT = 0x0008,
        SET_CONTEXT = 0x0010,
        SET_INFORMATION = 0x0020,
        QUERY_INFORMATION = 0x0040,
        SET_THREAD_TOKEN = 0x0080,
        IMPERSONATE = 0x0100,
        DIRECT_IMPERSONATION = 0x0200
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    public static IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType,
        MemoryProtection flProtect)
    {
        object[] parameters =
        {
            (IntPtr)(-1), lpAddress, IntPtr.Zero, dwSize, flAllocationType, flProtect
        };

        Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtAllocateVirtualMemory",
            typeof(NtAllocateVirtualMemory),
            ref parameters);

        return (IntPtr)parameters[1];
    }

    public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, MemoryProtection flNewProtect,
        out MemoryProtection oldProtect)
    {
        object[] parameters =
        {
            (IntPtr)(-1), lpAddress, dwSize, flNewProtect, (MemoryProtection)0
        };

        var status = (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtProtectVirtualMemory",
            typeof(NtProtectVirtualMemory),
            ref parameters);

        oldProtect = (MemoryProtection)parameters[4];
        return status == 0;
    }

    public static bool VirtualFree(IntPtr lpAddress, int dwSize)
    {
        object[] parameters =
        {
            (IntPtr)(-1), lpAddress, (IntPtr)dwSize,
            (uint)AllocationType.Release
        };

        var status = (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtFreeVirtualMemory",
            typeof(NtFreeVirtualMemory),
            ref parameters);

        return status == 0;
    }

    public static void CopyMemory(IntPtr destData, IntPtr srcData, int size)
    {
        object[] parameters =
        {
            destData, srcData, (UIntPtr)size
        };

        Generic.DynamicApiInvoke(
            "ntdll.dll",
            "RtlMoveMemory",
            typeof(RtlMoveMemory),
            ref parameters);
    }

    public static bool VirtualQuery(IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength)
    {
        var buf = Marshal.AllocHGlobal(dwLength);

        object[] parameters =
        {
            (IntPtr)(-1), lpAddress, MEMORY_INFO_CLASS.MemoryBasicInformation,
            buf, (uint)dwLength, (uint)0
        };

        var status = (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtQueryVirtualMemory",
            typeof(NtQueryVirtualMemory),
            ref parameters);

        if (status == 0)
            lpBuffer = Marshal.PtrToStructure<MEMORY_BASIC_INFORMATION>(buf);

        Marshal.FreeHGlobal(buf);
        return status == 0;
    }

    public static IntPtr GetModuleHandle(string lpModuleName)
    {
        return Generic.GetLoadedModuleAddress(lpModuleName);
    }

    public static void GetSystemInfo(ref SYSTEM_INFO info)
    {
        object[] parameters =
        {
            info
        };

        Generic.DynamicApiInvoke(
            "kernel32.dll",
            "GetSystemInfo",
            typeof(GetSystemInformation),
            ref parameters);

        info = (SYSTEM_INFO)parameters[0];
    }

    public static IntPtr GetProcAddress(IntPtr hModule, string procName)
    {
        return Generic.GetExportAddress(hModule, procName);
    }

    public static bool SuspendThread(IntPtr hThread)
    {
        object[] parameters =
        {
            hThread, (ulong)0
        };

        var status = (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtSuspendThread",
            typeof(NtSuspendThread),
            ref parameters);

        return status == 0;
    }

    public static IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId)
    {
        var oa = new Native.OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(oa);

        var cid = new CLIENT_ID
        {
            UniqueProcess = (IntPtr)(-1),
            UniqueThread = (IntPtr)dwThreadId
        };

        object[] parameters =
        {
            IntPtr.Zero, (uint)dwDesiredAccess, cid
        };

        _ = (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtOpenThread",
            typeof(NtOpenThread),
            ref parameters);

        return (IntPtr)parameters[0];
    }

    public static bool CloseHandle(IntPtr hObject)
    {
        object[] parameters =
        {
            hObject
        };

        return (bool)Generic.DynamicApiInvoke(
            "kernel32.dll",
            "CloseHandle",
            typeof(CloseObjectHandle),
            ref parameters);
    }

    public static uint GetCurrentThreadId()
    {
        object[] parameters = { };

        return (uint)Generic.DynamicApiInvoke(
            "kernel32.dll",
            "GetCurrentThreadId",
            typeof(GetCurrentThread),
            ref parameters);
    }

    public static uint ResumeThread(IntPtr hThread)
    {
        object[] parameters =
        {
            hThread, (UIntPtr)0
        };

        return (uint)Generic.DynamicApiInvoke(
            "ntdll.dll",
            "NtResumeThread",
            typeof(NtResumeThread),
            ref parameters);
    }

    public static bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize)
    {
        object[] parameters =
        {
            hProcess, lpBaseAddress, dwSize
        };

        return (bool)Generic.DynamicApiInvoke(
            "kernel32.dll",
            "FlushInstructionCache",
            typeof(FlushInstructions),
            ref parameters);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtAllocateVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        ref IntPtr regionSize,
        AllocationType allocationType,
        MemoryProtection memoryProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtProtectVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        ref UIntPtr regionSize,
        MemoryProtection newProtect,
        ref MemoryProtection oldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtFreeVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        ref IntPtr regionSize,
        uint freeType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtQueryVirtualMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        MEMORY_INFO_CLASS memoryInformationClass,
        IntPtr memoryInformation,
        uint memoryInformationLength,
        ref uint returnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint RtlMoveMemory(
        IntPtr destination,
        IntPtr source,
        UIntPtr length);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void GetSystemInformation(ref SYSTEM_INFO info);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtSuspendThread(
        IntPtr hThread,
        out ulong suspendCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtOpenThread(
        ref IntPtr hThread,
        uint desiredAccess,
        Native.OBJECT_ATTRIBUTES objectAttributes,
        CLIENT_ID clientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint GetCurrentThread();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool CloseObjectHandle(IntPtr hObject);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint NtResumeThread(
        IntPtr hThread,
        ulong suspendCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool FlushInstructions(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        UIntPtr dwSize);
}