# MinHook.NET

An experimental fork of CCob's [MinHook.NET](https://github.com/CCob/MinHook.NET) project.  Changes include:

- Retargeted from .NET Framework to .NET Standard.
- Replaced P/Invoke with [D/Invoke](https://github.com/rasta-mouse/DInvoke).
- Replaced Win32 APIs (VirtualAlloc/VirtualProtect/etc) with their equivalent Nt-API counterparts (NtAllocateVirtualMemory/NtProtectVirtualMemory/etc).
