#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

extern "C" {
    NTSTATUS NTAPI NtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );
    
    NTSTATUS NTAPI NtSetInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );
    
    NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    NTSTATUS NTAPI NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    NTSTATUS NTAPI NtQueryObject(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength
    );
}

struct ThreadInfo {
    DWORD tid;
    DWORD pid;
    uintptr_t tebAddress;
    std::string state;
    int priority;
};

struct ModuleInfo {
    std::string name;
    std::string fullPath;
    uintptr_t baseAddress;
    uintptr_t entryPoint;
    SIZE_T size;
    DWORD pid;
    FILETIME creationTime;
    FILETIME lastWriteTime;
    std::vector<std::pair<std::string, uintptr_t>> exports;
};

struct MemoryProtectInfo {
    uintptr_t address;
    SIZE_T size;
    DWORD protect;
    DWORD state;
    DWORD type;
    std::string protectString;
    std::string stateString;
    std::string typeString;
    uintptr_t allocationBase;
    DWORD allocationProtect;
};

struct HandleInfo {
    HANDLE handle;
    DWORD handleValue;
    std::string objectType;
    std::string objectName;
    DWORD pid;
    ACCESS_MASK grantedAccess;
};

struct PEBInfo {
    uintptr_t pebAddress;
    uintptr_t imageBaseAddress;
    uintptr_t AllocationBase;
    DWORD ImageBaseSize;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    DWORD OSBuildNumber;
    std::string CommandLine;
    std::string CurrentDirectory;
    std::string WindowTitle;
    std::vector<std::string> loadedModules;
    BOOL beingDebugged;
    DWORD processId;
    DWORD parentProcessId;
};

struct HardwareBreakpoint {
    int index;
    uintptr_t address;
    DWORD length;
    DWORD type;
    bool enabled;
    bool active;
    
    std::string getLengthString() {
        switch (length) {
            case 0: return "1 byte";
            case 1: return "2 bytes";
            case 2: return "4 bytes";
            case 3: return "8 bytes";
            default: return "Unknown";
        }
    }
    
    std::string getTypeString() {
        switch (type) {
            case 0: return "Execute";
            case 1: return "Write";
            case 2: return "IO Read";
            case 3: return "IO Write";
            default: return "Read/Write";
        }
    }
};

class WindowsAPI {
public:
    static bool RequestDebugPrivilege();
    static std::vector<ThreadInfo> GetThreadList(DWORD pid);
    static std::vector<ModuleInfo> GetModuleList(DWORD pid);
    static ModuleInfo GetModuleInfo(DWORD pid, const std::string& moduleName);
    static std::string GetProtectionString(DWORD protect);
    static std::string GetStateString(DWORD state);
    static std::string GetTypeString(DWORD type);
    static std::vector<MemoryProtectInfo> GetMemoryRegionsEx(HANDLE hProcess);
    static PEBInfo GetPEBInfo(HANDLE hProcess);
    static std::vector<HandleInfo> GetHandles(DWORD pid);
    static bool SetMemoryProtection(HANDLE hProcess, uintptr_t address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
    static uintptr_t AllocateMemory(HANDLE hProcess, SIZE_T size, DWORD protect);
    static bool FreeMemory(HANDLE hProcess, uintptr_t address);
    static std::vector<HardwareBreakpoint> GetHardwareBreakpoints(HANDLE hThread);
    static bool SetHardwareBreakpoint(HANDLE hThread, int index, uintptr_t address, DWORD type, DWORD length);
    static bool ClearHardwareBreakpoint(HANDLE hThread, int index);
    static bool SuspendProcess(DWORD pid);
    static bool ResumeProcess(DWORD pid);
    static bool SuspendThread(DWORD tid);
    static bool ResumeThread(DWORD tid);
    
private:
    static std::string WideToString(const wchar_t* wideStr);
    static std::string GetObjectTypeName(HANDLE handle);
};
