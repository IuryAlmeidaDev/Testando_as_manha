#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

struct ETWEvent {
    DWORD pid;
    DWORD tid;
    std::string providerName;
    std::string eventName;
    ULONGLONG timestamp;
    std::string data;
};

struct HeapBlock {
    uintptr_t address;
    SIZE_T size;
    BOOL busy;
    DWORD extraInfo;
    std::string heapSegment;
};

struct HeapInfo {
    uintptr_t baseAddress;
    SIZE_T totalSize;
    DWORD flags;
    std::vector<HeapBlock> blocks;
};

struct HookDetection {
    std::string moduleName;
    std::string functionName;
    uintptr_t originalAddress;
    uintptr_t hookedAddress;
    std::string hookType;
    std::string hookDetails;
};

struct DebuggerDetection {
    std::string method;
    bool detected;
    std::string details;
};

struct ProcessHollowResult {
    bool success;
    std::string message;
    DWORD newPID;
    uintptr_t imageBase;
};

class AdvancedTools {
public:
    static std::vector<ETWEvent> traceSyscalls(DWORD pid, int durationMs);
    static bool attachToProcess(DWORD pid);
    static void detachFromProcess();
    static std::vector<DebuggerDetection> detectAllDebuggers();
    static bool patchAntiDebug();
    
    static std::vector<HookDetection> detectIATHooks(const std::string& moduleName);
    static std::vector<HookDetection> detectInlineHooks(const std::string& moduleName);
    static std::vector<HookDetection> detectAllHooks();
    
    static std::vector<HeapInfo> analyzeHeaps(HANDLE hProcess);
    static std::vector<HeapBlock> scanHeapForBlocks(HANDLE hProcess, uintptr_t heapBase);
    static bool detectHeapCorruption(HANDLE hProcess, uintptr_t heapBase);
    
    static ProcessHollowResult processHollow(const std::string& targetPath, const std::string& payloadPath);
    static uintptr_t manualMapDLL(HANDLE hProcess, const std::string& dllPath);
    static bool unmapDLL(HANDLE hProcess, uintptr_t moduleBase);
    
    static uintptr_t allocateShellcode(HANDLE hProcess, const std::vector<uint8_t>& shellcode);
    static bool executeShellcode(HANDLE hProcess, uintptr_t shellcodeAddress);
    static bool freeShellcode(HANDLE hProcess, uintptr_t shellcodeAddress);
    
    static bool injectShellcodeRemoteThread(HANDLE hProcess, const std::vector<uint8_t>& shellcode);

private:
    static std::string WideToString(const wchar_t* wideStr);
    static uintptr_t getModuleBase(const std::string& moduleName);
    static std::vector<uint8_t> readFile(const std::string& path);
    static bool writeMemory(HANDLE hProcess, uintptr_t address, const void* data, SIZE_T size);
    static uintptr_t allocateMemory(HANDLE hProcess, SIZE_T size, DWORD protect);
};
