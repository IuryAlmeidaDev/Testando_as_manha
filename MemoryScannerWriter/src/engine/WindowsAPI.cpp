#include "WindowsAPI.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

std::string WindowsAPI::WideToString(const wchar_t* wideStr) {
    if (!wideStr) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (size_needed == 0) return "";
    std::string result(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], size_needed, NULL, NULL);
    return result;
}

bool WindowsAPI::RequestDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL) != 0;
    
    CloseHandle(hToken);
    return result;
}

std::vector<ThreadInfo> WindowsAPI::GetThreadList(DWORD pid) {
    std::vector<ThreadInfo> threads;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threads;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                ThreadInfo info;
                info.tid = te32.th32ThreadID;
                info.pid = te32.th32OwnerProcessID;
                info.priority = te32.tpBasePri;
                
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, info.tid);
                if (hThread) {
                    NT_TIB tib;
                    if (GetThreadInformation(hThread, ThreadInformationClass, &tib, sizeof(tib))) {
                        info.tebAddress = (uintptr_t)tib.Self;
                    }
                    CloseHandle(hThread);
                }
                
                switch (te32.tpBasePri) {
                    case THREAD_PRIORITY_TIME_CRITICAL: info.state = "Time Critical"; break;
                    case THREAD_PRIORITY_HIGHEST: info.state = "Highest"; break;
                    case THREAD_PRIORITY_ABOVE_NORMAL: info.state = "Above Normal"; break;
                    case THREAD_PRIORITY_NORMAL: info.state = "Normal"; break;
                    case THREAD_PRIORITY_BELOW_NORMAL: info.state = "Below Normal"; break;
                    case THREAD_PRIORITY_LOWEST: info.state = "Lowest"; break;
                    case THREAD_PRIORITY_IDLE: info.state = "Idle"; break;
                    default: info.state = "Unknown"; break;
                }
                
                threads.push_back(info);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return threads;
}

std::vector<ModuleInfo> WindowsAPI::GetModuleList(DWORD pid) {
    std::vector<ModuleInfo> modules;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    if (Module32First(hSnapshot, &me32)) {
        do {
            ModuleInfo info;
            info.name = me32.szModule;
            info.fullPath = me32.szExePath;
            info.baseAddress = (uintptr_t)me32.modBaseAddr;
            info.size = me32.modBaseSize;
            info.pid = pid;
            
            HANDLE hFile = CreateFileA(me32.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME ftCreate, ftAccess, ftWrite;
                if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                    info.lastWriteTime = ftWrite;
                }
                CloseHandle(hFile);
            }
            
            modules.push_back(info);
        } while (Module32Next(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
    return modules;
}

ModuleInfo WindowsAPI::GetModuleInfo(DWORD pid, const std::string& moduleName) {
    auto modules = GetModuleList(pid);
    for (const auto& mod : modules) {
        if (mod.name == moduleName) {
            return mod;
        }
    }
    return ModuleInfo();
}

std::string WindowsAPI::GetProtectionString(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "READONLY";
        case PAGE_READWRITE: return "READWRITE";
        case PAGE_WRITECOPY: return "WRITECOPY";
        case PAGE_EXECUTE: return "EXECUTE";
        case PAGE_EXECUTE_READ: return "EXECUTE_READ";
        case PAGE_EXECUTE_READ_WRITE: return "EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
        case PAGE_GUARD: return "GUARD";
        case PAGE_NOCACHE: return "NOCACHE";
        case PAGE_WRITECOMBINE: return "WRITECOMBINE";
        default: return "UNKNOWN";
    }
}

std::string WindowsAPI::GetStateString(DWORD state) {
    switch (state) {
        case MEM_COMMIT: return "COMMIT";
        case MEM_RESERVE: return "RESERVE";
        case MEM_FREE: return "FREE";
        default: return "UNKNOWN";
    }
}

std::string WindowsAPI::GetTypeString(DWORD type) {
    switch (type) {
        case MEM_PRIVATE: return "PRIVATE";
        case MEM_MAPPED: return "MAPPED";
        case MEM_IMAGE: return "IMAGE";
        default: return "UNKNOWN";
    }
}

std::vector<MemoryProtectInfo> WindowsAPI::GetMemoryRegionsEx(HANDLE hProcess) {
    std::vector<MemoryProtectInfo> regions;
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uintptr_t minAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    uintptr_t currentAddr = minAddr;
    
    while (currentAddr < maxAddr) {
        MEMORY_BASIC_INFORMATION memInfo;
        SIZE_T result = VirtualQueryEx(hProcess, (LPCVOID)currentAddr, &memInfo, sizeof(memInfo));
        
        if (result == 0) break;
        
        MemoryProtectInfo info;
        info.address = (uintptr_t)memInfo.BaseAddress;
        info.size = memInfo.RegionSize;
        info.protect = memInfo.Protect;
        info.state = memInfo.State;
        info.type = memInfo.Type;
        info.protectString = GetProtectionString(memInfo.Protect);
        info.stateString = GetStateString(memInfo.State);
        info.typeString = GetTypeString(memInfo.Type);
        info.allocationBase = (uintptr_t)memInfo.AllocationBase;
        info.allocationProtect = memInfo.AllocationProtect;
        
        regions.push_back(info);
        currentAddr = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
    }
    
    return regions;
}

PEBInfo WindowsAPI::GetPEBInfo(HANDLE hProcess) {
    PEBInfo info;
    info.pebAddress = 0;
    info.imageBaseAddress = 0;
    
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    
    if (status >= 0 && pbi.PebBaseAddress) {
        info.pebAddress = (uintptr_t)pbi.PebBaseAddress;
        
        SIZE_T bytesRead;
        
        PEB peb;
        if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead) && bytesRead == sizeof(peb)) {
            info.imageBaseAddress = (uintptr_t)peb.ImageBaseAddress;
            info.OSMajorVersion = peb.OSMajorVersion;
            info.OSMinorVersion = peb.OSMinorVersion;
            info.OSBuildNumber = peb.OSBuildNumber;
            info.beingDebugged = peb.BeingDebugged;
            info.processId = peb.ProcessId;
            info.parentProcessId = (DWORD)peb.InheritedFromUniqueProcessId;
            
            RTL_USER_PROCESS_PARAMETERS params;
            if (ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead) && bytesRead == sizeof(params)) {
                wchar_t cmdLine[1024];
                if (params.CommandLine.Length > 0 && params.CommandLine.Length < sizeof(cmdLine)) {
                    if (ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmdLine, params.CommandLine.Length, &bytesRead)) {
                        cmdLine[params.CommandLine.Length / 2] = 0;
                        info.CommandLine = WideToString(cmdLine);
                    }
                }
                
                wchar_t curDir[512];
                if (params.CurrentDirectory.DosPath.Length > 0 && params.CurrentDirectory.DosPath.Length < sizeof(curDir)) {
                    if (ReadProcessMemory(hProcess, params.CurrentDirectory.DosPath.Buffer, curDir, params.CurrentDirectory.DosPath.Length, &bytesRead)) {
                        curDir[params.CurrentDirectory.DosPath.Length / 2] = 0;
                        info.CurrentDirectory = WideToString(curDir);
                    }
                }
                
                wchar_t windowTitle[512];
                if (params.WindowTitle.Length > 0 && params.WindowTitle.Length < sizeof(windowTitle)) {
                    if (ReadProcessMemory(hProcess, params.WindowTitle.Buffer, windowTitle, params.WindowTitle.Length, &bytesRead)) {
                        windowTitle[params.WindowTitle.Length / 2] = 0;
                        info.WindowTitle = WideToString(windowTitle);
                    }
                }
            }
            
            PPEB_LDR_DATA ldrData;
            if (ReadProcessMemory(hProcess, &peb.Ldr, &ldrData, sizeof(ldrData), &bytesRead) && ldrData) {
                for (int i = 0; i < 3; i++) {
                    PLIST_ENTRY head = &ldrData->InMemoryOrderModuleList;
                    PLIST_ENTRY entry = head->Flink;
                    int count = 0;
                    
                    while (entry != head && count < 256) {
                        LDR_DATA_TABLE_ENTRY entryData;
                        if (ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)entry - sizeof(PVOID)), &entryData, sizeof(entryData), &bytesRead)) {
                            wchar_t dllName[512];
                            if (ReadProcessMemory(hProcess, entryData.BaseDllName.Buffer, dllName, entryData.BaseDllName.Length, &bytesRead)) {
                                dllName[entryData.BaseDllName.Length / 2] = 0;
                                info.loadedModules.push_back(WideToString(dllName));
                            }
                        }
                        entry = entry->Flink;
                        count++;
                    }
                    break;
                }
            }
        }
    }
    
    return info;
}

std::vector<HandleInfo> WindowsAPI::GetHandles(DWORD pid) {
    std::vector<HandleInfo> handles;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return handles;
    }
    
    std::vector<DWORD> threadIds;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);
    
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return handles;
    }
    
    for (DWORD i = 0; i < 65536; i += sizeof(HANDLE)) {
        HANDLE hDup = NULL;
        if (DuplicateHandle(hProcess, (HANDLE)(uintptr_t)i, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            HandleInfo info;
            info.handle = hDup;
            info.handleValue = i;
            info.pid = pid;
            
            info.objectType = GetObjectTypeName(hDup);
            
            CloseHandle(hDup);
            
            if (!info.objectType.empty()) {
                handles.push_back(info);
            }
        }
    }
    
    CloseHandle(hProcess);
    return handles;
}

std::string WindowsAPI::GetObjectTypeName(HANDLE handle) {
    char buffer[256];
    NTSTATUS status = NtQueryObject(handle, ObjectTypeInformation, buffer, sizeof(buffer), NULL);
    
    if (status >= 0) {
        OBJECT_TYPE_INFORMATION* typeInfo = (OBJECT_TYPE_INFORMATION*)buffer;
        return WideToString(typeInfo->Name.Buffer);
    }
    
    return "";
}

bool WindowsAPI::SetMemoryProtection(HANDLE hProcess, uintptr_t address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtectEx(hProcess, (LPVOID)address, size, newProtect, oldProtect) != 0;
}

uintptr_t WindowsAPI::AllocateMemory(HANDLE hProcess, SIZE_T size, DWORD protect) {
    LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    return (uintptr_t)addr;
}

bool WindowsAPI::FreeMemory(HANDLE hProcess, uintptr_t address) {
    return VirtualFreeEx(hProcess, (LPVOID)address, 0, MEM_RELEASE) != 0;
}

std::vector<HardwareBreakpoint> WindowsAPI::GetHardwareBreakpoints(HANDLE hThread) {
    std::vector<HardwareBreakpoint> bps;
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(hThread, &ctx)) {
        for (int i = 0; i < 4; i++) {
            HardwareBreakpoint bp;
            bp.index = i;
            
            uint64_t* dr7 = (uint64_t*)&ctx.Dr7;
            bool enabled = (*dr7 >> (i * 2)) & 1;
            
            switch (i) {
                case 0:
                    bp.address = ctx.Dr0;
                    break;
                case 1:
                    bp.address = ctx.Dr1;
                    break;
                case 2:
                    bp.address = ctx.Dr2;
                    break;
                case 3:
                    bp.address = ctx.Dr3;
                    break;
            }
            
            int lenBits = ((*dr7 >> (16 + i * 4)) & 3);
            switch (lenBits) {
                case 0: bp.length = 0; break;
                case 1: bp.length = 1; break;
                case 2: bp.length = 2; break;
                case 3: bp.length = 3; break;
            }
            
            int typeBits = ((*dr7 >> (18 + i * 4)) & 3);
            switch (typeBits) {
                case 0: bp.type = 0; break;
                case 1: bp.type = (ctx.Dr7 & (1 << 11)) ? 2 : 1; break;
                case 2: bp.type = 3; break;
                case 3: bp.type = (ctx.Dr7 & (1 << (11 + i * 4))) ? 2 : 1; break;
            }
            
            bp.enabled = enabled && bp.address != 0;
            bp.active = bp.address != 0;
            
            if (bp.active) {
                bps.push_back(bp);
            }
        }
    }
    
    return bps;
}

bool WindowsAPI::SetHardwareBreakpoint(HANDLE hThread, int index, uintptr_t address, DWORD type, DWORD length) {
    if (index < 0 || index > 3) return false;
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(hThread, &ctx)) {
        return false;
    }
    
    uint64_t* dr7 = (uint64_t*)&ctx.Dr7;
    
    switch (index) {
        case 0: ctx.Dr0 = address; break;
        case 1: ctx.Dr1 = address; break;
        case 2: ctx.Dr2 = address; break;
        case 3: ctx.Dr3 = address; break;
    }
    
    ctx.Dr7 &= ~(3ULL << (16 + index * 4));
    ctx.Dr7 |= ((uint64_t)length & 3) << (16 + index * 4);
    
    ctx.Dr7 &= ~(3ULL << (18 + index * 4));
    ctx.Dr7 |= ((uint64_t)type & 3) << (18 + index * 4);
    
    ctx.Dr7 |= (1ULL << (index * 2));
    
    return SetThreadContext(hThread, &ctx) != 0;
}

bool WindowsAPI::ClearHardwareBreakpoint(HANDLE hThread, int index) {
    if (index < 0 || index > 3) return false;
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(hThread, &ctx)) {
        return false;
    }
    
    switch (index) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
    }
    
    ctx.Dr7 &= ~(3ULL << (16 + index * 4));
    ctx.Dr7 &= ~(3ULL << (18 + index * 4));
    ctx.Dr7 &= ~(1ULL << (index * 2));
    
    return SetThreadContext(hThread, &ctx) != 0;
}

bool WindowsAPI::SuspendProcess(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    bool result = true;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) == (DWORD)-1) {
                        result = false;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return result;
}

bool WindowsAPI::ResumeProcess(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    bool result = true;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    while (ResumeThread(hThread) > 0);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return result;
}

bool WindowsAPI::SuspendThread(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) return false;
    
    bool result = SuspendThread(hThread) != (DWORD)-1;
    CloseHandle(hThread);
    return result;
}

bool WindowsAPI::ResumeThread(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) return false;
    
    bool result = ResumeThread(hThread) != (DWORD)-1;
    CloseHandle(hThread);
    return result;
}
