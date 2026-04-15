#include "AdvancedTools.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>

std::string AdvancedTools::WideToString(const wchar_t* wideStr) {
    if (!wideStr) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (size_needed == 0) return "";
    std::string result(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], size_needed, NULL, NULL);
    return result;
}

std::vector<uint8_t> AdvancedTools::readFile(const std::string& path) {
    std::vector<uint8_t> data;
    std::ifstream file(path, std::ios::binary);
    if (file.is_open()) {
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        data.resize(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
    }
    return data;
}

bool AdvancedTools::writeMemory(HANDLE hProcess, uintptr_t address, const void* data, SIZE_T size) {
    SIZE_T written;
    return WriteProcessMemory(hProcess, (LPVOID)address, data, size, &written) && written == size;
}

uintptr_t AdvancedTools::allocateMemory(HANDLE hProcess, SIZE_T size, DWORD protect) {
    return (uintptr_t)VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
}

uintptr_t AdvancedTools::getModuleBase(const std::string& moduleName) {
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(GetCurrentProcess(), modules[i], modName, sizeof(modName))) {
                if (moduleName == modName || moduleName.empty()) {
                    return (uintptr_t)modules[i];
                }
            }
        }
    }
    return 0;
}

std::vector<DebuggerDetection> AdvancedTools::detectAllDebuggers() {
    std::vector<DebuggerDetection> results;
    
    DebuggerDetection detection;
    detection.method = "IsDebuggerPresent";
    detection.detected = !!IsDebuggerPresent();
    detection.details = detection.detected ? "Debugger detected via IsDebuggerPresent" : "No debugger detected";
    results.push_back(detection);
    
    detection.method = "CheckRemoteDebuggerPresent";
    BOOL isRemoteDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
    detection.detected = !!isRemoteDebuggerPresent;
    detection.details = detection.detected ? "Remote debugger detected" : "No remote debugger";
    results.push_back(detection);
    
    detection.method = "NtQueryInformationProcess (ProcessDebugPort)";
    HANDLE hProcess = GetCurrentProcess();
    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    detection.detected = debugPort != 0 || status < 0;
    detection.details = debugPort != 0 ? "Debug port is set (debugger attached)" : "No debug port";
    results.push_back(detection);
    
    detection.method = "NtQueryInformationProcess (ProcessDebugObjectHandle)";
    HANDLE debugObject = NULL;
    status = NtQueryInformationProcess(hProcess, ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), NULL);
    detection.detected = debugObject != NULL && debugObject != INVALID_HANDLE_VALUE;
    detection.details = detection.detected ? "Debug object handle found" : "No debug object handle";
    results.push_back(detection);
    
    detection.method = "NtQueryInformationProcess (ProcessDebugFlags)";
    DWORD debugFlags = 0;
    status = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL);
    detection.detected = debugFlags == 0;
    detection.details = debugFlags == 0 ? "Debug flags = 0 (debugging allowed)" : "Debug flags modified";
    results.push_back(detection);
    
    detection.method = "BeingDebugged (PEB)";
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    detection.detected = peb && peb->BeingDebugged;
    detection.details = detection.detected ? "PEB.BeingDebugged is TRUE" : "PEB.BeingDebugged is FALSE";
    results.push_back(detection);
    
    detection.method = "NtSetInformationThread (ThreadHideFromDebugger)";
    HANDLE hThread = GetCurrentThread();
    status = NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
    detection.detected = status >= 0;
    detection.details = status >= 0 ? "Thread hidden from debugger" : "Failed to hide thread";
    results.push_back(detection);
    
    detection.method = "Heap Flags (PEB)";
    if (peb) {
        PVOID heapBase = peb->ProcessHeap;
        DWORD heapFlags = 0;
        DWORD heapForceFlags = 0;
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((uintptr_t)heapBase + 0x0C), &heapFlags, sizeof(heapFlags), NULL);
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((uintptr_t)heapBase + 0x10), &heapForceFlags, sizeof(heapForceFlags), NULL);
        detection.detected = (heapFlags & 0x2) || (heapForceFlags != 0);
        std::ostringstream oss;
        oss << "Heap flags: 0x" << std::hex << heapFlags << ", Force flags: 0x" << heapForceFlags;
        detection.details = oss.str();
        results.push_back(detection);
    }
    
    detection.method = "Timing Checks (GetTickCount)";
    DWORD startTick = GetTickCount();
    for (volatile int i = 0; i < 100; i++);
    DWORD endTick = GetTickCount();
    detection.detected = (endTick - startTick) > 100;
    std::ostringstream oss;
    oss << "Tick delta: " << (endTick - startTick) << "ms (slow = debugger)";
    detection.details = oss.str();
    results.push_back(detection);
    
    detection.method = "CheckWindowClass";
    HWND hwnd = FindWindowA("OLLYDBG", NULL);
    if (!hwnd) hwnd = FindWindowA("IDA", NULL);
    if (!hwnd) hwnd = FindWindowA("x64dbg", NULL);
    if (!hwnd) hwnd = FindWindowA("x32dbg", NULL);
    detection.detected = hwnd != NULL;
    detection.details = detection.detected ? "Debug window detected" : "No debug windows found";
    results.push_back(detection);
    
    return results;
}

bool AdvancedTools::patchAntiDebug() {
    HANDLE hProcess = GetCurrentProcess();
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    
    if (!peb) return false;
    
    BOOL oldValue = peb->BeingDebugged;
    SIZE_T written;
    
    peb->BeingDebugged = FALSE;
    
    HANDLE heap = peb->ProcessHeap;
    if (heap) {
        DWORD heapFlags = 0;
        ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)heap + 0x0C), &heapFlags, sizeof(heapFlags), NULL);
        heapFlags &= ~0x2;
        WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)heap + 0x0C), &heapFlags, sizeof(heapFlags), &written);
        
        DWORD heapForceFlags = 0;
        WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)heap + 0x10), &heapForceFlags, sizeof(heapForceFlags), &written);
    }
    
    return true;
}

std::vector<HookDetection> AdvancedTools::detectIATHooks(const std::string& moduleName) {
    std::vector<HookDetection> hooks;
    
    HMODULE hModule = GetModuleHandleA(moduleName.empty() ? NULL : moduleName.c_str());
    if (!hModule) return hooks;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)hModule + dosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return hooks;
    }
    
    for (int i = 0; importDesc[i].Name != 0; i++) {
        const char* dllName = (const char*)((uintptr_t)hModule + importDesc[i].Name);
        HMODULE hDll = GetModuleHandleA(dllName);
        
        if (!hDll) {
            HookDetection hook;
            hook.moduleName = moduleName;
            hook.functionName = dllName;
            hook.hookType = "IAT - DLL Not Loaded";
            hook.hookDetails = "Import DLL is not loaded - possible IAT hook";
            hooks.push_back(hook);
            continue;
        }
        
        PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + importDesc[i].OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + importDesc[i].FirstThunk);
        
        for (int j = 0; originalThunk[j].u1.AddressOfData != 0; j++) {
            if (originalThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            
            PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hModule + originalThunk[j].u1.AddressOfData);
            const char* funcName = (const char*)importName->Name;
            
            FARPROC originalAddr = GetProcAddress(hDll, funcName);
            FARPROC currentAddr = (FARPROC)thunk[j].u1.Function;
            
            if (originalAddr && currentAddr != originalAddr) {
                HookDetection hook;
                hook.moduleName = moduleName;
                hook.functionName = funcName;
                hook.originalAddress = (uintptr_t)originalAddr;
                hook.hookedAddress = (uintptr_t)currentAddr;
                hook.hookType = "IAT Hook";
                std::ostringstream oss;
                oss << "Original: 0x" << std::hex << originalAddr << ", Current: 0x" << currentAddr;
                hook.hookDetails = oss.str();
                hooks.push_back(hook);
            }
        }
    }
    
    return hooks;
}

std::vector<HookDetection> AdvancedTools::detectInlineHooks(const std::string& moduleName) {
    std::vector<HookDetection> hooks;
    
    HMODULE hModule = GetModuleHandleA(moduleName.empty() ? NULL : moduleName.c_str());
    if (!hModule) return hooks;
    
    uint8_t jumpBytes[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    uint8_t callBytes[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    uint8_t pushRet[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    
    uint8_t buffer[4096];
    SIZE_T bytesRead;
    
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = (uintptr_t)hModule;
    
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.Protect & PAGE_EXECUTE_READ && mbi.State == MEM_COMMIT) {
            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, buffer, sizeof(buffer), &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - 5; i++) {
                    if (buffer[i] == 0xE9) {
                        int32_t offset = *(int32_t*)(buffer + i + 1);
                        uintptr_t jumpTarget = addr + i + 5 + offset;
                        uintptr_t functionStart = addr + i;
                        
                        if (jumpTarget < addr || jumpTarget > addr + 0x10000000) {
                            HookDetection hook;
                            hook.moduleName = moduleName;
                            hook.originalAddress = functionStart;
                            hook.hookedAddress = jumpTarget;
                            hook.hookType = "Inline Hook (JMP)";
                            std::ostringstream oss;
                            oss << "JMP at 0x" << std::hex << functionStart << " to 0x" << jumpTarget;
                            hook.hookDetails = oss.str();
                            hooks.push_back(hook);
                        }
                    }
                    else if (buffer[i] == 0xE8) {
                        int32_t offset = *(int32_t*)(buffer + i + 1);
                        uintptr_t callTarget = addr + i + 5 + offset;
                        
                        if (callTarget < addr || callTarget > addr + 0x10000000) {
                            HookDetection hook;
                            hook.moduleName = moduleName;
                            hook.originalAddress = addr + i;
                            hook.hookedAddress = callTarget;
                            hook.hookType = "Inline Hook (CALL)";
                            hook.hookDetails = "Suspicious CALL to external address";
                            hooks.push_back(hook);
                        }
                    }
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr > (uintptr_t)hModule + 0x10000000) break;
    }
    
    return hooks;
}

std::vector<HookDetection> AdvancedTools::detectAllHooks() {
    std::vector<HookDetection> allHooks;
    
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(GetCurrentProcess(), modules[i], modName, sizeof(modName))) {
                auto iatHooks = detectIATHooks(modName);
                allHooks.insert(allHooks.end(), iatHooks.begin(), iatHooks.end());
            }
        }
    }
    
    return allHooks;
}

std::vector<HeapInfo> AdvancedTools::analyzeHeaps(HANDLE hProcess) {
    std::vector<HeapInfo> heaps;
    
    PPEB peb = NULL;
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    peb = (PPEB)pbi.PebBaseAddress;
    
    if (!peb) return heaps;
    
    ReadProcessMemory(hProcess, peb->ProcessHeap, &heaps, sizeof(heaps), NULL);
    
    for (DWORD i = 0; i < 32; i++) {
        uintptr_t heapBase = (uintptr_t)peb->ProcessHeap + (i * sizeof(HEAP));
        HEAP heap;
        
        if (ReadProcessMemory(hProcess, (LPCVOID)heapBase, &heap, sizeof(heap), NULL)) {
            HeapInfo info;
            info.baseAddress = heapBase;
            info.totalSize = 0;
            info.flags = heap.Flags;
            heaps.push_back(info);
        }
    }
    
    return heaps;
}

std::vector<HeapBlock> AdvancedTools::scanHeapForBlocks(HANDLE hProcess, uintptr_t heapBase) {
    std::vector<HeapBlock> blocks;
    
    HEAP_SEGMENT segment;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(hProcess, (LPCVOID)heapBase, &segment, sizeof(segment), &bytesRead)) {
        return blocks;
    }
    
    uintptr_t entryAddr = segment.FirstEntry;
    uintptr_t lastEntry = segment.LastEntry;
    
    int count = 0;
    while (entryAddr != lastEntry && entryAddr != 0 && count < 10000) {
        HEAP_ENTRY entry;
        if (ReadProcessMemory(hProcess, (LPCVOID)entryAddr, &entry, sizeof(entry), &bytesRead)) {
            if (entry.Size == 0 || entry.Size > 0x1000) break;
            
            HeapBlock block;
            block.address = entryAddr + sizeof(HEAP_ENTRY);
            block.size = entry.Size * 8;
            block.busy = entry.Flags & HEAP_ENTRY_BUSY;
            block.extraInfo = entry.ExtraInfo;
            blocks.push_back(block);
            
            entryAddr = *(uintptr_t*)entryAddr;
        } else {
            break;
        }
        count++;
    }
    
    return blocks;
}

bool AdvancedTools::detectHeapCorruption(HANDLE hProcess, uintptr_t heapBase) {
    HEAP heap;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(hProcess, (LPCVOID)heapBase, &heap, sizeof(heap), &bytesRead)) {
        return false;
    }
    
    if (heap.ForceFlags & 0x1) return true;
    if (heap.Flags & 0x2) return true;
    
    uintptr_t entryAddr = heap.FirstEntry;
    uintptr_t lastEntry = heap.LastEntry;
    
    while (entryAddr != 0 && entryAddr != lastEntry) {
        HEAP_ENTRY entry;
        if (!ReadProcessMemory(hProcess, (LPCVOID)entryAddr, &entry, sizeof(entry), &bytesRead)) {
            return true;
        }
        
        if (entry.Size == 0 && entry.Flags == 0 && entry.ExtraInfo == 0) {
            return true;
        }
        
        entryAddr = *(uintptr_t*)((uint8_t*)entryAddr + sizeof(HEAP_ENTRY) - sizeof(PVOID));
    }
    
    return false;
}

uintptr_t AdvancedTools::allocateShellcode(HANDLE hProcess, const std::vector<uint8_t>& shellcode) {
    return allocateMemory(hProcess, shellcode.size(), PAGE_EXECUTE_READWRITE);
}

bool AdvancedTools::executeShellcode(HANDLE hProcess, uintptr_t shellcodeAddress) {
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddress, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return true;
    }
    return false;
}

bool AdvancedTools::freeShellcode(HANDLE hProcess, uintptr_t shellcodeAddress) {
    return VirtualFreeEx(hProcess, (LPVOID)shellcodeAddress, 0, MEM_RELEASE);
}

bool AdvancedTools::injectShellcodeRemoteThread(HANDLE hProcess, const std::vector<uint8_t>& shellcode) {
    uintptr_t addr = allocateShellcode(hProcess, shellcode);
    if (!addr) return false;
    
    if (!writeMemory(hProcess, addr, shellcode.data(), shellcode.size())) {
        freeShellcode(hProcess, addr);
        return false;
    }
    
    bool success = executeShellcode(hProcess, addr);
    freeShellcode(hProcess, addr);
    return success;
}

ProcessHollowResult AdvancedTools::processHollow(const std::string& targetPath, const std::string& payloadPath) {
    ProcessHollowResult result;
    result.success = false;
    
    std::vector<uint8_t> payloadData = readFile(payloadPath);
    if (payloadData.empty()) {
        result.message = "Failed to read payload file";
        return result;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadData.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        result.message = "Invalid PE file";
        return result;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        result.message = "Invalid NT signature";
        return result;
    }
    
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    uintptr_t imageBase = ntHeaders->OptionalHeader.ImageBase;
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        result.message = "Failed to create suspended process";
        return result;
    }
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(pi.hThread, &ctx);
    
    uintptr_t paramAddr = 0;
    SIZE_T bytesWritten;
    
    uintptr_t targetBase = 0;
    DWORD oldProtect = 0;
    
    uint8_t* imageBuffer = new uint8_t[imageSize];
    memset(imageBuffer, 0, imageSize);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        memcpy(imageBuffer + section[i].VirtualAddress,
               payloadData.data() + section[i].PointerToRawData,
               section[i].SizeOfRawData);
    }
    
    NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase);
    
    uintptr_t newBase = (uintptr_t)VirtualAllocEx(pi.hProcess, (LPVOID)imageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        newBase = (uintptr_t)VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    if (!newBase) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        delete[] imageBuffer;
        result.message = "Failed to allocate memory in target process";
        return result;
    }
    
    WriteProcessMemory(pi.hProcess, (LPVOID)newBase, imageBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess, 
            (LPVOID)(newBase + section[i].VirtualAddress),
            imageBuffer + section[i].VirtualAddress,
            section[i].SizeOfRawData,
            &bytesWritten);
    }
    
#ifdef _WIN64
    ctx.Rcx = newBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = newBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
    
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    
    delete[] imageBuffer;
    
    result.success = true;
    result.message = "Process hollowing successful";
    result.newPID = pi.dwProcessId;
    result.imageBase = newBase;
    
    return result;
}

uintptr_t AdvancedTools::manualMapDLL(HANDLE hProcess, const std::string& dllPath) {
    std::vector<uint8_t> dllData = readFile(dllPath);
    if (dllData.empty()) return 0;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllData.data() + dosHeader->e_lfanew);
    
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    uintptr_t dllBase = (uintptr_t)VirtualAllocEx(hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!dllBase) return 0;
    
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        
        SIZE_T written;
        WriteProcessMemory(hProcess, (LPVOID)(dllBase + sections[i].VirtualAddress),
                          dllData.data() + sections[i].PointerToRawData,
                          sections[i].SizeOfRawData, &written);
    }
    
    uintptr_t relocTable = dllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    SIZE_T relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (relocSize > 0 && dllBase != ntHeaders->OptionalHeader.ImageBase) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(dllData.data() + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress != 0) {
            DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)(reloc + 1);
            
            for (DWORD j = 0; j < numEntries; j++) {
                BYTE type = entries[j] >> 12;
                WORD offset = entries[j] & 0xFFF;
                
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uintptr_t* patchAddr = (uintptr_t*)(dllBase + reloc->VirtualAddress + offset);
                    uintptr_t originalValue;
                    SIZE_T read;
                    ReadProcessMemory(hProcess, patchAddr, &originalValue, sizeof(originalValue), &read);
                    originalValue = originalValue - ntHeaders->OptionalHeader.ImageBase + dllBase;
                    WriteProcessMemory(hProcess, patchAddr, &originalValue, sizeof(originalValue), &read);
                }
            }
            
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }
    
    PIMAGE_TLS_DIRECTORY tlsDir = (PIMAGE_TLS_DIRECTORY)(dllData.data() + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    
    return dllBase;
}

std::vector<ETWEvent> AdvancedTools::traceSyscalls(DWORD pid, int durationMs) {
    std::vector<ETWEvent> events;
    
    return events;
}

bool AdvancedTools::attachToProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess) {
        CloseHandle(hProcess);
        return true;
    }
    return false;
}

void AdvancedTools::detachFromProcess() {
}

bool AdvancedTools::unmapDLL(HANDLE hProcess, uintptr_t moduleBase) {
    NTSTATUS status = NtUnmapViewOfSection(hProcess, (PVOID)moduleBase);
    return status >= 0;
}
