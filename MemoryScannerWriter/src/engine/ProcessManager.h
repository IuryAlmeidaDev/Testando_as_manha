#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include "../engine/WindowsAPI.h"

struct ProcessInfo {
    DWORD pid;
    std::string name;
    bool is64Bit;
    std::string path;
};

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    std::vector<ProcessInfo> getProcessList();
    bool openProcess(DWORD pid, bool requestDebugPrivilege = false);
    void closeProcess();
    HANDLE getHandle() const { return m_hProcess; }
    bool isProcessOpen() const { return m_hProcess != nullptr; }
    bool is64Bit() const { return m_is64Bit; }
    DWORD getPID() const { return m_pid; }
    
    std::vector<ThreadInfo> getThreadList();
    std::vector<ModuleInfo> getModuleList();
    ModuleInfo getModuleInfo(const std::string& moduleName);
    std::vector<HandleInfo> getHandleList();
    PEBInfo getPEBInfo();
    std::vector<MemoryProtectInfo> getMemoryRegions();
    
    bool suspendProcess();
    bool resumeProcess();
    bool suspendThread(DWORD tid);
    bool resumeThread(DWORD tid);
    
    bool hasDebugPrivilege() const { return m_hasDebugPrivilege; }

private:
    HANDLE m_hProcess;
    bool m_is64Bit;
    bool m_hasDebugPrivilege;
    DWORD m_pid;
    bool isWow64Process(HANDLE hProcess);
    std::string getProcessPath(DWORD pid);
};
