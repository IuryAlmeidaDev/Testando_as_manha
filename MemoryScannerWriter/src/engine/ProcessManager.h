#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    bool is64Bit;
};

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    std::vector<ProcessInfo> getProcessList();
    bool openProcess(DWORD pid);
    void closeProcess();
    HANDLE getHandle() const { return m_hProcess; }
    bool isProcessOpen() const { return m_hProcess != nullptr; }
    bool is64Bit() const { return m_is64Bit; }

private:
    HANDLE m_hProcess;
    bool m_is64Bit;
    DWORD m_pid;
    bool isWow64Process(HANDLE hProcess);
};
