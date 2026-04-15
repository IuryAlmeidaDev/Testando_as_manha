#include "ProcessManager.h"
#include <algorithm>
#include <psapi.h>

ProcessManager::ProcessManager() : m_hProcess(nullptr), m_is64Bit(false), m_hasDebugPrivilege(false), m_pid(0) {}

ProcessManager::~ProcessManager() {
    closeProcess();
}

std::string ProcessManager::getProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "";
    
    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, path, sizeof(path))) {
        CloseHandle(hProcess);
        return path;
    }
    
    CloseHandle(hProcess);
    return "";
}

std::vector<ProcessInfo> ProcessManager::getProcessList() {
    std::vector<ProcessInfo> procList;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return procList;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;
            info.path = getProcessPath(pe32.th32ProcessID);
            
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProc) {
                info.is64Bit = !isWow64Process(hProc);
                CloseHandle(hProc);
            } else {
                info.is64Bit = false;
            }
            
            procList.push_back(info);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    std::sort(procList.begin(), procList.end(), 
        [](const ProcessInfo& a, const ProcessInfo& b) { return a.name < b.name; });

    return procList;
}

bool ProcessManager::openProcess(DWORD pid, bool requestDebugPrivilege) {
    closeProcess();
    
    if (requestDebugPrivilege) {
        m_hasDebugPrivilege = WindowsAPI::RequestDebugPrivilege();
    }
    
    m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!m_hProcess) {
        m_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    
    if (!m_hProcess) {
        return false;
    }

    m_pid = pid;
    m_is64Bit = isWow64Process(m_hProcess);
    return true;
}

void ProcessManager::closeProcess() {
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    m_pid = 0;
    m_hasDebugPrivilege = false;
}

bool ProcessManager::isWow64Process(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(kernel32, "IsWow64Process");
        if (fnIsWow64Process) {
            fnIsWow64Process(hProcess, &isWow64);
        }
    }
    return isWow64 != FALSE;
}

std::vector<ThreadInfo> ProcessManager::getThreadList() {
    if (!m_hProcess) return {};
    return WindowsAPI::GetThreadList(m_pid);
}

std::vector<ModuleInfo> ProcessManager::getModuleList() {
    if (!m_hProcess) return {};
    return WindowsAPI::GetModuleList(m_pid);
}

ModuleInfo ProcessManager::getModuleInfo(const std::string& moduleName) {
    if (!m_hProcess) return ModuleInfo();
    return WindowsAPI::GetModuleInfo(m_pid, moduleName);
}

std::vector<HandleInfo> ProcessManager::getHandleList() {
    if (!m_hProcess) return {};
    return WindowsAPI::GetHandles(m_pid);
}

PEBInfo ProcessManager::getPEBInfo() {
    if (!m_hProcess) return PEBInfo();
    return WindowsAPI::GetPEBInfo(m_hProcess);
}

std::vector<MemoryProtectInfo> ProcessManager::getMemoryRegions() {
    if (!m_hProcess) return {};
    return WindowsAPI::GetMemoryRegionsEx(m_hProcess);
}

bool ProcessManager::suspendProcess() {
    if (!m_hProcess) return false;
    return WindowsAPI::SuspendProcess(m_pid);
}

bool ProcessManager::resumeProcess() {
    if (!m_hProcess) return false;
    return WindowsAPI::ResumeProcess(m_pid);
}

bool ProcessManager::suspendThread(DWORD tid) {
    return WindowsAPI::SuspendThread(tid);
}

bool ProcessManager::resumeThread(DWORD tid) {
    return WindowsAPI::ResumeThread(tid);
}
