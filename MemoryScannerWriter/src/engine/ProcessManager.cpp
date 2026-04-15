#include "ProcessManager.h"
#include <algorithm>

ProcessManager::ProcessManager() : m_hProcess(nullptr), m_is64Bit(false), m_pid(0) {}

ProcessManager::~ProcessManager() {
    closeProcess();
}

std::vector<ProcessInfo> ProcessManager::getProcessList() {
    std::vector<ProcessInfo> processes;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;
            
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProc) {
                info.is64Bit = !isWow64Process(hProc);
                CloseHandle(hProc);
            } else {
                info.is64Bit = false;
            }
            
            processes.push_back(info);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    std::sort(processes.begin(), processes.end(), 
        [](const ProcessInfo& a, const ProcessInfo& b) { return a.name < b.name; });

    return processes;
}

bool ProcessManager::openProcess(DWORD pid) {
    closeProcess();
    
    m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!m_hProcess) {
        m_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
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
