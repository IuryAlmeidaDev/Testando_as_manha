#include "MemoryEngine.h"
#include <psapi.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>

MemoryEngine::MemoryEngine(HANDLE hProcess, bool is64Bit)
    : m_hProcess(hProcess), m_is64Bit(is64Bit) {
    m_scanning.store(false);
    m_paused.store(false);
    m_stopScan.store(false);
}

MemoryEngine::~MemoryEngine() {
    stopScan();
}

void MemoryEngine::setProgressCallback(std::function<void(int)> callback) {
    m_progressCallback = callback;
}

void MemoryEngine::setLogCallback(std::function<void(const std::string&)> callback) {
    m_logCallback = callback;
}

std::vector<MemoryRegion> MemoryEngine::getAllMemoryRegions() {
    std::vector<MemoryRegion> regions;
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uintptr_t minAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    
    MEMORY_BASIC_INFORMATION memInfo;
    uintptr_t currentAddr = minAddr;
    
    while (currentAddr < maxAddr) {
        if (VirtualQueryEx(m_hProcess, (LPCVOID)currentAddr, &memInfo, sizeof(memInfo)) == 0) {
            break;
        }
        
        if (memInfo.State == MEM_COMMIT &&
            (memInfo.Protect & PAGE_GUARD) == 0 &&
            memInfo.Protect != PAGE_NOACCESS &&
            memInfo.Protect != 0) {
            
            MemoryRegion region;
            region.baseAddress = (uintptr_t)memInfo.BaseAddress;
            region.size = memInfo.RegionSize;
            region.protect = memInfo.Protect;
            region.moduleName = getModuleNameInternal(region.baseAddress);
            regions.push_back(region);
        }
        
        currentAddr = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
    }
    
    return regions;
}

std::vector<MemoryRegion> MemoryEngine::getMemoryRegions() {
    auto allRegions = getAllMemoryRegions();
    std::vector<MemoryRegion> filtered;
    
    for (const auto& region : allRegions) {
        bool isWhitelisted = m_whitelist.empty();
        bool isBlacklisted = false;
        
        for (const auto& whitelist : m_whitelist) {
            if (region.moduleName.find(whitelist) != std::string::npos) {
                isWhitelisted = true;
                break;
            }
        }
        
        for (const auto& blacklist : m_blacklist) {
            if (region.moduleName.find(blacklist) != std::string::npos) {
                isBlacklisted = true;
                break;
            }
        }
        
        if (isWhitelisted && !isBlacklisted) {
            filtered.push_back(region);
        }
    }
    
    return filtered;
}

std::string MemoryEngine::getModuleNameInternal(uintptr_t address) {
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(m_hProcess, modules, sizeof(modules), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(m_hProcess, modules[i], &modInfo, sizeof(modInfo))) {
                uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t modEnd = modBase + modInfo.SizeOfImage;
                
                if (address >= modBase && address < modEnd) {
                    char modName[MAX_PATH];
                    if (GetModuleFileNameExA(m_hProcess, modules[i], modName, sizeof(modName))) {
                        std::string fullPath = modName;
                        size_t pos = fullPath.find_last_of("\\/");
                        if (pos != std::string::npos) {
                            return fullPath.substr(pos + 1);
                        }
                        return fullPath;
                    }
                }
            }
        }
    }
    
    return "";
}

std::string MemoryEngine::getModuleName(uintptr_t address) {
    return getModuleNameInternal(address);
}

void MemoryEngine::addWhitelistModule(const std::string& module) {
    m_whitelist.push_back(module);
}

void MemoryEngine::addBlacklistModule(const std::string& module) {
    m_blacklist.push_back(module);
}

void MemoryEngine::clearModuleFilters() {
    m_whitelist.clear();
    m_blacklist.clear();
}

std::vector<ScanResult> MemoryEngine::initialScan(DataType type, const std::string& value) {
    m_results.clear();
    m_scanning.store(true);
    m_stopScan.store(false);
    m_paused.store(false);
    
    double numValue = 0;
    if (type != DataType::STRING && type != DataType::WSTRING && type != DataType::BYTEARRAY) {
        std::istringstream iss(value);
        iss >> numValue;
    }
    
    auto regions = getMemoryRegions();
    size_t totalSize = 0;
    size_t processedSize = 0;
    
    for (const auto& region : regions) {
        totalSize += region.size;
    }
    
    for (const auto& region : regions) {
        if (m_stopScan.load()) break;
        
        while (m_paused.load() && !m_stopScan.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        scanMemoryRegion(region.baseAddress, region.baseAddress + region.size, type, numValue, value);
        
        processedSize += region.size;
        if (m_progressCallback && totalSize > 0) {
            int progress = static_cast<int>((processedSize * 100) / totalSize);
            m_progressCallback(progress);
        }
    }
    
    m_scanning.store(false);
    if (m_logCallback) {
        m_logCallback("Initial scan complete. Found " + std::to_string(m_results.size()) + " addresses.");
    }
    return m_results;
}

std::vector<ScanResult> MemoryEngine::nextScan(ScanFilter filter, const std::string& value) {
    if (m_results.empty()) {
        return m_results;
    }
    
    m_scanning.store(true);
    m_stopScan.store(false);
    
    double numValue = 0;
    if (m_results[0].type != DataType::STRING && m_results[0].type != DataType::WSTRING) {
        std::istringstream iss(value);
        iss >> numValue;
    }
    
    std::vector<ScanResult> filtered;
    
    for (size_t i = 0; i < m_results.size() && !m_stopScan.load(); i++) {
        double currentValue = 0;
        std::string currentString;
        readValue(m_results[i].address, m_results[i].type, currentValue, currentString);
        
        bool match = false;
        switch (filter) {
            case ScanFilter::EXACT:
                if (m_results[i].type == DataType::STRING || m_results[i].type == DataType::WSTRING) {
                    match = (currentString == value);
                } else {
                    match = (std::abs(currentValue - numValue) < 0.0001);
                }
                break;
            case ScanFilter::INCREASED:
                if (m_results[i].type != DataType::STRING && m_results[i].type != DataType::WSTRING) {
                    match = (currentValue > m_results[i].numericValue);
                }
                break;
            case ScanFilter::DECREASED:
                if (m_results[i].type != DataType::STRING && m_results[i].type != DataType::WSTRING) {
                    match = (currentValue < m_results[i].numericValue);
                }
                break;
            case ScanFilter::UNCHANGED:
                if (m_results[i].type != DataType::STRING && m_results[i].type != DataType::WSTRING) {
                    match = (std::abs(currentValue - m_results[i].numericValue) < 0.0001);
                }
                break;
        }
        
        if (match) {
            ScanResult newResult = m_results[i];
            newResult.numericValue = currentValue;
            newResult.stringValue = currentString;
            filtered.push_back(newResult);
        }
        
        if (m_progressCallback) {
            int progress = static_cast<int>((i * 100) / m_results.size());
            m_progressCallback(progress);
        }
    }
    
    m_results = filtered;
    m_scanning.store(false);
    
    if (m_logCallback) {
        m_logCallback("Next scan complete. Found " + std::to_string(m_results.size()) + " addresses.");
    }
    return m_results;
}

std::vector<ScanResult> MemoryEngine::aobScan(const std::string& pattern) {
    m_results.clear();
    m_scanning.store(true);
    m_stopScan.store(false);
    
    ByteArray aob = ByteArray::fromHexWithMask(pattern);
    
    if (m_logCallback) {
        m_logCallback("AOB Scan: Searching for pattern with " + std::to_string(aob.size()) + " bytes...");
    }
    
    auto regions = getMemoryRegions();
    size_t totalSize = 0;
    size_t processedSize = 0;
    
    for (const auto& region : regions) {
        totalSize += region.size;
    }
    
    for (const auto& region : regions) {
        if (m_stopScan.load()) break;
        
        while (m_paused.load() && !m_stopScan.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        scanMemoryRegionAOB(region.baseAddress, region.baseAddress + region.size, aob);
        
        processedSize += region.size;
        if (m_progressCallback && totalSize > 0) {
            int progress = static_cast<int>((processedSize * 100) / totalSize);
            m_progressCallback(progress);
        }
    }
    
    m_scanning.store(false);
    
    if (m_logCallback) {
        m_logCallback("AOB Scan complete. Found " + std::to_string(m_results.size()) + " matches.");
    }
    return m_results;
}

std::vector<ScanResult> MemoryEngine::pointerScan(uintptr_t address, int maxLevel, int maxResults) {
    m_results.clear();
    m_scanning.store(true);
    m_stopScan.store(false);
    
    if (m_logCallback) {
        m_logCallback("Pointer Scan: Searching for path to 0x" + std::hex + address);
    }
    
    m_pointerBases.clear();
    
    std::vector<std::pair<uintptr_t, uintptr_t>> candidateBases;
    
    scanMemoryRegionPointer(0, 0x7FFFFFFF, address, {}, maxLevel);
    
    for (const auto& base : m_pointerBases) {
        ScanResult result;
        result.address = base.first;
        result.type = DataType::POINTER;
        result.numericValue = static_cast<double>(base.second);
        result.label = "Pointer to 0x" + std::to_string(address);
        m_results.push_back(result);
        
        if (m_results.size() >= (size_t)maxResults) break;
    }
    
    m_scanning.store(false);
    
    if (m_logCallback) {
        m_logCallback("Pointer scan complete. Found " + std::to_string(m_results.size()) + " paths.");
    }
    return m_results;
}

bool MemoryEngine::scanMemoryRegion(uintptr_t start, uintptr_t end, DataType type, double searchValue, const std::string& searchString) {
    const size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    
    for (uintptr_t addr = start; addr < end; addr += sizeof(double)) {
        if (m_stopScan.load()) return false;
        
        while (m_paused.load() && !m_stopScan.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        SIZE_T bytesRead;
        size_t readSize = (type == DataType::STRING || type == DataType::WSTRING) ? 256 : 8;
        if (addr + readSize > end) readSize = (size_t)(end - addr);
        
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)addr, buffer, readSize, &bytesRead) || bytesRead == 0) {
            continue;
        }
        
        if (type == DataType::STRING) {
            std::string found((char*)buffer, bytesRead);
            size_t nullPos = found.find('\0');
            if (nullPos != std::string::npos) {
                found = found.substr(0, nullPos);
            }
            if (!searchString.empty() && found == searchString) {
                ScanResult result(addr, type, 0, found);
                result.moduleName = getModuleName(addr);
                m_results.push_back(result);
            }
        } else if (type == DataType::WSTRING) {
            std::wstring found((wchar_t*)buffer, bytesRead / 2);
            size_t nullPos = found.find(L'\0');
            if (nullPos != std::wstring::npos) {
                found = found.substr(0, nullPos);
            }
            std::string narrow(found.begin(), found.end());
            if (!searchString.empty() && narrow == searchString) {
                ScanResult result(addr, type, 0, narrow);
                result.moduleName = getModuleName(addr);
                m_results.push_back(result);
            }
        } else {
            double value = 0;
            switch (type) {
                case DataType::INT8:
                    value = (double)*(int8_t*)buffer;
                    break;
                case DataType::INT16:
                    value = (double)*(int16_t*)buffer;
                    break;
                case DataType::INT32:
                    value = (double)*(int32_t*)buffer;
                    break;
                case DataType::INT64:
                    value = (double)*(int64_t*)buffer;
                    break;
                case DataType::FLOAT:
                    value = (double)*(float*)buffer;
                    break;
                case DataType::DOUBLE:
                    value = *(double*)buffer;
                    break;
                case DataType::BYTE:
                    value = (double)*buffer;
                    break;
                case DataType::POINTER:
                    if (m_is64Bit) {
                        value = (double)*(uint64_t*)buffer;
                    } else {
                        value = (double)*(uint32_t*)buffer;
                    }
                    break;
                default:
                    continue;
            }
            
            if (std::abs(value - searchValue) < 0.0001) {
                ScanResult result(addr, type, value);
                result.moduleName = getModuleName(addr);
                m_results.push_back(result);
            }
        }
    }
    
    return true;
}

bool MemoryEngine::scanMemoryRegionAOB(uintptr_t start, uintptr_t end, const ByteArray& pattern) {
    const size_t bufferSize = 65536;
    std::vector<uint8_t> buffer(bufferSize);
    
    for (uintptr_t addr = start; addr < end - pattern.size(); addr += bufferSize / 2) {
        if (m_stopScan.load()) return false;
        
        while (m_paused.load() && !m_stopScan.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        SIZE_T bytesRead;
        size_t toRead = bufferSize;
        if (addr + toRead > end) toRead = (size_t)(end - addr);
        
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)addr, buffer.data(), toRead, &bytesRead) || bytesRead == 0) {
            continue;
        }
        
        for (SIZE_T i = 0; i < bytesRead - pattern.size(); i++) {
            if (pattern.matches(buffer.data() + i, bytesRead - i)) {
                ScanResult result(addr + i, pattern);
                result.moduleName = getModuleName(addr + i);
                m_results.push_back(result);
            }
        }
    }
    
    return true;
}

bool MemoryEngine::scanMemoryRegionPointer(uintptr_t start, uintptr_t end, uintptr_t targetAddress, 
                                          const std::vector<uintptr_t>& currentOffsets, int maxLevel) {
    if (currentOffsets.size() >= (size_t)maxLevel) return false;
    
    const size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    
    uintptr_t step = m_is64Bit ? 8 : 4;
    
    for (uintptr_t addr = start; addr < end; addr += step) {
        if (m_stopScan.load()) return false;
        
        SIZE_T bytesRead;
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)addr, buffer, step, &bytesRead) || bytesRead != step) {
            continue;
        }
        
        uintptr_t ptrValue;
        if (m_is64Bit) {
            ptrValue = *(uintptr_t*)buffer;
        } else {
            ptrValue = *(uint32_t*)buffer;
        }
        
        if (ptrValue >= 0x10000 && ptrValue < 0x7FFFFFFF0000) {
            std::vector<uintptr_t> newOffsets = currentOffsets;
            newOffsets.push_back(addr);
            
            uint8_t targetBuffer[8];
            if (ReadProcessMemory(m_hProcess, (LPCVOID)targetAddress, targetBuffer, 8, &bytesRead) && bytesRead > 0) {
                uintptr_t targetValue;
                if (m_is64Bit) {
                    targetValue = *(uintptr_t*)targetBuffer;
                } else {
                    targetValue = *(uint32_t*)targetBuffer;
                }
                
                if (ptrValue == targetValue) {
                    m_pointerBases.push_back({addr, targetAddress});
                    return true;
                }
            }
            
            if (newOffsets.size() < (size_t)maxLevel) {
                scanMemoryRegionPointer(ptrValue & 0x7FFFFFFFFFFF, ptrValue + 0x1000, targetAddress, newOffsets, maxLevel);
            }
        }
    }
    
    return true;
}

bool MemoryEngine::readValue(uintptr_t address, DataType type, double& outValue, std::string& outString) {
    uint8_t buffer[256];
    SIZE_T bytesRead = 0;
    
    if (!ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, 8, &bytesRead) || bytesRead == 0) {
        return false;
    }
    
    switch (type) {
        case DataType::INT8:
            outValue = (double)*(int8_t*)buffer;
            break;
        case DataType::INT16:
            outValue = (double)*(int16_t*)buffer;
            break;
        case DataType::INT32:
            outValue = (double)*(int32_t*)buffer;
            break;
        case DataType::INT64:
            outValue = (double)*(int64_t*)buffer;
            break;
        case DataType::FLOAT:
            outValue = (double)*(float*)buffer;
            break;
        case DataType::DOUBLE:
            outValue = *(double*)buffer;
            break;
        case DataType::BYTE:
            outValue = (double)*buffer;
            break;
        case DataType::POINTER:
            if (m_is64Bit) {
                outValue = (double)*(uint64_t*)buffer;
            } else {
                outValue = (double)*(uint32_t*)buffer;
            }
            break;
        case DataType::STRING: {
            ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, 256, &bytesRead);
            outString = std::string((char*)buffer, bytesRead);
            size_t nullPos = outString.find('\0');
            if (nullPos != std::string::npos) {
                outString = outString.substr(0, nullPos);
            }
            break;
        }
        case DataType::WSTRING: {
            ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, 256, &bytesRead);
            std::wstring wide((wchar_t*)buffer, bytesRead / 2);
            outString = std::string(wide.begin(), wide.end());
            size_t nullPos = outString.find('\0');
            if (nullPos != std::string::npos) {
                outString = outString.substr(0, nullPos);
            }
            break;
        }
        default:
            return false;
    }
    return true;
}

bool MemoryEngine::readBytes(uintptr_t address, uint8_t* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool MemoryEngine::readMemory(uintptr_t address, DataType type, std::string& outValue) {
    double numValue;
    return readValue(address, type, numValue, outValue);
}

bool MemoryEngine::writeMemory(uintptr_t address, DataType type, const std::string& value) {
    double numValue = 0;
    if (type != DataType::STRING && type != DataType::WSTRING) {
        std::istringstream iss(value);
        iss >> numValue;
    }
    return writeValue(address, type, numValue, value);
}

bool MemoryEngine::writeValue(uintptr_t address, DataType type, double numValue, const std::string& strValue) {
    uint8_t buffer[256] = {0};
    SIZE_T bytesWritten = 0;
    size_t size = 0;
    
    switch (type) {
        case DataType::INT8:
            *(int8_t*)buffer = (int8_t)numValue;
            size = 1;
            break;
        case DataType::INT16:
            *(int16_t*)buffer = (int16_t)numValue;
            size = 2;
            break;
        case DataType::INT32:
            *(int32_t*)buffer = (int32_t)numValue;
            size = 4;
            break;
        case DataType::INT64:
            *(int64_t*)buffer = (int64_t)numValue;
            size = 8;
            break;
        case DataType::FLOAT:
            *(float*)buffer = (float)numValue;
            size = 4;
            break;
        case DataType::DOUBLE:
            *(double*)buffer = numValue;
            size = 8;
            break;
        case DataType::BYTE:
            *buffer = (uint8_t)numValue;
            size = 1;
            break;
        case DataType::POINTER:
            if (m_is64Bit) {
                *(uint64_t*)buffer = (uint64_t)numValue;
            } else {
                *(uint32_t*)buffer = (uint32_t)numValue;
            }
            size = m_is64Bit ? 8 : 4;
            break;
        case DataType::STRING:
            memcpy(buffer, strValue.c_str(), strValue.length());
            size = strValue.length() + 1;
            break;
        case DataType::WSTRING: {
            std::wstring wide(strValue.begin(), strValue.end());
            memcpy(buffer, wide.c_str(), wide.length() * 2);
            size = (wide.length() + 1) * 2;
            break;
        }
        default:
            return false;
    }
    
    bool result = WriteProcessMemory(m_hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
    
    if (result && m_logCallback) {
        m_logCallback("Wrote " + std::to_string(size) + " bytes to 0x" + std::to_string(address));
    }
    
    return result;
}

std::vector<uint8_t> MemoryEngine::dumpMemory(uintptr_t address, SIZE_T size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    
    if (ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead)) {
        buffer.resize(bytesRead);
        return buffer;
    }
    
    return std::vector<uint8_t>();
}

bool MemoryEngine::saveDumpToFile(const std::string& filename, uintptr_t address, SIZE_T size) {
    auto data = dumpMemory(address, size);
    
    if (data.empty()) {
        if (m_logCallback) {
            m_logCallback("Failed to dump memory at 0x" + std::to_string(address));
        }
        return false;
    }
    
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        
        if (m_logCallback) {
            m_logCallback("Dumped " + std::to_string(data.size()) + " bytes to " + filename);
        }
        return true;
    }
    
    return false;
}

bool MemoryEngine::injectDLL(const std::string& dllPath) {
    if (m_logCallback) {
        m_logCallback("DLL injection requested: " + dllPath);
    }
    
    size_t pathLen = dllPath.length() + 1;
    LPVOID remotePath = VirtualAllocEx(m_hProcess, nullptr, pathLen, MEM_COMMIT, PAGE_READWRITE);
    
    if (!remotePath) {
        if (m_logCallback) {
            m_logCallback("Failed to allocate memory in target process");
        }
        return false;
    }
    
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(m_hProcess, remotePath, dllPath.c_str(), pathLen, &bytesWritten)) {
        VirtualFreeEx(m_hProcess, remotePath, 0, MEM_RELEASE);
        if (m_logCallback) {
            m_logCallback("Failed to write DLL path to target process");
        }
        return false;
    }
    
    HANDLE hThread = CreateRemoteThread(m_hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"),
        remotePath, 0, nullptr);
    
    if (!hThread) {
        VirtualFreeEx(m_hProcess, remotePath, 0, MEM_RELEASE);
        if (m_logCallback) {
            m_logCallback("Failed to create remote thread");
        }
        return false;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(m_hProcess, remotePath, 0, MEM_RELEASE);
    
    if (m_logCallback) {
        m_logCallback("DLL injected successfully");
    }
    return true;
}
