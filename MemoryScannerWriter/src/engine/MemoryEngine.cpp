#include "MemoryEngine.h"
#include <psapi.h>
#include <sstream>
#include <cmath>

MemoryEngine::MemoryEngine(HANDLE hProcess, bool is64Bit)
    : m_hProcess(hProcess), m_is64Bit(is64Bit) {}

std::vector<ScanResult> MemoryEngine::initialScan(DataType type, const std::string& value) {
    m_results.clear();
    
    double numValue = 0;
    if (type != DataType::STRING) {
        std::istringstream iss(value);
        iss >> numValue;
    }
    
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
            
            uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
            uintptr_t regionEnd = regionStart + memInfo.RegionSize;
            
            scanMemoryRegion(regionStart, regionEnd, type, numValue, value);
        }
        
        currentAddr = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
    }
    
    return m_results;
}

std::vector<ScanResult> MemoryEngine::nextScan(ScanFilter filter, const std::string& value) {
    double numValue = 0;
    if (!m_results.empty() && m_results[0].type != DataType::STRING) {
        std::istringstream iss(value);
        iss >> numValue;
    }
    
    std::vector<ScanResult> filtered;
    
    for (const auto& result : m_results) {
        double currentValue = 0;
        std::string currentString;
        readValue(result.address, result.type, currentValue, currentString);
        
        bool match = false;
        switch (filter) {
            case ScanFilter::EXACT:
                if (result.type == DataType::STRING) {
                    match = (currentString == value);
                } else {
                    match = (std::abs(currentValue - numValue) < 0.0001);
                }
                break;
            case ScanFilter::INCREASED:
                if (result.type != DataType::STRING) {
                    match = (currentValue > result.numericValue);
                }
                break;
            case ScanFilter::DECREASED:
                if (result.type != DataType::STRING) {
                    match = (currentValue < result.numericValue);
                }
                break;
            case ScanFilter::UNCHANGED:
                if (result.type != DataType::STRING) {
                    match = (std::abs(currentValue - result.numericValue) < 0.0001);
                }
                break;
        }
        
        if (match) {
            ScanResult newResult = result;
            newResult.numericValue = currentValue;
            newResult.stringValue = currentString;
            filtered.push_back(newResult);
        }
    }
    
    m_results = filtered;
    return m_results;
}

bool MemoryEngine::scanMemoryRegion(uintptr_t start, uintptr_t end, DataType type, double searchValue, const std::string& searchString) {
    const size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    
    for (uintptr_t addr = start; addr < end; addr += sizeof(double)) {
        SIZE_T bytesRead;
        size_t readSize = (type == DataType::STRING) ? 256 : 8;
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
                m_results.emplace_back(addr, type, 0, found);
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
                default:
                    continue;
            }
            
            if (std::abs(value - searchValue) < 0.0001) {
                m_results.emplace_back(addr, type, value);
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
        case DataType::STRING: {
            ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, 256, &bytesRead);
            outString = std::string((char*)buffer, bytesRead);
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

bool MemoryEngine::readMemory(uintptr_t address, DataType type, std::string& outValue) {
    double numValue;
    return readValue(address, type, numValue, outValue);
}

bool MemoryEngine::writeMemory(uintptr_t address, DataType type, const std::string& value) {
    double numValue = 0;
    if (type != DataType::STRING) {
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
        case DataType::STRING:
            memcpy(buffer, strValue.c_str(), strValue.length());
            size = strValue.length() + 1;
            break;
        default:
            return false;
    }
    
    return WriteProcessMemory(m_hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
}
