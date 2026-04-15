#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../models/ScanResult.h"

enum class ScanFilter {
    EXACT,
    INCREASED,
    DECREASED,
    UNCHANGED
};

class MemoryEngine {
public:
    MemoryEngine(HANDLE hProcess, bool is64Bit);
    
    std::vector<ScanResult> initialScan(DataType type, const std::string& value);
    std::vector<ScanResult> nextScan(ScanFilter filter, const std::string& value);
    
    bool writeMemory(uintptr_t address, DataType type, const std::string& value);
    bool readMemory(uintptr_t address, DataType type, std::string& outValue);
    
    void clearResults() { m_results.clear(); }
    size_t getResultCount() const { return m_results.size(); }

private:
    HANDLE m_hProcess;
    bool m_is64Bit;
    std::vector<ScanResult> m_results;
    
    bool scanMemoryRegion(uintptr_t start, uintptr_t end, DataType type, double searchValue, const std::string& searchString);
    bool readValue(uintptr_t address, DataType type, double& outValue, std::string& outString);
    bool writeValue(uintptr_t address, DataType type, double numValue, const std::string& strValue);
};
