#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <atomic>
#include <functional>
#include <thread>
#include "../models/ScanResult.h"

enum class ScanFilter {
    EXACT,
    INCREASED,
    DECREASED,
    UNCHANGED
};

enum class ScanMode {
    VALUE,
    AOB,
    POINTER
};

struct MemoryRegion {
    uintptr_t baseAddress;
    SIZE_T size;
    DWORD protect;
    std::string moduleName;
};

struct PointerPath {
    std::vector<uintptr_t> offsets;
};

class MemoryEngine {
public:
    MemoryEngine(HANDLE hProcess, bool is64Bit);
    ~MemoryEngine();
    
    std::vector<ScanResult> initialScan(DataType type, const std::string& value);
    std::vector<ScanResult> nextScan(ScanFilter filter, const std::string& value);
    
    std::vector<ScanResult> aobScan(const std::string& pattern);
    std::vector<ScanResult> pointerScan(uintptr_t address, int maxLevel, int maxResults);
    
    bool writeMemory(uintptr_t address, DataType type, const std::string& value);
    bool readMemory(uintptr_t address, DataType type, std::string& outValue);
    
    std::vector<uint8_t> dumpMemory(uintptr_t address, SIZE_T size);
    bool saveDumpToFile(const std::string& filename, uintptr_t address, SIZE_T size);
    
    bool injectDLL(const std::string& dllPath);
    
    void clearResults() { m_results.clear(); }
    size_t getResultCount() const { return m_results.size(); }
    bool isScanning() const { return m_scanning.load(); }
    void pauseScan() { m_paused.store(true); }
    void resumeScan() { m_paused.store(false); }
    void stopScan() { m_stopScan.store(true); m_paused.store(false); }
    
    std::vector<MemoryRegion> getMemoryRegions();
    std::string getModuleName(uintptr_t address);
    
    void setFloatPrecision(int precision) { m_floatPrecision = precision; }
    int getFloatPrecision() const { return m_floatPrecision; }
    
    void addWhitelistModule(const std::string& module);
    void addBlacklistModule(const std::string& module);
    void clearModuleFilters();
    
    void setProgressCallback(std::function<void(int)> callback);
    void setLogCallback(std::function<void(const std::string&)> callback);

private:
    HANDLE m_hProcess;
    bool m_is64Bit;
    std::vector<ScanResult> m_results;
    std::vector<std::string> m_whitelist;
    std::vector<std::string> m_blacklist;
    
    std::atomic<bool> m_scanning;
    std::atomic<bool> m_paused;
    std::atomic<bool> m_stopScan;
    
    int m_floatPrecision = 6;
    std::function<void(int)> m_progressCallback;
    std::function<void(const std::string&)> m_logCallback;
    
    std::vector<std::pair<uintptr_t, uintptr_t>> m_pointerBases;
    
    bool scanMemoryRegion(uintptr_t start, uintptr_t end, DataType type, double searchValue, const std::string& searchString);
    bool scanMemoryRegionAOB(uintptr_t start, uintptr_t end, const ByteArray& pattern);
    bool scanMemoryRegionPointer(uintptr_t start, uintptr_t end, uintptr_t targetAddress, const std::vector<uintptr_t>& currentOffsets, int maxLevel);
    
    bool readValue(uintptr_t address, DataType type, double& outValue, std::string& outString);
    bool writeValue(uintptr_t address, DataType type, double numValue, const std::string& strValue);
    bool readBytes(uintptr_t address, uint8_t* buffer, SIZE_T size);
    
    std::vector<MemoryRegion> getAllMemoryRegions();
    std::string getModuleNameInternal(uintptr_t address);
};
