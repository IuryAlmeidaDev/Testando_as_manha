#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class DataType {
    INT8,
    INT16,
    INT32,
    INT64,
    FLOAT,
    DOUBLE,
    BYTE,
    STRING,
    WSTRING,
    POINTER,
    BYTEARRAY
};

struct ByteArray {
    std::vector<uint8_t> bytes;
    std::string mask;

    ByteArray() {}
    ByteArray(const std::string& hexStr);
    
    static ByteArray fromHexWithMask(const std::string& pattern);
    bool matches(const uint8_t* data, size_t len) const;
    size_t size() const { return bytes.size(); }
};

struct ScanResult {
    uintptr_t address;
    std::string stringValue;
    double numericValue;
    DataType type;
    size_t byteSize;
    ByteArray aobPattern;
    std::string label;
    std::string moduleName;

    ScanResult() : address(0), numericValue(0), type(DataType::INT32), byteSize(0) {}

    ScanResult(uintptr_t addr, DataType t, double numVal = 0, const std::string& strVal = "")
        : address(addr), type(t), numericValue(numVal), stringValue(strVal) {
        byteSize = calculateSize(t);
    }

    ScanResult(uintptr_t addr, const ByteArray& pattern)
        : address(addr), type(DataType::BYTEARRAY), numericValue(0), aobPattern(pattern) {
        byteSize = pattern.size();
    }

    static size_t calculateSize(DataType t) {
        switch (t) {
            case DataType::INT8:
            case DataType::BYTE:
                return 1;
            case DataType::INT16:
            case DataType::WSTRING:
                return 2;
            case DataType::INT32:
            case DataType::FLOAT:
            case DataType::POINTER:
                return 4;
            case DataType::INT64:
            case DataType::DOUBLE:
                return 8;
            default:
                return 0;
        }
    }

    std::string getTypeString() const;
    std::string getValueString() const;
};
