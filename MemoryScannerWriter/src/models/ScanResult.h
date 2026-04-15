#pragma once
#include <cstdint>
#include <string>

enum class DataType {
    INT8,
    INT16,
    INT32,
    INT64,
    FLOAT,
    DOUBLE,
    BYTE,
    STRING
};

struct ScanResult {
    uintptr_t address;
    std::string stringValue;
    double numericValue;
    DataType type;
    size_t byteSize;

    ScanResult(uintptr_t addr, DataType t, double numVal = 0, const std::string& strVal = "")
        : address(addr), type(t), numericValue(numVal), stringValue(strVal) {
        switch (t) {
            case DataType::INT8:
            case DataType::BYTE:
                byteSize = 1;
                break;
            case DataType::INT16:
                byteSize = 2;
                break;
            case DataType::INT32:
            case DataType::FLOAT:
                byteSize = 4;
                break;
            case DataType::INT64:
            case DataType::DOUBLE:
                byteSize = 8;
                break;
            case DataType::STRING:
                byteSize = strVal.length() + 1;
                break;
        }
    }

    std::string getTypeString() const;
    std::string getValueString() const;
};
