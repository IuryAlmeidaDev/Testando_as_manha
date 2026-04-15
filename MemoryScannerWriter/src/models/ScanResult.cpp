#include "ScanResult.h"
#include <sstream>
#include <iomanip>

std::string ScanResult::getTypeString() const {
    switch (type) {
        case DataType::INT8: return "int8";
        case DataType::INT16: return "int16";
        case DataType::INT32: return "int32";
        case DataType::INT64: return "int64";
        case DataType::FLOAT: return "float";
        case DataType::DOUBLE: return "double";
        case DataType::BYTE: return "byte";
        case DataType::STRING: return "string";
        default: return "unknown";
    }
}

std::string ScanResult::getValueString() const {
    std::ostringstream oss;
    if (type == DataType::STRING) {
        oss << stringValue;
    } else if (type == DataType::FLOAT || type == DataType::DOUBLE) {
        oss << std::fixed << std::setprecision(6) << numericValue;
    } else {
        oss << numericValue;
    }
    return oss.str();
}
