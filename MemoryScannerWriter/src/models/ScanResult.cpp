#include "ScanResult.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

ByteArray::ByteArray(const std::string& hexStr) {
    std::string cleanHex;
    for (char c : hexStr) {
        if (c != ' ' && c != '\t' && c != '-') {
            cleanHex += c;
        }
    }
    
    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        if (i + 2 <= cleanHex.length()) {
            std::string byteStr = cleanHex.substr(i, 2);
            unsigned int byte;
            std::istringstream iss(byteStr);
            iss >> std::hex >> byte;
            bytes.push_back(static_cast<uint8_t>(byte));
            mask += 'x';
        }
    }
}

ByteArray ByteArray::fromHexWithMask(const std::string& pattern) {
    ByteArray result;
    std::string cleanPattern;
    
    for (char c : pattern) {
        if (c != ' ' && c != '\t' && c != '-') {
            cleanPattern += c;
        }
    }
    
    size_t i = 0;
    while (i < cleanPattern.length()) {
        if (cleanPattern[i] == '?' || (cleanPattern[i + 1] != '\0' && cleanPattern[i + 1] == '?')) {
            result.mask += '?';
            if (cleanPattern[i] == '?') i++;
            if (i < cleanPattern.length() && cleanPattern[i] == '?') i++;
            
            if (i < cleanPattern.length() && isxdigit(cleanPattern[i])) {
                std::string byteStr = cleanPattern.substr(i, 2);
                unsigned int byte;
                std::istringstream iss(byteStr);
                iss >> std::hex >> byte;
                result.bytes.push_back(static_cast<uint8_t>(byte));
                if (result.mask.length() > 1 && result.mask[result.mask.length() - 2] == '?') {
                } else {
                    result.mask[result.mask.length() - 1] = 'x';
                    i += 2;
                }
            }
        } else if (isxdigit(cleanPattern[i]) && i + 1 < cleanPattern.length() && isxdigit(cleanPattern[i + 1])) {
            std::string byteStr = cleanPattern.substr(i, 2);
            unsigned int byte;
            std::istringstream iss(byteStr);
            iss >> std::hex >> byte;
            result.bytes.push_back(static_cast<uint8_t>(byte));
            result.mask += 'x';
            i += 2;
        } else {
            i++;
        }
    }
    
    return result;
}

bool ByteArray::matches(const uint8_t* data, size_t len) const {
    if (len < bytes.size()) return false;
    
    for (size_t i = 0; i < bytes.size(); i++) {
        if (mask[i] == 'x') {
            if (data[i] != bytes[i]) return false;
        }
    }
    return true;
}

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
        case DataType::WSTRING: return "wstring";
        case DataType::POINTER: return "pointer";
        case DataType::BYTEARRAY: return "aob";
        default: return "unknown";
    }
}

std::string ScanResult::getValueString() const {
    std::ostringstream oss;
    
    if (type == DataType::BYTEARRAY) {
        for (size_t i = 0; i < std::min(bytes.size(), size_t(16)); i++) {
            if (i > 0) oss << " ";
            oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) 
                << static_cast<int>(bytes[i]);
        }
        if (bytes.size() > 16) oss << "...";
    } else if (type == DataType::STRING || type == DataType::WSTRING) {
        oss << stringValue;
    } else if (type == DataType::FLOAT || type == DataType::DOUBLE) {
        oss << std::fixed << std::setprecision(6) << numericValue;
    } else {
        oss << std::hex << "0x" << numericValue;
    }
    
    return oss.str();
}
