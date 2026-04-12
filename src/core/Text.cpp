#include "netwire/core/Text.hpp"

#include <algorithm>
#include <cctype>

namespace netwire::core {

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string Trim(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

bool IsNumeric(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

std::string SafeMask(const std::string& value) {
    if (value.empty()) {
        return "";
    }
    if (value.size() <= 2) {
        return std::string(value.size(), '*');
    }
    return value.substr(0, 1) + std::string(value.size() - 2, '*') + value.substr(value.size() - 1);
}

}
