#pragma once

#include <string>

namespace netwire::core {

std::string ToLower(std::string value);
std::string Trim(const std::string& value);
bool IsNumeric(const std::string& value);
std::string SafeMask(const std::string& value);

}
