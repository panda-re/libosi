#pragma once

#include "offset/offset.h"
#include <map>
#include <string>

namespace debian8_11_x86
{

uint64_t translate_type(const char* tname);
uint64_t offset_of_member(uint64_t tid, const char* mname);
uint64_t type_of_member(uint64_t tid, const char* mname);
} // namespace debian8_11_x86
