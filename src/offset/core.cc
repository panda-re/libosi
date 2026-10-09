#include "DOMParsing.h"
#include "offset/offset.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <istream>
#include <libgen.h>
#include <map>
#include <stdexcept>
#include <stdint.h>
#include <vector>

#define POINTER 0x80000000

struct StructureType {
    uint64_t tid;

    StructureType() { tid = 0; }

    StructureType(uint64_t arg_tid) { tid = arg_tid; }
};

const struct StructureType* add_tid_to_map(struct StructureTypeLibrary*, uint64_t);

struct StructureTypeLibrary : Profile {
    std::string profile;
    std::map<uint64_t, const struct StructureType*> tid_map;

    uint64_t translate(const char* tname)
    {
        const std::string tname_str(tname);
        auto search = TRANSLATE.find(tname_str);
        if (search != TRANSLATE.end()) {
            return search->second;
        }
        return INVALID_TYPE;
    }

    uint64_t offset_of(uint64_t tid, const char* mname)
    {
        if (tid >= OFFSET.size()) {
            return INVALID_OFFSET;
        }
        const auto& type_offsets = OFFSET[tid];
        const std::string mname_str(mname);
        auto search = type_offsets.find(mname_str);
        if (search != type_offsets.end()) {
            return search->second.first;
        }
        return INVALID_OFFSET;
    }

    uint64_t type_of(uint64_t tid, const char* mname)
    {
        if (tid >= OFFSET.size()) {
            return INVALID_OFFSET;
        }
        const auto& type_offsets = OFFSET[tid];
        const std::string mname_str(mname);
        auto search = type_offsets.find(mname_str);
        if (search != type_offsets.end()) {
            return search->second.second;
        }
        return INVALID_OFFSET;
    }

    std::string translate_enum(const char* ename, long idx)
    {
        auto search = ENUM.find(std::string(ename));

        if (search != ENUM.end()) {
            auto name = search->second.find(idx);
            if (name != search->second.end()) {
                return name->second;
            }
        }

        return "unknown";
    }
};

const char* get_type_library_profile(const StructureTypeLibrary* tlib)
{
    return tlib->profile.c_str();
}

const struct StructureType* add_tid_to_map(struct StructureTypeLibrary* tlib,
                                           uint64_t tid)
{
    auto candidate = tlib->tid_map.find(tid);
    if (candidate != tlib->tid_map.end()) {
        return candidate->second;
    }
    struct StructureType* st =
        (struct StructureType*)std::malloc(sizeof(struct StructureType));
    st->tid = tid;
    tlib->tid_map[tid] = st;
    return st;
}

void deserialize_from_json(StructureTypeLibrary* tlib, std::istream& file)
{
    Profile profile;
    if (!ParseProfile(file, profile)) {
        throw std::runtime_error("Failed to parse offset profile");
    }

    tlib->OFFSET = std::move(profile.OFFSET);
    tlib->TRANSLATE = std::move(profile.TRANSLATE);
    tlib->ENUM = std::move(profile.ENUM);
}

struct StructureTypeLibrary* load_type_library(const char* profile)
{
    if (!profile) {
        return nullptr;
    }

    auto stm = new StructureTypeLibrary();
    stm->profile = std::string(profile);

    // LIBOSI_PROFILES_DIR overrides the compiled-in install location.
    const char* profiles_dir = std::getenv("LIBOSI_PROFILES_DIR");
    std::filesystem::path profile_path{
        (profiles_dir && *profiles_dir) ? profiles_dir : OFFSET_PROFILES_DIR};
    profile_path /= profile;
    profile_path += ".json";

    std::ifstream profile_file(profile_path);

    if (!profile_file.is_open()) {
        delete stm;
        return nullptr;
    }

    try {
        deserialize_from_json(stm, profile_file);
    } catch (...) {
        delete stm;
        return nullptr;
    }

    return stm;
}

const struct StructureType* translate(struct StructureTypeLibrary* tlib,
                                      const char* tname)
{
    auto tid = tlib->translate(tname);
    auto st = add_tid_to_map(tlib, tid);
    return st;
}

struct MemberResult* offset_of(struct StructureTypeLibrary* tlib,
                               const struct StructureType* type, const char* member)
{
    struct MemberResult* result =
        (struct MemberResult*)std::calloc(1, sizeof(struct MemberResult));
    result->offset = tlib->offset_of(type->tid, member);
    result->type = add_tid_to_map(tlib, tlib->type_of(type->tid, member));
    return result;
}

void free_member_result(struct MemberResult* mr) { std::free(mr); }

char* translate_enum(struct StructureTypeLibrary* tlib, const char* ename, long idx)
{
    auto name = tlib->translate_enum(ename, idx);
    return strdup(name.c_str());
}

uint64_t get_member_offset(struct StructureTypeLibrary* tlib,
                           const struct MemberResult& mresult)
{
    return mresult.offset;
}

const struct StructureType* get_member_type(struct StructureTypeLibrary* tlib,
                                            const struct MemberResult& mresult)
{
    return mresult.type;
}

bool is_valid_structure_type(const struct StructureType* st)
{
    return (st != nullptr) && (st->tid != INVALID_TYPE);
}

bool is_pointer_structure_type(const struct StructureType* tid)
{
    return (tid->tid) & POINTER;
}

const struct StructureType* dereference_st(struct StructureTypeLibrary* tlib,
                                           const struct StructureType* st)
{
    uint64_t new_tid = st->tid ^ POINTER;
    return add_tid_to_map(tlib, new_tid);
}

bool is_unknown_structure_type(const struct StructureType* st) { return st->tid == 0; }

bool equal_structure_types(const struct StructureType* st1,
                           const struct StructureType* st2)
{
    if (st1 == nullptr && st2 == nullptr) {
        return true;
    } else if (st1 == nullptr || st2 == nullptr) {
        return false;
    }
    return st1->tid == st2->tid;
}
