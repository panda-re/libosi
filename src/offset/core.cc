#include "offset/offset.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <libgen.h>
#include <map>
#include <stdint.h>

#include "profiles/win7_sp0_x64.h"
#include "profiles/win7_sp0_x86.h"
#include "profiles/win7_sp1_x64.h"
#include "profiles/win7_sp1_x86.h"

#define POINTER 0x80000000

typedef uint64_t (*TranslateTypeFunc)(const char*);
typedef uint64_t (*OffsetOfMemberFunc)(uint64_t tid, const char* mname);
typedef uint64_t (*TypeOfMemberFunc)(uint64_t tid, const char* mname);

struct StructureType {
    uint64_t tid;

    StructureType() { tid = 0; }

    StructureType(uint64_t arg_tid) { tid = arg_tid; }
};

const struct StructureType* add_tid_to_map(struct StructureTypeLibrary*, uint64_t);

struct StructureTypeLibrary {
    TranslateTypeFunc translate;
    OffsetOfMemberFunc offset_of;
    TypeOfMemberFunc type_of;
    std::map<uint64_t, const struct StructureType*> tid_map;
};

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

struct StructureTypeLibrary* load_type_library(const char* profile)
{
    if (!profile) {
        return nullptr;
    }

    auto stm = new StructureTypeLibrary();
    if (strcmp(profile, "windows-32-7sp0") == 0) {
        stm->translate = windows_7sp0_x86::translate_type;
        stm->offset_of = windows_7sp0_x86::offset_of_member;
        stm->type_of = windows_7sp0_x86::type_of_member;
    } else if (strcmp(profile, "windows-64-7sp0") == 0) {
        stm->translate = windows_7sp0_x64::translate_type;
        stm->offset_of = windows_7sp0_x64::offset_of_member;
        stm->type_of = windows_7sp0_x64::type_of_member;
    } else if (strcmp(profile, "windows-32-7sp1") == 0) {
        stm->translate = windows_7sp1_x86::translate_type;
        stm->offset_of = windows_7sp1_x86::offset_of_member;
        stm->type_of = windows_7sp1_x86::type_of_member;
    } else if (strcmp(profile, "windows-64-7sp1") == 0) {
        stm->translate = windows_7sp1_x64::translate_type;
        stm->offset_of = windows_7sp1_x64::offset_of_member;
        stm->type_of = windows_7sp1_x64::type_of_member;
    } else {
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
