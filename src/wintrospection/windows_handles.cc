#include "windows_handles.h"
#include "wintrospection/i_t.h"
#include "wintrospection/wintrospection.h"

/**
 * TODO the recordings used for testing didn't have any handles that went
 * more than two tables deep. This has yet to be validated but seems correct ...
 */
#define WIDTH_x86 0x4
#define WIDTH_x64 0x8

#define H_ENTRY_SIZE_x86 0x08
#define H_ENTRY_SIZE_x64 0x10

#define LEVEL_MASK 0x0000000000000007
#define TABLE_MASK 0xfffffffffffffff8

#define HANDLE_SHIFT1_x86 0x02
#define HANDLE_SHIFT2_x86 0x0B
#define HANDLE_SHIFT3_x86 0x15

#define HANDLE_SHIFT1_x64 0x02
#define HANDLE_SHIFT2_x64 0x0A
#define HANDLE_SHIFT3_x64 0x13

#define HANDLE_MASK1_x86 0x000007fc
#define HANDLE_MASK2_x86 0x001ff800
#define HANDLE_MASK3_x86 0x7fe00000

#define HANDLE_MASK1_x64 0x000003fc
#define HANDLE_MASK2_x64 0x0007fc00
#define HANDLE_MASK3_x64 0x0ff80000

/**
 *  Returns the address to a Handle Table
 */
uint64_t get_l1_addr(uint64_t code, uint64_t index, bool x64)
{
    code &= TABLE_MASK;
    if (x64)
        return code + WIDTH_x64 * index;
    return code + WIDTH_x86 * index;
}

uint64_t get_l2_addr(uint64_t table_l1, uint64_t index, bool x64)
{
    if (!table_l1)
        return 0;
    if (x64)
        return table_l1 + WIDTH_x64 * index;
    return table_l1 + WIDTH_x86 * index;
}

/*
 *  Returns the address to an entry in the specified table
 */
uint64_t get_l1_entry(uint64_t code, uint64_t index, bool x64)
{
    code &= TABLE_MASK;
    if (x64)
        return code + H_ENTRY_SIZE_x64 * index;
    return code + H_ENTRY_SIZE_x86 * index;
}

uint64_t get_l2_entry(uint64_t table_l1, uint64_t index, bool x64)
{
    if (!table_l1)
        return 0;
    if (x64)
        return table_l1 + H_ENTRY_SIZE_x64 * index;
    return table_l1 + H_ENTRY_SIZE_x86 * index;
}

uint64_t get_l3_entry(uint64_t table_l2, uint64_t index, bool x64)
{
    if (!table_l2)
        return 0;
    if (x64)
        return table_l2 + H_ENTRY_SIZE_x64 * index;
    return table_l2 + H_ENTRY_SIZE_x86 * index;
}

/**
 * In this function, obj will be used for virtual memory reading. It rarely is
 * used for any type information.
 *
 */
osi::i_t resolve_handle_table_entry(struct WindowsProcessOSI* posi, uint64_t handle, bool x64)
{
    osi::i_t obj(posi->vmem, posi->tlib, posi->eprocess_address, "_EPROCESS");
    auto code = obj("ObjectTable")["TableCode"].getu();
    obj.set_type("UNKNOWN"); // just going to be a vmem interface now

    auto level = code & LEVEL_MASK;
    uint64_t entry, index;
    switch (level) {
    case 0: {
        // get entry from handle table level 1
        if (x64)
            index = (handle & HANDLE_MASK1_x64) >> HANDLE_SHIFT1_x64;
        else
            index = (handle & HANDLE_MASK1_x86) >> HANDLE_SHIFT1_x86;
        entry = get_l1_entry(code, index, x64);
    } break;

    case 1: {
        // get entry from handle table level 2 after resolving it in level 1
        if (x64)
            index = (handle & HANDLE_MASK2_x64) >> HANDLE_SHIFT2_x64;
        else
            index = (handle & HANDLE_MASK2_x86) >> HANDLE_SHIFT2_x86;
        obj.set_address(get_l1_addr(code, index, x64));

        uint64_t table_l1 = obj.getu();

        if (x64)
            index = (handle & HANDLE_MASK1_x64) >> HANDLE_SHIFT1_x64;
        else
            index = (handle & HANDLE_MASK1_x86) >> HANDLE_SHIFT1_x86;
        entry = get_l2_entry(table_l1, index, x64);
    } break;

    case 2: {
        // get entry from handle table level 3 after resolving it in level 2
        // which you resolve in level 1
        if (x64)
            index = (handle & HANDLE_MASK3_x64) >> HANDLE_SHIFT3_x64;
        else
            index = (handle & HANDLE_MASK3_x86) >> HANDLE_SHIFT3_x86;
        obj.set_address(get_l1_addr(code, index, x64));

        uint64_t table_l1 = obj.getu();

        if (x64)
            index = (handle & HANDLE_MASK2_x64) >> HANDLE_SHIFT2_x64;
        else
            index = (handle & HANDLE_MASK2_x86) >> HANDLE_SHIFT2_x86;
        obj.set_address(get_l2_addr(table_l1, index, x64));

        uint64_t table_l2 = obj.getu();

        if (x64)
            index = (handle & HANDLE_MASK1_x64) >> HANDLE_SHIFT1_x64;
        else
            index = (handle & HANDLE_MASK1_x86) >> HANDLE_SHIFT1_x86;
        entry = get_l3_entry(table_l2, index, x64);
    } break;

    default:
        return osi::i_t();
    }

    if (!entry)
        return osi::i_t();

    // get the object header from our entry
    uint64_t header = obj.set_address(entry).getu() & TABLE_MASK;
    return obj.set_address(header).set_type("_OBJECT_HEADER");
}
