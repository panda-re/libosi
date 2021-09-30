#ifndef __LIBINTRO_WINDOWS_INTROSPECTION_H
#define __LIBINTRO_WINDOWS_INTROSPECTION_H

#include "offset/offset.h"
#include "wintrospection/utils.h"
#include <iohal/memory/virtual_memory.h>
#include <offset/i_t.h>
#include <set>

class WindowsIntrospectionImpl
{
public:
    WindowsIntrospectionImpl(struct PhysicalMemory* pmem, uint8_t pointer_width)
        : m_pmem(pmem), m_vmem(nullptr), m_tlib(nullptr), m_kdbg(0),
          m_pointer_width(pointer_width), m_kernelbase(0)
    {
    }

    WindowsIntrospectionImpl(const WindowsIntrospectionImpl& other) = delete;
    WindowsIntrospectionImpl& operator=(const WindowsIntrospectionImpl&) = delete;

    bool initialize(struct StructureTypeLibrary* tlib, vm_addr_t kpcr, pm_addr_t asid,
                    vm_addr_t kdbg);
    uint64_t process_list_head(void);
    uint64_t get_kdbg(void);
    VirtualMemory* vmem(void);
    struct StructureTypeLibrary* tlib(void);
    bool is64bit(void);

private:
    struct PhysicalMemory* m_pmem;
    VirtualMemory* m_vmem;
    struct StructureTypeLibrary* m_tlib;
    uint64_t m_kdbg;
    const uint8_t m_pointer_width;
    vm_addr_t m_kernelbase;
};

#endif
