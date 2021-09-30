#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <libgen.h>
#include <map>
#include <stdint.h>

#include "windows_introspection.h"
#include "windows_static_offsets.h"
#include <iohal/memory/virtual_memory.h>
#include <offset/i_t.h>
#include <offset/offset.h>

uint64_t WindowsIntrospectionImpl::process_list_head(void)
{
    return get_address_active_process_head(m_vmem, m_kdbg);
}

bool WindowsIntrospectionImpl::is64bit(void) { return m_vmem->get_pointer_width() == 8; }

bool WindowsIntrospectionImpl::initialize(struct StructureTypeLibrary* tlib,
                                          vm_addr_t kpcr, pm_addr_t asid, uint64_t kdbg)
{
    return false;
}

uint64_t WindowsIntrospectionImpl::get_kdbg() { return m_kdbg; }

VirtualMemory* WindowsIntrospectionImpl::vmem() { return m_vmem; }

struct StructureTypeLibrary* WindowsIntrospectionImpl::tlib() { return m_tlib; }
