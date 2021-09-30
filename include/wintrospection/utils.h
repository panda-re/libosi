#ifndef __LIBINTRO_WINDOWS_INTROSPECTION_UTILS_H
#define __LIBINTRO_WINDOWS_INTROSPECTION_UTILS_H

#include <iohal/memory/virtual_memory.h>
#include <offset/i_t.h>
#include <offset/offset.h>
#include <set>

bool find_kernel_base(VirtualMemory* vmem, vm_addr_t kpcr, vm_addr_t* base);

bool scan_for_kdbg(VirtualMemory* vmem, vm_addr_t kernel_base, vm_addr_t* kdbg);
bool scan_for_version64(VirtualMemory* vmem, vm_addr_t kernel_base, vm_addr_t kdbg,
                        vm_addr_t* version64);

vm_addr_t get_address_active_process_head(VirtualMemory* vmem, vm_addr_t kdbg);

std::set<uint64_t> get_process_list(VirtualMemory* vmem, vm_addr_t kdbg,
                                    struct StructureTypeLibrary* tlib);

void print_process_list(std::set<uint64_t> proc_list);

#endif
