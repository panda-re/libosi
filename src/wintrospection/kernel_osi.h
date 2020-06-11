#ifndef __OSI_KERNEL
#define __OSI_KERNEL

#include <stdint.h>
#include <cstring>
#include <cstdio>
#include <dlfcn.h>
#include <cstdlib>
#include <libgen.h>
#include <map>

#include <iohal/memory/virtual_memory.h>
#include "offset/offset.h"
#include "wintrospection/iterator.h"
#include "wintrospection/i_t.h"
#include "windows_introspection.h"
#include "windows_static_offsets.h"

namespace osi {
	class kernel {
	private:
		std::shared_ptr<VirtualMemory> vmem;
		vm_addr_t kdbg;
		struct StructureTypeLibrary* tlib;
	
	public:
		kernel(std::shared_ptr<VirtualMemory> vm, vm_addr_t kdg, struct StructureTypeLibrary* lib) {
			vmem = vm;
			kdbg = kdg;
			tlib = lib;
		}
		
		std::set<uint64_t> get_process_list() {
		    std::set<uint64_t> observed_pids;
		    vm_addr_t eproc_address;
		    uint8_t ptr_width = vmem->get_pointer_width();
		    
		    if (ptr_width == 4) {
		        eproc_address = get_address_active_process_head(vmem.get(), kdbg) - static_offsets::i386::ACTIVEPROCESSLINK_OFFSET;
		    } else if (ptr_width == 8) {
		        eproc_address = get_address_active_process_head(vmem.get(), kdbg) - static_offsets::amd64::ACTIVEPROCESSLINK_OFFSET;
		    } else {
		        return observed_pids;
		    }

		    osi::i_t process;
		    osi::i_t eproc = osi::i_t(vmem, tlib, eproc_address, "_EPROCESS");
		    osi::iterator p(eproc, "ActiveProcessLinks");
		    do {
		        process = *p++;
		        
		        auto dtb = process["Pcb"]["DirectoryTableBase"].getu();
		         // _EPROCESS.is_valid from volatility, used to filter out PsActiveProcessHead header
		        if (dtb == 0 || (dtb % 0x20) != 0) {
		            //fprintf(stderr, "Process %u has dtb %u and is getting skipped\n", process["UniqueProcessId"].getu(), dtb);
		            continue;
		        }

		        uint64_t pid = process["UniqueProcessId"].getu();
		        observed_pids.insert(pid);
		    } while(*p != eproc);
		    
		    return observed_pids;
		}

		void print_process_list(std::set<uint64_t> proc_list) {
		    for (std::set<uint64_t>::iterator it=proc_list.begin(); it!=proc_list.end(); ++it)
		    {
		        fprintf(stderr, "PID: %lu\n", *it);
		    }
		}	
	};
}


bool find_kernel_base(VirtualMemory* vmem, vm_addr_t kpcr, vm_addr_t* base);
bool find_kernel_base_i386(VirtualMemory* vmem, vm_addr_t kpcr, vm_addr_t* base);
bool find_kernel_base_amd64(VirtualMemory* vmem, vm_addr_t kpcr, vm_addr_t* base);
bool scan_for_kdbg(VirtualMemory* vmem, vm_addr_t kernel_base, vm_addr_t* kdbg);
vm_addr_t get_address_active_process_head(VirtualMemory* vmem, vm_addr_t kdbg);


#endif // __OSI_KERNELs
