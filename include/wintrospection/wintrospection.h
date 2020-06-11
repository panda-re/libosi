#ifndef __LIBINTRO_WINTROSPECTION_H
#define __LIBINTRO_WINTROSPECTION_H

#include <stdbool.h>
#include <stdint.h>
#include <memory>
#include <iohal/memory/virtual_memory.h>

struct WindowsKernelDetails {
    uint8_t pointer_width;
    uint64_t kpcr;
    uint64_t kernelbase;
    uint64_t PsActiveProcessHead;
    uint64_t kdbg;
    uint64_t version64;
    uint64_t system_asid;
};

struct WindowsKernelOSI {
    struct StructureTypeLibrary* kernel_tlib;
    struct PhysicalMemory* pmem;
    std::shared_ptr<VirtualMemory> system_vmem;
    struct WindowsKernelDetails* details;
};

struct ProcessOSI {
    struct StructureTypeLibrary* tlib;
    std::shared_ptr<VirtualMemory> vmem;
    vm_addr_t eprocess_address;
};



struct WindowsInstrospection;
struct process;
struct module_entry;
struct process_list;
struct module_list;

bool initialize_windows_kernel_osi(struct WindowsKernelOSI* kosi,
                                   struct WindowsKernelDetails* kdetails,
                                   uint64_t current_asid, bool pae);
struct process* kosi_get_current_process(struct WindowsKernelOSI* kosi);

struct process_list* get_process_list(struct WindowsKernelOSI* kosi);
struct process* process_list_next(struct process_list* plist);
struct process* create_process(struct WindowsKernelOSI* kosi,
                               uint64_t eprocess_address);
struct process* create_process_from_asid(struct WindowsKernelOSI* kosi,
                               uint64_t asid);
uint64_t get_pid_from_asid(struct WindowsKernelOSI* kosi,
                               uint64_t asid);
uint64_t get_eproc_addr_from_asid(struct WindowsKernelOSI* kosi,
                               uint64_t asid);
void free_process_list(struct process_list* plist);

bool init_process_osi_from_pid(struct WindowsKernelOSI* kosi, struct ProcessOSI* process_osi, uint64_t pid);
bool init_process_osi(struct WindowsKernelOSI* kosi, struct ProcessOSI* process, uint64_t eprocess);
void uninit_process_osi(struct ProcessOSI* kosi);



uint64_t process_get_eprocess(const struct process*);
const char* process_get_shortname(const struct process*);
uint64_t process_get_pid(const struct process*);
uint64_t process_get_ppid(const struct process*);
uint64_t process_get_asid(const struct process*);
uint64_t process_createtime(const struct process*);
bool process_is_wow64(const struct process*);
void free_process(struct process*);

const uint8_t MODULELIST_LOAD_ORDER = 0;
struct module_list* get_module_list(struct WindowsKernelOSI* process_osi,
                                    const struct process* p,
                                    uint8_t order);
struct module_entry* module_list_next(struct module_list*);
void free_module_list(struct module_list* mlist);

uint64_t module_entry_get_base_address(struct module_entry*);
uint32_t module_entry_get_checksum(struct module_entry*);
uint64_t module_entry_get_entrypoint(struct module_entry*);
uint32_t module_entry_get_flags(struct module_entry*);
uint32_t module_entry_get_timedatestamp(struct module_entry*);
uint16_t module_entry_get_loadcount(struct module_entry*);
uint32_t module_entry_get_modulesize(struct module_entry*);
bool module_entry_is_wow64(struct module_entry*);
const char* module_entry_get_dllpath(struct module_entry*);
void free_module_entry(struct module_entry*);


#endif
