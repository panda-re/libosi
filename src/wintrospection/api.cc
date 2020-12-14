#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <glib.h>
#include <libgen.h>
#include <map>
#include <memory>
#include <stdint.h>
#include <vector>

#include "iohal/memory/virtual_memory.h"
#include "offset/offset.h"
#include "windows_introspection.h"
#include "windows_static_offsets.h"
#include "wintrospection/iterator.h"
#include "wintrospection/ustring.h"
#include "wintrospection/wintrospection.h"

struct process_list {
    uint64_t head;
    uint64_t ptr;
    WindowsKernelOSI* kosi;
};

struct process {
    uint64_t eprocess_address;
    char shortname[17];
    uint64_t pid;
    uint64_t ppid;
    uint64_t asid;
    uint64_t createtime;
    bool is_wow64;
};

struct module_list {
    std::shared_ptr<VirtualMemory> vmem;
    struct StructureTypeLibrary* tlib;
    std::vector<uint64_t>* module_list;
    std::map<uint64_t, bool>* modules;
    uint16_t idx;
};

#define MAX_PATH_SIZE 4096
struct module_entry {
    uint64_t module_entry;
    uint64_t base_address;
    uint32_t checksum;
    uint64_t entrypoint;
    uint32_t flags;
    uint32_t timedatestamp;
    uint16_t loadcount;
    uint32_t modulesize;
    char dllpath[MAX_PATH_SIZE];
    bool is_wow64;
};

uint64_t get_next_process_link(struct WindowsKernelOSI* kosi, uint64_t start_address);

std::string maybe_parse_unicode_string(osi::ustring& ustr)
{
    try {
        return ustr.as_utf8();
    } catch (...) {
        return std::string("");
    }
}

struct process_list* get_process_list(struct WindowsKernelOSI* kosi)
{
    auto plist = new struct process_list;
    plist->head = kosi->details->PsActiveProcessHead;
    plist->head -= ((kosi->details->pointer_width == 8)
                        ? static_offsets::amd64::ACTIVEPROCESSLINK_OFFSET
                        : static_offsets::i386::ACTIVEPROCESSLINK_OFFSET);

    plist->head = get_next_process_link(kosi, plist->head);

    plist->ptr = 0;
    plist->kosi = kosi;
    return plist;
}

uint64_t get_next_process_link(struct WindowsKernelOSI* kosi, uint64_t start_address)
{
    auto vmem = kosi->system_vmem;
    auto tlib = kosi->kernel_tlib;
    osi::i_t eproc(vmem, tlib, start_address, "_EPROCESS");
    osi::iterator process_itr(eproc, "ActiveProcessLinks");
    // maximum number of attempts before bailing
    for (unsigned int ix = 0; ix < 3; ++ix) {
        try {
            auto next_process = *process_itr++;

            auto dtb = next_process["Pcb"]["DirectoryTableBase"].getu();
            // _EPROCESS.is_valid from volatility
            if (dtb == 0 || (dtb % 0x20) != 0) {
                continue;
            }
            auto peb = next_process("Peb"); // try this to see if valid process (if
                                            // invalid, will return peb address = 0)
            if (peb.get_address() == 0 && next_process["UniqueProcessId"].getu() != 4)
                continue;

            return next_process.get_address();
        } catch (...) {
            continue;
        }
    }
    return 0;
}

struct process* process_list_next(struct process_list* plist)
{
    try {
        if (plist->ptr == plist->head) {
            return nullptr;
        } else if (plist->ptr == 0) {
            plist->ptr = plist->head;
        }

        auto p = create_process(plist->kosi, plist->ptr);
        plist->ptr = get_next_process_link(plist->kosi, plist->ptr);

        return p;
    } catch (...) {
        return nullptr;
    }
    return nullptr;
}

static void sanitize_process_name(char* process_name, size_t nbytes)
{
    for (size_t ix = 0; ix < nbytes; ++ix) {
        if (process_name[ix] == 0) {
            break;
        }
        if (!g_ascii_isprint(process_name[ix])) {
            process_name[ix] = '?';
        }
    }
}

struct process* create_process(struct WindowsKernelOSI* kosi, uint64_t eprocess_address)
{
    auto p = (struct process*)std::malloc(sizeof(struct process));
    std::memset(p, 0, sizeof(struct process));
    p->eprocess_address = eprocess_address;
    auto vmem = kosi->system_vmem;
    auto tlib = kosi->kernel_tlib;
    osi::i_t eproc(vmem, tlib, eprocess_address, "_EPROCESS");

    eproc["ImageFileName"].getx(p->shortname, 16);

    sanitize_process_name(p->shortname, 16);
    // const char shortname[16];
    p->pid = eproc["UniqueProcessId"].getu();
    p->ppid = eproc["InheritedFromUniqueProcessId"].getu();
    p->asid = eproc["Pcb"]["DirectoryTableBase"].getu();
    p->createtime = eproc["CreateTime"].get64();
    if (vmem->get_pointer_width() == 4) {
        p->is_wow64 = false;
    } else {
        p->is_wow64 = (eproc["Wow64Process"].getu() != 0);
    }
    return p;
}

struct process* create_process_from_asid(struct WindowsKernelOSI* kosi, uint64_t asid)
{
    auto vmem = kosi->system_vmem;
    auto tlib = kosi->kernel_tlib;

    auto plist = get_process_list(kosi);
    auto process = process_list_next(plist);

    while (process != nullptr) {
        uint64_t eproc_address = 0;
        uint64_t proc_asid = process_get_asid(process);
        if (proc_asid == asid) {
            eproc_address = process_get_eprocess(process);
        }
        free_process(process);

        if (eproc_address != 0) {
            free_process_list(plist);
            return create_process(kosi, eproc_address);
        }
        process = process_list_next(plist);
    }
    free_process_list(plist);
    return nullptr;
}

uint64_t get_pid_from_asid(struct WindowsKernelOSI* kosi, uint64_t asid)
{
    auto vmem = kosi->system_vmem;
    auto tlib = kosi->kernel_tlib;

    auto plist = get_process_list(kosi);
    auto process = process_list_next(plist);

    while (process != nullptr) {
        uint64_t eproc_address = 0;
        uint64_t proc_asid = process_get_asid(process);
        if (proc_asid == asid) {
            eproc_address = process_get_eprocess(process);
        }
        free_process(process);

        if (eproc_address != 0) {
            free_process_list(plist);
            auto vmem = kosi->system_vmem;
            auto tlib = kosi->kernel_tlib;
            osi::i_t eproc(vmem, tlib, eproc_address, "_EPROCESS");
            return eproc["UniqueProcessId"].getu();
        }
        process = process_list_next(plist);
    }
    free_process_list(plist);
    return 0;
}

uint64_t get_eproc_addr_from_asid(struct WindowsKernelOSI* kosi, uint64_t asid)
{
    auto vmem = kosi->system_vmem;
    auto tlib = kosi->kernel_tlib;

    auto plist = get_process_list(kosi);
    auto process = process_list_next(plist);

    while (process != nullptr) {
        uint64_t eproc_address = 0;
        uint64_t proc_asid = process_get_asid(process);
        if (proc_asid == asid) {
            eproc_address = process_get_eprocess(process);
        }
        free_process(process);

        if (eproc_address != 0) {
            free_process_list(plist);
            return eproc_address;
        }
        process = process_list_next(plist);
    }
    free_process_list(plist);
    return 0;
}
void free_process(struct process* p)
{
    if (p) {
        delete p;
    }
}

void free_process_list(struct process_list* plist)
{
    if (plist) {
        delete plist;
    }
}

uint64_t process_get_eprocess(const struct process* plist)
{
    return plist->eprocess_address;
}

uint64_t process_get_pid(const struct process* plist) { return plist->pid; }

uint64_t process_get_ppid(const struct process* plist) { return plist->ppid; }

const char* process_get_shortname(const struct process* p) { return p->shortname; }

uint64_t process_get_asid(const struct process* p) { return p->asid; }

uint64_t process_createtime(const struct process* p) { return p->createtime; }

bool process_is_wow64(const struct process* p) { return p->is_wow64; }

struct module_list* get_module_list(struct WindowsKernelOSI* kosi,
                                    const struct process* p, uint8_t order)
{
    auto mlist = (struct module_list*)std::calloc(1, sizeof(struct module_list));
    if (!mlist) {
        return nullptr;
    }
    mlist->module_list = new std::vector<uint64_t>();
    mlist->modules = new std::map<uint64_t, bool>();

    // Deep copy, we are going to change the asid
    mlist->vmem = std::make_shared<VirtualMemory>(*(kosi->system_vmem));
    mlist->tlib = kosi->kernel_tlib;

    // Access the kernel-only members to find process address space
    // from whatever address space we are in now
    osi::i_t proc(mlist->vmem, mlist->tlib, process_get_eprocess(p), "_EPROCESS");
    uint64_t new_asid = proc["Pcb"]["DirectoryTableBase"].getu();

    // Update this virtual memory object to use the correct ASID for this process
    mlist->vmem->set_asid(new_asid);
    mlist->idx = 0;
    proc = osi::i_t(mlist->vmem, mlist->tlib, process_get_eprocess(p), "_EPROCESS");

    bool is_wow64 = process_is_wow64(p);

    if (is_wow64) {
        try {
            uint32_t peb32_address = proc["Wow64Process"].get32();
            osi::i_t peb32 = osi::i_t(proc.get_virtual_memory_shared(),
                                      proc.get_type_library(), peb32_address, "_PEB32");
            uint32_t ldr32_address = peb32["Ldr"].get32();
            osi::i_t ldr32 =
                osi::i_t(proc.get_virtual_memory_shared(), proc.get_type_library(),
                         ldr32_address, "_PEB_LDR_DATA32");
            auto ldr_table32 =
                ldr32["InLoadOrderModuleList"].set_type("_LDR_DATA_TABLE_ENTRY32");
            osi::iterator32 pitr(ldr_table32, "InLoadOrderLinks");
            pitr++; // skip head_sentinel
            do {
                auto entry = *pitr;
                auto mod_address = entry.get_address();
                if (mlist->modules->find(mod_address) != mlist->modules->end()) {
                    fprintf(
                        stderr,
                        "WARNING: Found an anomoly (duplicated module), jumping out...");
                    // Fail hard, we've only seen this when the list is corrupted
                    mlist->module_list->clear();
                    mlist->modules->clear();
                    break;
                }
                mlist->module_list->push_back(mod_address);
                mlist->modules->insert(std::pair<uint64_t, bool>(mod_address, true));
                if (!pitr.has_next()) {
                    break;
                }
                pitr++;
            } while (*pitr != ldr_table32);
        } catch (const std::exception& e) {
            std::cerr << e.what();
        }
    }
    auto peb = proc("Peb");
    if (peb.get_address() == 0) {
        free_module_list(mlist);
        return nullptr;
    }
    try {
        auto ldr = peb("Ldr");
        auto ldr_table = ldr["InLoadOrderModuleList"].set_type("_LDR_DATA_TABLE_ENTRY");
        osi::iterator pitr(ldr_table, "InLoadOrderLinks");
        pitr++; // skip head_sentinel
        do {
            auto entry = *pitr;
            auto mod_address = entry.get_address();
            if (mlist->modules->find(mod_address) != mlist->modules->end()) {
                fprintf(stderr,
                        "WARNING: Found an anomoly (duplicated module), jumping out...");
                // Fail hard, we've only seen this when the list is corrupted
                mlist->module_list->clear();
                mlist->modules->clear();
                break;
            }
            mlist->module_list->push_back(mod_address);
            mlist->modules->insert(std::pair<uint64_t, bool>(mod_address, false));
            if (!pitr.has_next()) {
                break;
            }
            pitr++;
        } while (*pitr != ldr_table);
    } catch (const std::exception& e) {
        // TODO Make sure this is paged out and not just generic failure
        free_module_list(mlist);
        return nullptr;
    }

    return mlist;
}

struct module_entry* create_module_entry(struct module_list* mlist,
                                         uint64_t module_entry_addr, bool is_wow64)
{
    if (is_wow64) {
        auto mentry = (struct module_entry*)std::calloc(1, sizeof(struct module_entry));
        osi::i_t data_table_entry(mlist->vmem, mlist->tlib, module_entry_addr,
                                  "_LDR_DATA_TABLE_ENTRY32");
        mentry->module_entry = module_entry_addr;
        // No point if we can't capture these
        try {
            // fprintf(stderr, "MODULE ENTRY: %lx\n", mentry->module_entry);

            mentry->base_address = data_table_entry["DllBase"].get32();
            /*
            if (mentry->base_address == 0) {
                std::free(mentry);
                return nullptr;
            }
            */
            mentry->modulesize = data_table_entry["SizeOfImage"].get32();
            mentry->checksum = data_table_entry["CheckSum"].get32();
            mentry->entrypoint = data_table_entry["EntryPoint"].get32();
            mentry->flags = data_table_entry["Flags"].get32();
            mentry->timedatestamp = data_table_entry["TimeDateStamp"].get32();
            mentry->loadcount = data_table_entry["LoadCount"].get16();

            osi::ustring dllpath(data_table_entry["FullDllName"]);
            std::string dllpath_utf8 = maybe_parse_unicode_string(dllpath);
            strncpy(mentry->dllpath, dllpath_utf8.c_str(), MAX_PATH_SIZE - 1);

            //fprintf(stderr, "WOW64 base_address: %lu\n", module_entry_get_base_address(mentry));
            //fprintf(stderr, "WOW64 modulesize: %lu\n", module_entry_get_modulesize(mentry));
            //fprintf(stderr, "WOW64 checksum: %lu\n", module_entry_get_checksum(mentry));
            //fprintf(stderr, "WOW64 entrypoint: %lu\n", module_entry_get_entrypoint(mentry));
            //fprintf(stderr, "WOW64 flags: %lu\n", module_entry_get_flags(mentry));
            //fprintf(stderr, "WOW64 TimeDateStamp: %lu\n", module_entry_get_timedatestamp(mentry));
            //fprintf(stderr, "WOW64 loadcount: %lu\n", module_entry_get_loadcount(mentry));
            //fprintf(stderr, "WOW64 DLLPATH: %s\n", dllpath_utf8.c_str());

        } catch (...) {
            return nullptr;
        }
        return mentry;
    }

    auto mentry = (struct module_entry*)std::calloc(1, sizeof(struct module_entry));
    osi::i_t data_table_entry(mlist->vmem, mlist->tlib, module_entry_addr,
                              "_LDR_DATA_TABLE_ENTRY");

    mentry->module_entry = module_entry_addr;
    // No point if we can't capture these
    try {
        // fprintf(stderr, "MODULE ENTRY: %lx\n", mentry->module_entry);

        mentry->base_address = data_table_entry["DllBase"].getu();

        /*if (mentry->base_address == 0) {
            std::free(mentry);
            return nullptr;
        }
        */
        mentry->modulesize = data_table_entry["SizeOfImage"].get32();
        mentry->checksum = data_table_entry["CheckSum"].get32();
        mentry->entrypoint = data_table_entry["EntryPoint"].getu();
        mentry->flags = data_table_entry["Flags"].get32();
        mentry->timedatestamp = data_table_entry["TimeDateStamp"].get32();
        mentry->loadcount = data_table_entry["LoadCount"].get16();

        osi::ustring dllpath(data_table_entry["FullDllName"]);
        std::string dllpath_utf8 = maybe_parse_unicode_string(dllpath);
        strncpy(mentry->dllpath, dllpath_utf8.c_str(), MAX_PATH_SIZE - 1);

    } catch (...) {
        return nullptr;
    }
    return mentry;
}

void free_module_entry(struct module_entry* me)
{
    if (me) {
        std::free(me);
    }
}

struct module_entry* module_list_next(struct module_list* mlist)
{
    if (mlist->module_list->size() == 0) {
        return nullptr;
    } else if (mlist->module_list->size() <= mlist->idx) {
        return nullptr;
    }

    auto mod_address = (*(mlist->module_list))[mlist->idx++];
    bool mod_iswow64 = (*(mlist->modules))[mod_address];
    auto mod_entry = create_module_entry(mlist, mod_address, mod_iswow64);
    if (!mod_entry) {
        // skip invalid
        return module_list_next(mlist);
    }
    return mod_entry;
}

void free_module_list(struct module_list* mlist)
{
    if (mlist) {
        if (mlist->vmem) {
            mlist->vmem.reset();
        }

        delete mlist->module_list;
        delete mlist->modules;
        std::free(mlist);
    }
}

uint64_t module_entry_get_base_address(struct module_entry* me)
{
    return me->base_address;
}

uint32_t module_entry_get_checksum(struct module_entry* me) { return me->checksum; }

uint64_t module_entry_get_entrypoint(struct module_entry* me) { return me->entrypoint; }

uint32_t module_entry_get_flags(struct module_entry* me) { return me->flags; }

uint32_t module_entry_get_timedatestamp(struct module_entry* me)
{
    return me->timedatestamp;
}

uint16_t module_entry_get_loadcount(struct module_entry* me) { return me->loadcount; }

uint32_t module_entry_get_modulesize(struct module_entry* me) { return me->modulesize; }

bool module_entry_is_wow64(struct module_entry* me) { return me->is_wow64; }

const char* module_entry_get_dllpath(struct module_entry* me) { return me->dllpath; }

bool init_process_osi_from_pid(struct WindowsKernelOSI* kosi,
                               struct ProcessOSI* process_osi, uint64_t target_pid)
{
    auto plist = get_process_list(kosi);
    if (!plist) {
        return false;
    }
    auto process = process_list_next(plist);
    while (process) {
        auto pid = process_get_pid(process);
        if (pid == target_pid) {
            auto eprocess_addr = process_get_eprocess(process);
            free_process(process);
            free_process_list(plist);
            return init_process_osi(kosi, process_osi, eprocess_addr);
        }
        free_process(process);
        process = process_list_next(plist);
    }
    free_process_list(plist);
    return false;
}

bool init_process_osi(struct WindowsKernelOSI* kosi, struct ProcessOSI* process_osi,
                      uint64_t eprocess_address)
{
    process_osi->tlib = kosi->kernel_tlib; // TODO change if wow64
    process_osi->vmem = std::make_shared<VirtualMemory>(*kosi->system_vmem);
    process_osi->kosi = kosi;
    process_osi->eprocess_address = eprocess_address;
    osi::i_t proc(process_osi->vmem, process_osi->tlib, eprocess_address, "_EPROCESS");
    uint64_t new_asid = proc["Pcb"]["DirectoryTableBase"].getu();
    process_osi->vmem->set_asid(new_asid);
    process_osi->createtime = proc["CreateTime"].get64();
    process_osi->pid = proc["UniqueProcessId"].getu();
    proc["ImageFileName"].getx(process_osi->shortname, 16);
    return true;
}

void uninit_process_osi(struct ProcessOSI* process_osi)
{
    process_osi->vmem.reset(); // TODO Process OSI should be a class
                               // with a destructor
}

static osi::i_t kosi_get_current_process_object(struct WindowsKernelOSI* kosi)
{
    osi::i_t kpcr =
        osi::i_t(kosi->system_vmem, kosi->kernel_tlib, kosi->details->kpcr, "_KPCR");

    // if (is_32bit() || is_winxp()) {
    osi::i_t eprocess;
    if (kosi->system_vmem->get_pointer_width() == 4) {
        auto ethread = kpcr["PrcbData"]("CurrentThread");
        eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
    } else {
        auto ethread = kpcr["Prcb"]("CurrentThread").set_type("_ETHREAD");
        eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
    }
    return eprocess;
}

uint64_t kosi_get_current_process_address(struct WindowsKernelOSI* kosi)
{
    auto eprocess = kosi_get_current_process_object(kosi);
    return eprocess.get_address();
}

struct process* kosi_get_current_process(struct WindowsKernelOSI* kosi)
{
    auto eprocess = kosi_get_current_process_object(kosi);
    return create_process(kosi, eprocess.get_address());
}

static inline uint16_t get_page_shift()
{
    return 12; // 4k pages
}

const std::pair<uint64_t, uint64_t> NO_MATCH = {0, 0};
static inline std::pair<uint64_t, uint64_t>
find_vad_range(osi::i_t& eprocess, struct ProcessOSI* process_osi, uint64_t addr)
{
    auto page_shift = get_page_shift();
    uint64_t target_vpn = addr >> page_shift;
    auto vad_root = eprocess["VadRoot"];
    auto working = vad_root["BalancedRoot"];

    while (working.get_address() != 0) {
        // Is this the target node?
        auto starting_vpn = working["StartingVpn"].getu();
        auto ending_vpn = working["EndingVpn"].getu();
        if ((starting_vpn <= target_vpn) && (target_vpn <= ending_vpn)) {
            working = working.set_type("_MMVAD");
            auto proto_pte = working["FirstPrototypePte"].getu();
            if (proto_pte == 0) {
                fprintf(stderr, "Failed to read prototype pte\n");
                return NO_MATCH;
            }
            uint64_t vad_offset = addr - (starting_vpn << page_shift);
            uint64_t vad_pte_index = vad_offset >> page_shift;
            uint64_t pte_addr =
                proto_pte + (vad_pte_index * process_osi->vmem->get_pointer_width());

            osi::i_t mmpte(process_osi->vmem, process_osi->tlib, pte_addr, "_MMPTE");
            try {
                uint64_t pte = mmpte.getu();
                return std::pair<uint64_t, uint64_t>(pte_addr, pte);
            } catch (const std::exception& e) {
                fprintf(stderr, "Failed to read mmpte at %lx\n", pte_addr);
                return NO_MATCH;
            }
        }
        // check left arm
        if (target_vpn < starting_vpn) {
            working = working("LeftChild");
        } else if (ending_vpn < target_vpn) {
            working = working("RightChild");
        } else {
            return NO_MATCH;
        }
    }
    return NO_MATCH;
}

static bool valid_pte(uint64_t pte)
{
    if ((pte & (0x1 << 0)) == 1) {
        return true;
    }

    // Not valid + is prototype
    if ((pte & (0x1 << 10)) != 0) {
        return false;
    }

    // not valid and in transition
    if ((pte & (0x1 << 11)) != 0) {
        return true;
    }
    return false;
}

TranslateStatus process_vmem_read(struct ProcessOSI* process_osi, vm_addr_t addr,
                                  void* buffer, uint64_t size)
{
    auto status = process_osi->vmem->read(addr, buffer, size);
    if (TRANSLATE_SUCCEEDED(status)) {
        return status;
    }

    if (status != TSTAT_PAGED_OUT) {
        return status;
    }

    // handle a page fault if we can
    osi::i_t proc(process_osi->vmem, process_osi->tlib, process_osi->eprocess_address,
                  "_EPROCESS");
    uint64_t bytes_remaining = size;
    while (bytes_remaining > 0) {
        auto vad = find_vad_range(proc, process_osi, addr);
        auto pte_addr = std::get<0>(vad);
        auto pte = std::get<1>(vad);

        if (!valid_pte(pte)) {
            // fprintf(stderr, "Invalid pte at %lx -> %lx\n", pte_addr, pte);
            return TSTAT_GENERIC_FAILURE;
        }

        uint64_t chunk_size = 0xfff - (addr & 0xfff);
        chunk_size = std::min(chunk_size, bytes_remaining);
        if (chunk_size == 0) {
            chunk_size = bytes_remaining;
        }
        uint64_t paddr = (pte & 0xffffffffff000) + (addr & 0xfff);
        auto pmem = process_osi->kosi->pmem;
        pmem->read(pmem, paddr, (uint8_t*)buffer, chunk_size);
        addr += chunk_size;
        buffer = (void*)(((uint8_t*)buffer) + chunk_size);
        bytes_remaining -= chunk_size;
    }
    // fprintf(stderr, "[DEBUG] Second chance memory read worked! %lx %lu\n", addr - size,
    // size);
    return TSTAT_SUCCESS;
}
