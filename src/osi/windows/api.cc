#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <dlfcn.h>
#include <exception>
#include <libgen.h>
#include <map>
#include <memory>
#include <stdint.h>
#include <vector>

#include "iohal/memory/virtual_memory.h"
#include <offset/i_t.h>
#include <offset/offset.h>

#include "osi/windows/iterator.h"
#include "osi/windows/ustring.h"
#include "osi/windows/wintrospection.h"
#include "windows_handles.h"
#include "windows_static_offsets.h"

struct WindowsProcessList {
    uint64_t head;
    uint64_t ptr;
    WindowsKernelOSI* kosi;
};

struct WindowsProcess {
    uint64_t eprocess_address;
    char shortname[17];
    char* cmdline;
    uint64_t pid;
    uint64_t ppid;
    uint64_t asid;
    uint64_t createtime;
    uint64_t base_vba;
    bool is_wow64;
};

struct WindowsModuleList {
    struct WindowsProcessOSI* posi;
    std::vector<uint64_t>* module_list;
    std::map<uint64_t, bool>* modules;
    uint16_t idx;
};

#define MAX_PATH_SIZE 4096
struct WindowsModuleEntry {
    uint64_t module_entry;
    uint64_t base_address;
    uint32_t checksum;
    uint64_t entrypoint;
    uint32_t flags;
    uint32_t timedatestamp;
    uint16_t loadcount;
    uint32_t modulesize;
    char dllpath[MAX_PATH_SIZE];
    char dllname[MAX_PATH_SIZE];
    bool is_wow64;
};

struct WindowsHandleObject {
    uint8_t type_index;
    uint64_t pointer;
    struct WindowsProcessOSI* posi;
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

struct WindowsProcessList* get_process_list(struct WindowsKernelOSI* kosi)
{
    auto plist = new struct WindowsProcessList;

    plist->head = kosi->details.PsActiveProcessHead;
    plist->head -= ((kosi->details.pointer_width == 8)
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
            if (peb.get_address() == 0 && next_process["UniqueProcessId"].getu() != 4) {
                continue;
            }

            return next_process.get_address();
        } catch (...) {
            continue;
        }
    }
    return 0;
}

struct WindowsProcess* process_list_next(struct WindowsProcessList* plist)
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
        if (!isprint(process_name[ix])) {
            process_name[ix] = '?';
        }
    }
}

struct WindowsProcess* create_process(struct WindowsKernelOSI* kosi,
                                      uint64_t eprocess_address)
{
    auto p = new WindowsProcess;

    p->eprocess_address = eprocess_address;
    auto vmem = std::make_shared<VirtualMemory>(*kosi->system_vmem);
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

    // use correct ASID when reading from PEB
    eproc.get_virtual_memory_shared()->set_asid(p->asid);

    osi::i_t peb;
    try {
        if (p->is_wow64) {
            peb = eproc("Wow64Process").set_type("_PEB32");
        } else {
            peb = eproc("Peb");
        }
    } catch (std::runtime_error) {
        // bail if the PEB isn't readable. user can still see other attrs
        p->cmdline = nullptr;
        p->base_vba = 0;
        return p;
    }

    try {
        p->base_vba = peb["ImageBaseAddress"].getu();
    } catch (std::runtime_error) {
        p->base_vba = 0;
    }

    try {
        osi::i_t params;
        if (p->is_wow64) {
            params = osi::i_t(peb.get_virtual_memory_shared(), peb.get_type_library(),
                              peb["ProcessParameters"].get32(),
                              "_RTL_USER_PROCESS_PARAMETERS");
        } else {
            params = peb("ProcessParameters");
        }

        auto cmdline_ustring = osi::ustring(params["CommandLine"]);
        p->cmdline = new char[cmdline_ustring.get_maximum_length()]();

        std::string cmdline = maybe_parse_unicode_string(cmdline_ustring);
        strncpy(p->cmdline, cmdline.c_str(), cmdline_ustring.get_maximum_length() - 1);

    } catch (std::runtime_error) {
        p->cmdline = nullptr;
    }

    return p;
}

struct WindowsProcess* create_process_from_asid(struct WindowsKernelOSI* kosi,
                                                uint64_t asid)
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
void free_process(struct WindowsProcess* p)
{
    if (p) {
        delete p;
        if (p->cmdline) {
            delete p->cmdline;
        }
    }
}

void free_process_list(struct WindowsProcessList* plist)
{
    if (plist) {
        delete plist;
    }
}

uint64_t process_get_eprocess(const struct WindowsProcess* plist)
{
    return plist->eprocess_address;
}

uint64_t process_get_pid(const struct WindowsProcess* plist) { return plist->pid; }

uint64_t process_get_ppid(const struct WindowsProcess* plist) { return plist->ppid; }

const char* process_get_shortname(const struct WindowsProcess* p) { return p->shortname; }

const char* process_get_cmdline(const struct WindowsProcess* p) { return p->cmdline; }

uint64_t process_get_asid(const struct WindowsProcess* p) { return p->asid; }

uint64_t process_createtime(const struct WindowsProcess* p) { return p->createtime; }

uint64_t process_get_base(const struct WindowsProcess* p) { return p->base_vba; }

bool process_is_wow64(const struct WindowsProcess* p) { return p->is_wow64; }

struct WindowsModuleList* get_module_list(struct WindowsKernelOSI* kosi,
                                          uint64_t process_address, bool is_wow64)
{
    auto mlist =
        (struct WindowsModuleList*)std::calloc(1, sizeof(struct WindowsModuleList));
    if (!mlist) {
        return nullptr;
    }
    mlist->module_list = new std::vector<uint64_t>();
    mlist->modules = new std::map<uint64_t, bool>();

    // Deep copy, we are going to change the asid
    mlist->posi =
        (struct WindowsProcessOSI*)std::calloc(1, sizeof(struct WindowsProcessOSI));
    init_process_osi(kosi, mlist->posi, process_address);

    mlist->idx = 0;
    osi::i_t proc(mlist->posi->vmem, mlist->posi->tlib, mlist->posi->eprocess_address,
                  "_EPROCESS");

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

struct WindowsModuleEntry* create_module_entry(struct WindowsModuleList* mlist,
                                               uint64_t module_entry_addr, bool is_wow64)
{
    if (is_wow64) {
        auto mentry =
            (struct WindowsModuleEntry*)std::calloc(1, sizeof(struct WindowsModuleEntry));
        osi::i_t data_table_entry(mlist->posi->vmem, mlist->posi->tlib, module_entry_addr,
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

            osi::ustring dllname(data_table_entry["BaseDllName"]);
            std::string dllname_utf8 = maybe_parse_unicode_string(dllname);
            strncpy(mentry->dllname, dllname_utf8.c_str(), MAX_PATH_SIZE - 1);

            osi::ustring dllpath(data_table_entry["FullDllName"]);
            std::string dllpath_utf8 = maybe_parse_unicode_string(dllpath);
            strncpy(mentry->dllpath, dllpath_utf8.c_str(), MAX_PATH_SIZE - 1);

            /*
            fprintf(stderr, "WOW64 base_address: %lu\n",
            module_entry_get_base_address(mentry));
            fprintf(stderr, "WOW64 modulesize: %lu\n",
            module_entry_get_modulesize(mentry));
            fprintf(stderr, "WOW64 checksum: %lu\n", module_entry_get_checksum(mentry));
            fprintf(stderr, "WOW64 entrypoint: %lu\n",
            module_entry_get_entrypoint(mentry));
            fprintf(stderr, "WOW64 flags: %lu\n", module_entry_get_flags(mentry));
            fprintf(stderr, "WOW64 TimeDateStamp: %lu\n",
            module_entry_get_timedatestamp(mentry));
            fprintf(stderr, "WOW64 loadcount: %lu\n", module_entry_get_loadcount(mentry));
            fprintf(stderr, "WOW64 DLLPATH: %s\n", dllpath_utf8.c_str());
            */

        } catch (...) {
            free_module_entry(mentry);
            return nullptr;
        }
        return mentry;
    }

    auto mentry =
        (struct WindowsModuleEntry*)std::calloc(1, sizeof(struct WindowsModuleEntry));
    osi::i_t data_table_entry(mlist->posi->vmem, mlist->posi->tlib, module_entry_addr,
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
        free_module_entry(mentry);
        return nullptr;
    }
    return mentry;
}

void free_module_entry(struct WindowsModuleEntry* me)
{
    if (me) {
        std::free(me);
    }
}

struct WindowsModuleEntry* module_list_next(struct WindowsModuleList* mlist)
{
    if (mlist->module_list->size() == 0) {
        return nullptr;
    } else if (mlist->module_list->size() <= mlist->idx) {
        return nullptr;
    }

    auto mod_address = (*(mlist->module_list))[mlist->idx++];
    bool mod_iswow64 = (*(mlist->modules))[mod_address];
    // TOOD push this down into module_entry ctor
    auto mod_entry = create_module_entry(mlist, mod_address, mod_iswow64);
    if (!mod_entry) {
        // skip invalid
        return module_list_next(mlist);
    }
    return mod_entry;
}

struct WindowsProcessOSI* module_list_get_osi(struct WindowsModuleList* mlist)
{
    return mlist->posi;
}

void free_module_list(struct WindowsModuleList* mlist)
{
    if (mlist) {
        if (mlist->posi) {
            uninit_process_osi(mlist->posi);
            delete mlist->posi;
        }

        delete mlist->module_list;
        delete mlist->modules;
        std::free(mlist);
    }
}

uint64_t module_entry_get_base_address(struct WindowsModuleEntry* me)
{
    return me->base_address;
}

uint32_t module_entry_get_checksum(struct WindowsModuleEntry* me) { return me->checksum; }

uint64_t module_entry_get_entrypoint(struct WindowsModuleEntry* me)
{
    return me->entrypoint;
}

uint32_t module_entry_get_flags(struct WindowsModuleEntry* me) { return me->flags; }

uint32_t module_entry_get_timedatestamp(struct WindowsModuleEntry* me)
{
    return me->timedatestamp;
}

uint16_t module_entry_get_loadcount(struct WindowsModuleEntry* me)
{
    return me->loadcount;
}

uint32_t module_entry_get_modulesize(struct WindowsModuleEntry* me)
{
    return me->modulesize;
}

bool module_entry_is_wow64(struct WindowsModuleEntry* me) { return me->is_wow64; }

const char* module_entry_get_dllpath(struct WindowsModuleEntry* me)
{
    return me->dllpath;
}

const char* module_entry_get_dllname(struct WindowsModuleEntry* me)
{
    return me->dllname;
}

bool init_process_osi_from_pid(struct WindowsKernelOSI* kosi,
                               struct WindowsProcessOSI* process_osi, uint64_t target_pid)
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

bool init_process_osi(struct WindowsKernelOSI* kosi,
                      struct WindowsProcessOSI* process_osi, uint64_t eprocess_address)
{
    process_osi->tlib = kosi->kernel_tlib; // TODO change if wow64
    process_osi->vmem = std::make_shared<VirtualMemory>(*kosi->system_vmem);
    process_osi->kosi = kosi;
    process_osi->eprocess_address = eprocess_address;
    osi::i_t proc(process_osi->vmem, process_osi->tlib, eprocess_address, "_EPROCESS");
    uint64_t new_asid = proc["Pcb"]["DirectoryTableBase"].getu();
    process_osi->vmem->set_asid(new_asid);
    // Get the basics
    process_osi->createtime = proc["CreateTime"].get64();
    process_osi->pid = proc["UniqueProcessId"].getu();
    return true;
}

void uninit_process_osi(struct WindowsProcessOSI* process_osi)
{
    process_osi->vmem.reset(); // TODO Process OSI should be a class
                               // with a destructor
}

static osi::i_t kosi_get_current_process_object(struct WindowsKernelOSI* kosi)
{
    osi::i_t kpcr =
        osi::i_t(kosi->system_vmem, kosi->kernel_tlib, kosi->details.kpcr, "_KPCR");

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

struct WindowsProcess* kosi_get_current_process(struct WindowsKernelOSI* kosi)
{
    auto eprocess = kosi_get_current_process_object(kosi);
    return create_process(kosi, eprocess.get_address());
}

uint64_t kosi_get_current_tid(struct WindowsKernelOSI* kosi)
{
    osi::i_t kpcr(kosi->system_vmem, kosi->kernel_tlib, kosi->details.kpcr, "_KPCR");

    osi::i_t ethread;
    if (kosi->system_vmem->get_pointer_width() == 4) {
        ethread = kpcr["PrcbData"]("CurrentThread");
    } else {
        ethread = kpcr["Prcb"]("CurrentThread");
    }
    ethread.set_type("_ETHREAD");

    return ethread["Cid"]["UniqueThread"].getu();
}

struct WindowsHandleObject* resolve_handle(struct WindowsKernelOSI* kosi, uint64_t handle)
{
    struct WindowsProcessOSI* posi =
        (struct WindowsProcessOSI*)std::calloc(1, sizeof(struct WindowsProcessOSI));
    init_process_osi(kosi, posi, kosi_get_current_process_address(kosi));

    osi::i_t obj_header =
        resolve_handle_table_entry(posi, handle, kosi->details.pointer_width > 4);
    if (!obj_header.get_address()) {
        uninit_process_osi(posi);
        std::free(posi);
        return nullptr;
    }

    struct WindowsHandleObject* h =
        (struct WindowsHandleObject*)std::calloc(1, sizeof(struct WindowsHandleObject));
    try {
        h->type_index = obj_header["TypeIndex"].get8();
        h->pointer = obj_header["Body"].get_address();
        h->posi = posi;
    } catch (std::runtime_error) {
        free_handle(h);
        return nullptr;
    }
    return h;
}

uint64_t handle_get_pointer(struct WindowsHandleObject* handle)
{
    return handle->pointer;
}

uint8_t handle_get_type(struct WindowsHandleObject* handle) { return handle->type_index; }

struct WindowsProcessOSI* handle_get_context(struct WindowsHandleObject* handle)
{
    return handle->posi;
}

void free_handle(struct WindowsHandleObject* handle)
{
    if (handle) {
        if (handle->posi) {
            uninit_process_osi(handle->posi);
            std::free(handle->posi);
        }
        std::free(handle);
    }
}

static inline uint16_t get_page_shift()
{
    // For 4K pages
    return 12;
}

const std::pair<uint64_t, uint64_t> NO_MATCH = {0, 0};
static inline std::pair<uint64_t, uint64_t>
find_vad_range(osi::i_t& eprocess, struct WindowsProcessOSI* process_osi, uint64_t addr)
{
    auto page_shift = get_page_shift();
    uint64_t target_vpn = addr >> page_shift;
    auto vad_root = eprocess["VadRoot"];
    auto working = vad_root["BalancedRoot"];

    while (working.get_address() != 0) {
        // Does this node contain target_vpn?
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
            uint64_t pte = mmpte.getu();
            return std::pair<uint64_t, uint64_t>(pte_addr, pte);
        }
        // Check the left arm
        if (target_vpn < starting_vpn) {
            auto left_child = working("LeftChild");
            if (left_child.get_address() == 0) {
                return NO_MATCH;
            }
            working = left_child;
            continue;
        } else if (ending_vpn < target_vpn) {
            // Check the right arm
            auto right_child = working("RightChild");
            if (right_child.get_address() == 0) {
                return NO_MATCH;
            }
            working = right_child;
            continue;
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
    // If it is not valid and a prototype, bail
    if ((pte & (0x1 << 10)) != 0) {
        return false;
    }
    // if it is not valid and is in transition, good to go
    if ((pte & (0x1 << 11)) != 0) {
        return true;
    }

    return false;
}

TranslateStatus process_vmem_read(struct WindowsProcessOSI* process_osi, vm_addr_t addr,
                                  void* buffer, uint64_t size)
{
    // Try to read the page normally
    auto status = process_osi->vmem->read(addr, buffer, size);
    if (TRANSLATE_SUCCEEDED(status)) {
        return status;
    }

    if (status != TSTAT_PAGED_OUT) {
        return status;
    }

    // Try to handle the page fault
    osi::i_t proc(process_osi->vmem, process_osi->tlib, process_osi->eprocess_address,
                  "_EPROCESS");
    uint64_t bytes_to_read = size;
    while (bytes_to_read > 0) {
        auto vad = find_vad_range(proc, process_osi, addr);
        auto pte_addr = std::get<0>(vad);
        auto pte = std::get<1>(vad);
        if (!valid_pte(pte)) {
            fprintf(stderr, "Failed to read from pte %lx %lx!\n", pte_addr, pte);
            return TSTAT_GENERIC_FAILURE;
        }
        uint64_t chunk_size = 0xfff - (addr & 0xfff);
        chunk_size = std::min(chunk_size, bytes_to_read);
        if (chunk_size == 0) {
            chunk_size = bytes_to_read;
        }
        uint64_t physaddr = (pte & 0xffffffffff000) + (addr & 0xfff);
        auto pmem = process_osi->kosi->pmem;
        pmem->read(pmem, physaddr, (uint8_t*)buffer, chunk_size);
        addr += chunk_size;
        buffer = (void*)(((uint8_t*)buffer) + chunk_size);
        bytes_to_read -= chunk_size;
    }
    return TSTAT_SUCCESS;
}
