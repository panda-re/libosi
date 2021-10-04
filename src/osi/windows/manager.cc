#include "osi/windows/manager.h"
#include "osi/windows/wintrospection.h"

#include "iohal/memory/physical_memory.h"
#include "iohal/memory/virtual_memory.h"

#include "kernel_osi.h"

bool WindowsKernelManager::initialize(struct PhysicalMemory* interface,
                                      uint8_t pointer_width, uint64_t initial_asid,
                                      vm_addr_t kpcr, bool pae_enabled)
{
    const char* profile = m_profile.c_str();

    m_kosi->kernel_tlib = load_type_library(profile);
    if (!(m_kosi->kernel_tlib)) {
        fprintf(stderr, "Could not locate type library for: %s\n", profile);
        return false;
    } else if (!interface) {
        fprintf(stderr, "A bad physical memory interface was provided\n");
        return false;
    } else if (!kpcr) {
        fprintf(stderr, "The current value of kpcr must be provided\n");
        return false;
    }

    uint8_t bits;
    if (pointer_width == 4) {
        bits = 32;
    } else if (pointer_width == 8) {
        bits = 64;
    } else {
        fprintf(stderr, "Must supply a valid pointer width\n");
        return false;
    }

    m_kosi->pmem = interface;
    m_kosi->details.pointer_width = pointer_width;
    m_kosi->details.kpcr = kpcr;
    m_kosi->system_vmem = std::make_shared<VirtualMemory>(
        m_kosi->pmem, bits, initial_asid, pae_enabled, profile);

    // Find the base address of the kernel
    if (!find_kernel_base(m_kosi->system_vmem.get(), kpcr,
                          &(m_kosi->details.kernelbase))) {
        fprintf(stderr, "Scan for kernel base failed\n");
        return false;
    }

    // Find the KDBG structure
    if (!scan_for_kdbg(m_kosi->system_vmem.get(), m_kosi->details.kernelbase,
                       &(m_kosi->details.kdbg))) {
        fprintf(stderr, "Failed to find KDBG\n");
        return false;
    }

    m_kosi->details.PsActiveProcessHead =
        get_address_active_process_head(m_kosi->system_vmem.get(), m_kosi->details.kdbg);
    if (!scan_for_version64(m_kosi->system_vmem.get(), m_kosi->details.kdbg,
                            m_kosi->details.kernelbase, &(m_kosi->details.version64))) {
        fprintf(stderr, "Warning: Could not scan for version64\n");
    }

    bool found_system_process = false;
    auto plist = get_process_list(m_kosi.get());
    if (plist) {
        struct WindowsProcess* p = nullptr;
        do {
            auto p = process_list_next(plist);
            if (process_get_pid(p) == 4) {
                m_kosi->details.system_eprocess = process_get_eprocess(p);
                m_kosi->system_vmem->set_asid(process_get_asid(p));
                m_kosi->details.system_asid = process_get_asid(p);
                found_system_process = true;
                break;
            }
            free_process(p);
        } while (plist != nullptr);
        free_process_list(plist);
    }

    m_initialized = found_system_process;
    return m_initialized;
}

osi::i_t WindowsKernelManager::get_type(vm_addr_t address, std::string type)
{
    return osi::i_t(m_kosi->system_vmem, m_kosi->kernel_tlib, address, type);
}
