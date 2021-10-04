#include <memory>
#include <string>

#include <iohal/memory/common.h>
#include <offset/i_t.h>
#include <offset/offset.h>

#include "wintrospection.h"

class WindowsKernelManager
{
protected:
    std::string m_profile;
    std::shared_ptr<WindowsKernelOSI> m_kosi;

    bool m_initialized;

public:
    WindowsKernelManager(std::string profile) : m_profile(profile)
    {
        m_kosi = std::make_shared<WindowsKernelOSI>();
        m_initialized = false;
    }

    bool initialize(struct PhysicalMemory* interface, uint8_t pointer_width,
                    uint64_t system_asid, vm_addr_t kpcr, bool pae_enabled = false);

    struct WindowsKernelOSI* get_kernel_object() { return m_kosi.get(); }

    osi::i_t get_type(vm_addr_t address, std::string type);
};
