#ifndef __LIBINTRO_WINDOWS_STATIC_OFFSETS_H
#define __LIBINTRO_WINDOWS_STATIC_OFFSETS_H

namespace static_offsets {
namespace i386 {
    static const vm_addr_t KPCR_SELF_OFFSET = 0x1C;
    static const vm_addr_t KPCR_CURRENT_PRCB_OFFSET = 0x20;
    static const vm_addr_t KPRCB_IDLE_THREAD = 0x0C;
    static const vm_addr_t KDBG_TAG_OFFSET = 0x10;
    static const vm_addr_t ACTIVEPROCESSLINK_OFFSET = 0xb8;
}

namespace amd64 {
    static const vm_addr_t KPCR_SELF_OFFSET = 0x18;
    static const vm_addr_t KPCR_CURRENT_PRCB_OFFSET = 0x20;
    static const vm_addr_t KPRCB_IDLE_THREAD = 0x18;
    static const vm_addr_t KDBG_TAG_OFFSET = 0x10;
    static const vm_addr_t ACTIVEPROCESSLINK_OFFSET = 0x188;
}

static const vm_addr_t KDBG_PSACTIVEPROCESSHEAD = 0x50;

}


#endif
