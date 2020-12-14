#include <stdio.h>
#include <vector>
#include <cstdlib>
#include <ctype.h>
#include "offset/offset.h"
#include "iohal/memory/virtual_memory.h"
#include "wintrospection/wintrospection.h"


int main(int argc, char* argv[])
{
    if (argc != 7) {
        fprintf(stderr, "usage: %s memfile dtb kpcr pid addr size\n", argv[0]);
        return 3;
    }

    const char* testfile = argv[1];
    uint64_t asid_arg = std::strtoull(argv[2], NULL, 16);
    uint64_t kpcr = std::strtoull(argv[3], NULL, 16);
    uint32_t target_pid = std::atoi(argv[4]);
    uint64_t addr = std::strtoull(argv[5], NULL, 16);
    uint64_t size = atoi(argv[6]);


    struct WindowsKernelDetails kdetails = {0};
    struct WindowsKernelOSI kosi = {0};
    kdetails.pointer_width = 8;
    kdetails.kpcr = kpcr;
    pm_addr_t asid = asid_arg;
    bool pae = false;

    kosi.pmem = load_physical_memory_snapshot(testfile);
    kosi.kernel_tlib = load_type_library("windows-64-7sp1");
    if (kosi.pmem == nullptr) {
        fprintf(stderr, "Failed to read physical memory snapshot\n");
        return 1;
    }
    if (kosi.kernel_tlib == nullptr) {
        fprintf(stderr, "Failed to load type library\n");
        return 2;
    }
    if (!initialize_windows_kernel_osi(&kosi, &kdetails, asid, false)) {
        fprintf(stderr, "Failed to initialize windows\n");
        return 3;
    }

    auto plist = get_process_list(&kosi);
    auto process = process_list_next(plist);
    while (process != nullptr) {
        auto pid = process_get_pid(process);
        if (pid == target_pid) {
            break;
        }
        free_process(process);
        process = process_list_next(plist);
    }

    if (process == nullptr) {
        fprintf(stderr, "Could not find target pid: %u\n", target_pid);
        return 7;
    }

    fprintf(stderr, "Starting with pid %u\n", target_pid);

    auto bytes = std::vector<uint8_t>(size);
    ProcessOSI posi = {0};
    if (!init_process_osi(&kosi, &posi, process_get_eprocess(process))) {
        fprintf(stderr, "Failed to init process introspection\n");
        return 6;
    }

    auto status = process_vmem_read(&posi, addr, bytes.data(), size);
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to read memory with status: %d\n", status);
        return 3;
    }

    size_t bytes_written = 0;
    while (bytes_written < size) {
        fprintf(stderr, "%016lx: ", addr);
        for (size_t ix=0; ix < 16 && bytes_written < size; ++ix) {
            fprintf(stderr, "%02x ", bytes[bytes_written]);
            bytes_written += 1;
        }
        fprintf(stderr, "| ");
        for (size_t jx=0; jx < 16; ++jx) {
            char c= bytes[bytes_written-16 + jx];
            if (isprint(c)) {
                fprintf(stderr, "%c", c);
            } else {
                fprintf(stderr, ".");
            }
        }
        fprintf(stderr, "\n");
    }


    return 0;
}

