#include "offset/offset.h"
#include "wintrospection/pe.h"
#include "wintrospection/wintrospection.h"
#include "gtest/gtest.h"
#include <iohal/memory/virtual_memory.h>
#include <set>
#include <unistd.h>

#include <iostream>
#include <map>

#include "wintrospection/utils.h"

char* testfile = nullptr;

TEST(TestAmd64MemPE, Win7SP1Amd64)
{
    ASSERT_TRUE(testfile) << "Couldn't load input test file!";
    ASSERT_TRUE(access(testfile, R_OK) == 0) << "Could not read input file";

    struct WindowsKernelDetails kdetails = {0};
    struct WindowsKernelOSI kosi = {0};
    kdetails.pointer_width = 8;
    kdetails.kpcr = 0xfffff80002848d00;
    kdetails.kdbg = 0xfffff800028470a0;
    pm_addr_t asid = 0x187000;
    bool pae = false;

    kosi.pmem = load_physical_memory_snapshot(testfile);
    kosi.kernel_tlib = load_type_library("windows-64-7sp1");
    ASSERT_TRUE(kosi.pmem != nullptr) << "failed to load physical memory snapshot";
    ASSERT_TRUE(kosi.kernel_tlib != nullptr) << "failed to load type library";
    ASSERT_TRUE(
        initialize_windows_kernel_osi(&kosi, &kdetails, asid, pae, "windows-64-7sp1"))
        << "Failed to initialize kernel osi";

    WindowsProcessOSI posi;
    ASSERT_TRUE(init_process_osi_from_pid(&kosi, &posi, 2856))
        << "Failed to initialize process OSI object";
    auto python_mem_pe = init_mem_pe(&posi, 0x400000, false);

    ASSERT_TRUE(python_mem_pe != nullptr) << "Failed to init mem_pe object";
    free_mem_pe(python_mem_pe);

    uninit_process_osi(&posi);
    kosi.system_vmem.reset();
    kosi.pmem->free(kosi.pmem);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc != 2) {
        fprintf(stderr, "usage: %s amd64.raw\n", argv[0]);
        return 3;
    }

    testfile = argv[1];

    return RUN_ALL_TESTS();
}
