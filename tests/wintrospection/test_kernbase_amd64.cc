#include "iohal/memory/virtual_memory.h"
#include "offset/offset.h"
#include "wintrospection/wintrospection.h"
#include "gtest/gtest.h"
#include <set>
#include <unistd.h>

// Include an internal header
#include "wintrospection/utils.h"

char* testfile = nullptr;

TEST(WintroKernelbaseTest, Win7SP1Amd64)
{
    ASSERT_TRUE(testfile) << "Couldn't load input test file!";
    ASSERT_TRUE(access(testfile, R_OK) == 0) << "Could not read input file";

    struct WindowsKernelDetails kdetails = {0};
    struct WindowsKernelOSI kosi = {0};
    kdetails.pointer_width = 8;
    kdetails.kpcr = 0xfffff8000284cd00;
    pm_addr_t asid = 0x1c55a000;
    bool pae = false;

    kosi.pmem = load_physical_memory_snapshot(testfile);
    kosi.kernel_tlib = load_type_library("windows-64-7sp1");
    ASSERT_TRUE(kosi.pmem != nullptr) << "failed to load physical memory snapshot";
    ASSERT_TRUE(kosi.kernel_tlib != nullptr) << "failed to load type library";

    ASSERT_TRUE(
        initialize_windows_kernel_osi(&kosi, &kdetails, asid, false, "windows-64-7sp1"))
        << "Failed to initialize kernel osi";

    ASSERT_EQ(kdetails.kernelbase, 0xfffff8000265a000) << "Found the wrong kernel base";

    ASSERT_EQ(kdetails.kdbg, 0xfffff8000284b0a0);

    ASSERT_EQ(kdetails.version64, 0xfffff8000284b068);

    // ASSERT_EQ(psList, 0xfffff80002881b90);
    // ASSERT_EQ(kdetails.PsActiveProcessHead, 0x8294a6d8);

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
