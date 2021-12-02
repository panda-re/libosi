#include "iohal/memory/virtual_memory.h"
#include "offset/offset.h"
#include "osi/windows/manager.h"
#include "osi/windows/wintrospection.h"
#include "gtest/gtest.h"
#include <set>
#include <unistd.h>

char* testfile = nullptr;

TEST(WintroKernelbaseTest, Win7SP1i386)
{
    ASSERT_TRUE(testfile) << "Couldn't load input test file!";
    ASSERT_TRUE(access(testfile, R_OK) == 0) << "Could not read input file";

    WindowsKernelManager manager = WindowsKernelManager("windows-32-7sp1");

    auto pmem = load_physical_memory_snapshot(testfile);
    ASSERT_TRUE(pmem != nullptr) << "failed to load physical memory snapshot";

    ASSERT_TRUE(manager.initialize(pmem, 4, 0x185000, 0x82933c00))
        << "Failed to initialize kernel osi";

    struct WindowsKernelOSI* kosi = manager.get_kernel_object();
    struct WindowsKernelDetails kdetails = kosi->details;

    ASSERT_EQ(kdetails.kernelbase, 0x82811000) << "Found the wrong kernel base";

    ASSERT_EQ(kdetails.kdbg, 0x82932c28);

    ASSERT_EQ(kdetails.version64, 0x82932c00);

    // ASSERT_EQ(kdetails.PsActiveProcessHead, 0x8294a6d8);

    pmem->free(pmem);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc != 2) {
        fprintf(stderr, "usage: %s i386.raw\n", argv[0]);
        return 3;
    }

    testfile = argv[1];

    return RUN_ALL_TESTS();
}
