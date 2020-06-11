
# Testing

message(FATAL_ERROR "These tests have not been ported")

set(RAPIDJSON_DIR "${PROJECT_SOURCE_DIR}/dependencies/rapidjson" CACHE PATH "Path to rapidjson source")
if (NOT EXISTS ${RAPIDJSON_DIR})
    message(WARNING "Could not find ${RAPIDJSON_DIR}")
    message(WARNING "Please install rapidjson to enable testing")
else()
    set(GTEST_SRC_DIR "/usr/src/gtest" CACHE PATH "Path to google test source")
    if (NOT EXISTS ${GTEST_SRC_DIR})
        message(WARNING "Could not find ${GTEST_SRC_DIR}")
        message(WARNING "Please install libgtest-dev to enable testing")
    else()
        include(ExternalProject)
        ExternalProject_Add(googletest
            SOURCE_DIR        "/usr/src/gtest"
            BINARY_DIR        "${CMAKE_BINARY_DIR}/wintro-gtest-build"
            CONFIGURE_COMMAND ""
            BUILD_COMMAND     ""
            INSTALL_COMMAND   ""
            TEST_COMMAND      ""
        )

        add_subdirectory(/usr/src/gtest
                         ${CMAKE_BINARY_DIR}/wintro-gtest-build
                         EXCLUDE_FROM_ALL)

        enable_testing()
        # test the test system

        add_executable(test-basic tests/test_basic.cc)
        target_link_libraries(test-basic wintrospection gtest_main -loffset -liohal)
        add_test(Wintrospection test-basic)

        include(ExternalData)

        macro(add_file_test testname testpath testdata)
            add_executable(${testname} ${testpath})
            target_link_libraries(${testname} wintrospection gtest_main -loffset -liohal)
            ExternalData_Add_Test(TestFiles
                NAME ${testname}-test
                COMMAND ${testname} DATA{${testdata}}
            )
        endmacro()

        add_file_test(test-i_t tests/test_i_t.cc tests/wintrospection-tests/amd64.raw)
        add_file_test(test-plist-amd64 tests/test_plist_amd64.cc tests/wintrospection-tests/amd64.raw)
        add_file_test(test-modlist-amd64 tests/test_modlist_amd64.cc tests/wintrospection-tests/amd64.raw)
        add_file_test(test-modlist-i386 tests/test_modlist_i386.cc tests/wintrospection-tests/i386.raw)
        add_file_test(test-kernbase-amd64 tests/test_kernbase_amd64.cc tests/wintrospection-tests/amd64.raw)
        add_file_test(test-plist-i386 tests/test_plist_i386.cc tests/wintrospection-tests/i386.raw)
        add_file_test(test-kernbase-i386 tests/test_kernbase_i386.cc tests/wintrospection-tests/i386.raw)

        #aprog-x64.raw is too large for git-lfs and would require compressing. test-mem-pe-general should test this functionality adequately
        #add_file_test(test-mem-pe-amd64 tests/test_mem_pe_amd64.cc tests/wintrospection-tests/aprog-x64.raw)

        macro(add_file_test_no_args testname testpath)
            add_executable(${testname} ${testpath})
            target_include_directories(${testname} PRIVATE ${RAPIDJSON_DIR}/include)
            target_link_libraries(${testname} wintrospection gtest_main -loffset -liohal)
             add_test(
                NAME ${testname}-test
                COMMAND ${testname})
        endmacro()

        add_file_test_no_args(test-modlist-wow64notepad-win7sp0 tests/test_modlist_wow64_notepad_win7sp0.cc)
        add_file_test_no_args(test-modlist-wow64windbg-win7sp0 tests/test_modlist_wow64_windbg_win7sp0.cc)
        add_file_test_no_args(test-modlist-wow64precalc-win7sp0 tests/test_modlist_wow64_precalc_win7sp0.cc)
        add_file_test_no_args(test-modlist-wow64notepad-win7sp1 tests/test_modlist_wow64_notepad_win7sp1.cc)
        add_file_test_no_args(test-modlist-wow64windbg-win7sp1 tests/test_modlist_wow64_windbg_win7sp1.cc)
        add_file_test_no_args(test-modlist-wow64precalc-win7sp1 tests/test_modlist_wow64_precalc_win7sp1.cc)

        add_file_test_no_args(test-kernbase-general tests/test_kernbase_general.cc)
        add_file_test_no_args(test-plist-general tests/test_plist_general.cc)
        add_file_test_no_args(test-modlist-general tests/test_modlist_general.cc)
        add_file_test_no_args(test-mem-pe-general tests/test_mem_pe_general.cc)
    endif()
endif()

