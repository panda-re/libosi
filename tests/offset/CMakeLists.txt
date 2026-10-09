add_executable(test-offset-basic ${CMAKE_CURRENT_SOURCE_DIR}/test_basic.cc)
target_include_directories(test-offset-basic PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test-offset-basic offset-static gtest_main)
add_test(TestBasicOffsets test-offset-basic)
set_tests_properties(TestBasicOffsets PROPERTIES
    ENVIRONMENT "LIBOSI_PROFILES_DIR=${CMAKE_SOURCE_DIR}/resources/profiles")
