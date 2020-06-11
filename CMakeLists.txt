project(wintrospection)
cmake_minimum_required(VERSION 3.0.2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# find glib and link to it
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG REQUIRED glib-2.0)
include_directories(${GLIB_PKG_INCLUDE_DIRS})

option(ENABLE_TESTING "Build and run tests" OFF)

set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")

set(IOHAL_SRCS src/iohal/memory/pmem_snapshot.cc
    src/iohal/translators/virtual_memory_translators.cc
    src/iohal/translators/windows_amd64.h src/iohal/translators/windows_amd64.cc
    src/iohal/translators/windows_i386.h  src/iohal/translators/windows_i386.cc
    src/iohal/translators/windows_i386_pae.h  src/iohal/translators/windows_i386_pae.cc
    src/iohal/memory/virtual_memory.cc)

# Compile all the .o files once
add_library(iohal-obj OBJECT ${IOHAL_SRCS})
target_include_directories(iohal-obj PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(iohal-obj PROPERTIES POSITION_INDEPENDENT_CODE 1)

# Then package them into a shared library and a static library
add_library(iohal SHARED $<TARGET_OBJECTS:iohal-obj>)
target_include_directories(iohal PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

add_library(iohal-static STATIC $<TARGET_OBJECTS:iohal-obj>)
target_include_directories(iohal-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)


set(OSI_SRCS src/offset/profiles/win7_sp0_x86.h
             src/offset/profiles/win7_sp1_x86.h
             src/offset/profiles/win7_sp1_x86.cpp
             src/offset/profiles/win7_sp0_x64.cpp
             src/offset/profiles/win7_sp0_x64.h
             src/offset/profiles/win7_sp1_x64.cpp
             src/offset/profiles/win7_sp1_x64.h
             src/offset/profiles/win7_sp0_x86.cpp
             src/offset/core.cc)

# Compile all the .o files once
add_library(offset-obj OBJECT ${OSI_SRCS})
target_include_directories(offset-obj PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/offset>
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(offset-obj PROPERTIES POSITION_INDEPENDENT_CODE 1)

# Then package them into a shared library and a static library
add_library(offset SHARED $<TARGET_OBJECTS:offset-obj>)
target_include_directories(offset PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/offset>
    $<INSTALL_INTERFACE:include>)

add_library(offset-static STATIC $<TARGET_OBJECTS:offset-obj>)
target_include_directories(offset-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/offset>
    $<INSTALL_INTERFACE:include>)


set(WINTRO_SRCS src/wintrospection/kernel_osi.h
                src/wintrospection/windows_introspection.cc
                src/wintrospection/windows_introspection.h
                src/wintrospection/kernel_osi.cc
                src/wintrospection/windows_static_offsets.h
                src/wintrospection/api.cc
                src/wintrospection/mem_pe/mem_pe.cc)

# Compile all the .o files once
add_library(wintrospection-obj OBJECT ${WINTRO_SRCS})
target_include_directories(wintrospection-obj PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(wintrospection-obj PROPERTIES POSITION_INDEPENDENT_CODE 1)

# Then package them into a shared library and a static library
add_library(wintrospection SHARED $<TARGET_OBJECTS:wintrospection-obj>)
target_include_directories(wintrospection PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:include>)

add_library(wintrospection-static STATIC $<TARGET_OBJECTS:wintrospection-obj>)
target_include_directories(wintrospection-static PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:include>)

target_link_libraries(wintrospection ${GLIB_PKG_LIBRARIES})

# Install everything
install(TARGETS wintrospection wintrospection-static offset offset-static iohal iohal-static
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h")

if (ENABLE_TESTING)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()


