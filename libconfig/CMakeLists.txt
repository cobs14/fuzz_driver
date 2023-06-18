cmake_minimum_required(VERSION 3.1)
if(CMAKE_HOST_WIN32)
    set(libname "libconfig")
else()
    set(libname "config")
endif()
set(CMAKE_VERBOSE_MAKEFILE ON) 
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Extract version from configure.ac.
set(VERSION_REGEX "^AC_INIT\\(\\[libconfig\\],[ \t]*\\[([0-9.]+)\\],.*")
file(STRINGS "configure.ac"
  VERSION_STRING REGEX ${VERSION_REGEX})
string(REGEX REPLACE ${VERSION_REGEX} "\\1" VERSION_STRING "${VERSION_STRING}")

project(libconfig LANGUAGES C CXX VERSION ${VERSION_STRING})
option(BUILD_EXAMPLES "Enable examples" ON)
option(BUILD_SHARED_LIBS  "Enable shared library" ON)
option(BUILD_TESTS "Enable tests" ON)

set_property(GLOBAL	PROPERTY USE_FOLDERS ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)

include(GNUInstallDirs)
include(CheckSymbolExists)
add_subdirectory(lib)

## ---

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -v -fsanitize=fuzzer,address -fsanitize-coverage=trace-cmp")

add_executable(Target target.cpp)

set_target_properties(Target
PROPERTIES
  CXX_STANDARD 11)

target_link_libraries(Target ${libname}++ )