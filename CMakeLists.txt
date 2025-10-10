cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(demap-tree VERSION 20251010)

include(GNUInstallDirs)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_executable(demap-tree src/demap-tree.cpp)

target_sources(demap-tree PUBLIC FILE_SET CXX_MODULES FILES
    src/cxxbtrfs.cpp
    src/formatted_error.cpp)

target_compile_options(demap-tree PUBLIC -Wall -Wextra -Wno-unqualified-std-cast-call -Wno-missing-field-initializers)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS demap-tree DESTINATION ${CMAKE_INSTALL_BINDIR}
    CXX_MODULES_BMI EXCLUDE_FROM_ALL
)
