cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(demap-tree)

include(GNUInstallDirs)

add_executable(demap-tree src/demap-tree.cpp)

target_sources(demap-tree PUBLIC FILE_SET CXX_MODULES FILES
    src/cxxbtrfs.cpp)

target_compile_options(demap-tree PUBLIC -Wall -Wextra -Wno-unqualified-std-cast-call -Wno-missing-field-initializers)

install(TARGETS demap-tree DESTINATION ${CMAKE_INSTALL_BINDIR}
    CXX_MODULES_BMI EXCLUDE_FROM_ALL
)
