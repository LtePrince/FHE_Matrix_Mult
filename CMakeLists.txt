cmake_minimum_required(VERSION 3.17)
project(SEAL_HMM_DEMO CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS
    ON
    CACHE BOOL "used for clangd" FORCE)

# Enable verbose compiler's command line information
option(VERBOSE "cmake verbose" OFF)
set(CMAKE_VERBOSE_MAKEFILE ${VERBOSE})

# ------------------------------------------------------------------------------
# 设置编译选项
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)

if(CMAKE_BUILD_TYPE)
  set(RELEASE_TYPES Debug Release RelWithDebInfo MinSizeRel)
  list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)

  if(${INDEX_FOUND} EQUAL -1)
    message(
      FATAL_ERROR
        "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel"
    )
  endif()
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-g -O3")

# ------------------------------------------------------------------------------
# 输出状态
# ------------------------------------------------------------------------------
message(STATUS "CMAKE_BUILD_TYPE:              ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_CXX_COMPILER:            ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_VERBOSE_MAKEFILE:        ${VERBOSE}")

# ------------------------------------------------------------------------------
# Third-party code...
# ------------------------------------------------------------------------------
add_subdirectory(lib/SEAL) # SEAL

add_executable(test2 src/test2.cpp)
target_link_libraries(test2 seal)

add_executable(test3 src/test3.cpp)
target_link_libraries(test3 seal)
