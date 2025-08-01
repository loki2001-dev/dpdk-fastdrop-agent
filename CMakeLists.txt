CMAKE_MINIMUM_REQUIRED(VERSION 3.28)
PROJECT(dpdk-fastdrop-agent)

# OPTION (Standard)
SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# OPTION (3rdparty)
SET(BUILD_SHARED_LIBS ON)

# FIND .pkgconfig
FIND_PACKAGE(PkgConfig REQUIRED)
PKG_CHECK_MODULES(DPDK REQUIRED libdpdk)

# ADD 3rdparty
ADD_SUBDIRECTORY(3rdparty/nlohmann)
ADD_SUBDIRECTORY(3rdparty/spdlog)

# INCLUDE
INCLUDE_DIRECTORIES(
        ${PROJECT_SOURCE_DIR}/include
        3rdparty/dpdk/app
        3rdparty/dpdk/lib
        ${DPDK_INCLUDE_DIRS}
)

# GLOB
FILE(GLOB_RECURSE DPDK_SOURCES
        "${PROJECT_SOURCE_DIR}/dpdk/*.cpp"
        "${PROJECT_SOURCE_DIR}/dpdk/*.h"
)

# DEFINE executable files
ADD_EXECUTABLE(dpdk-fastdrop-agent
        main.cpp
        ${DPDK_SOURCES}
)

# INCLUDE directories (OPTIONAL)
TARGET_INCLUDE_DIRECTORIES(dpdk-fastdrop-agent PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${DPDK_INCLUDE_DIRS}
)

# LINK
TARGET_LINK_LIBRARIES(dpdk-fastdrop-agent
        ${DPDK_LIBRARIES}
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)
