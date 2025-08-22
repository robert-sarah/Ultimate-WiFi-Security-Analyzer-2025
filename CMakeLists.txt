cmake_minimum_required(VERSION 3.12)
project(NoahWiFiAnalyzer VERSION 2.0.0)

# Configuration avancée C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configuration multi-plateformes
if(WIN32)
    set(PLATFORM_NAME "Windows")
    add_definitions(-DWINDOWS_PLATFORM)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
elseif(APPLE)
    set(PLATFORM_NAME "macOS")
    add_definitions(-DAPPLE_PLATFORM)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0")
elseif(UNIX)
    set(PLATFORM_NAME "Linux")
    add_definitions(-DLINUX_PLATFORM)
endif()

message(STATUS "Configuration pour ${PLATFORM_NAME}")

# Détection automatique de Python et Pybind11
find_package(PkgConfig REQUIRED)
find_package(pybind11 REQUIRED)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Bibliothèques système multi-plateformes
if(WIN32)
    set(SYSTEM_LIBS Wlanapi ws2_32 iphlpapi crypt32)
elseif(APPLE)
    set(SYSTEM_LIBS "-framework CoreWLAN" "-framework Foundation" "-framework SystemConfiguration")
elseif(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)
    set(SYSTEM_LIBS ${LIBNL_LIBRARIES} pthread)
endif()

# Options de compilation avancées
option(ENABLE_ADVANCED_ATTACKS "Activer les modules de pénétration avancés" ON)
option(ENABLE_REAL_TIME_ANALYSIS "Activer l'analyse temps réel" ON)
option(ENABLE_AI_MODULES "Activer les modules IA" ON)
option(ENABLE_DEBUG_MODE "Activer le mode debug" OFF)

if(ENABLE_DEBUG_MODE)
    add_definitions(-DDEBUG_MODE)
    set(CMAKE_BUILD_TYPE Debug)
else()
    set(CMAKE_BUILD_TYPE Release)
endif()

# Optimisations de compilation
if(MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /GL /Gy /DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /DDEBUG")
else()
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
endif()

# Modules principaux
add_subdirectory(src/cpp)

# Tests et benchmarks
enable_testing()
if(EXISTS "${CMAKE_SOURCE_DIR}/tests")
    add_subdirectory(tests)
endif()

# Documentation
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_EXTRACT_PRIVATE YES)
    doxygen_add_docs(docs src/cpp src/python)
    message(STATUS "Documentation Doxygen activée")
endif()

# Scripts d'installation
configure_file(${CMAKE_SOURCE_DIR}/scripts/install.sh ${CMAKE_BINARY_DIR}/install.sh COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/scripts/install.bat ${CMAKE_BINARY_DIR}/install.bat COPYONLY)

# Message de configuration finale
message(STATUS "========================================")
message(STATUS "Configuration ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "Plateforme: ${PLATFORM_NAME}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Python: ${Python3_VERSION}")
message(STATUS "========================================")