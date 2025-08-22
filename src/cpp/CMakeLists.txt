cmake_minimum_required(VERSION 3.12)
project(wifi_analyzer_core)

# Configuration pour le module C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fichiers sources
add_library(wifi_analyzer_core STATIC
    wifi_analyzer.cpp
    wifi_analyzer.h
)

# Options pour Windows
if(WIN32)
    target_link_libraries(wifi_analyzer_core PRIVATE Wlanapi.lib)
endif()

# Configuration pour Pybind11
find_package(pybind11 REQUIRED)
pybind11_add_module(wifi_core_cpp wifi_analyzer_wrapper.cpp)
target_link_libraries(wifi_core_cpp PRIVATE wifi_analyzer_core)