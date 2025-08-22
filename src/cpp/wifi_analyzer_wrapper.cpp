#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "wifi_analyzer.h"

namespace py = pybind11;

PYBIND11_MODULE(wifi_core_cpp, m) {
    m.doc() = "Module C++ pour l'analyse WiFi haute performance";
    
    py::class_<WiFiNetwork>(m, "WiFiNetwork")
        .def(py::init<>())
        .def_readwrite("ssid", &WiFiNetwork::ssid)
        .def_readwrite("bssid", &WiFiNetwork::bssid)
        .def_readwrite("channel", &WiFiNetwork::channel)
        .def_readwrite("rssi", &WiFiNetwork::rssi)
        .def_readwrite("encryption", &WiFiNetwork::encryption);
    
    py::class_<WiFiAnalyzer>(m, "WiFiAnalyzer")
        .def(py::init<>())
        .def("scanNetworks", &WiFiAnalyzer::scanNetworks)
        .def("capturePackets", &WiFiAnalyzer::capturePackets);
}