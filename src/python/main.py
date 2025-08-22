#!/usr/bin/env python3
"""
Ultimate Professional WiFi Analysis and Security Testing Platform
Wireshark-like Network Analysis Suite with Real-time Deep Packet Inspection
Advanced multi-OS penetration testing suite with AI-powered analysis
"""

import sys
import os
import json
import threading
import time
import subprocess
import platform
import psutil
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import queue
import logging
import ipaddress
import struct
import socket

# Advanced PyQt5 imports
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

# Scientific computing imports
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.patches as patches

# Network and security imports
import socket
import struct
import threading
import queue
import hashlib
import hmac
import binascii
import re

# Advanced network analysis
try:
    import scapy.all as scapy
    from scapy.layers import http, dns, dhcp, l2, inet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# C++ integration
import ctypes
import platform

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    capture_stopped = pyqtSignal()
    
    def __init__(self, interface=None, filter_expr=""):
        super().__init__()
        self.interface = interface
        self.filter_expr = filter_expr
        self.running = False
        self.packet_queue = queue.Queue()
        
    def run(self):
        if not SCAPY_AVAILABLE:
            self.packet_captured.emit({"error": "Scapy not available for packet capture"})
            return
            
        try:
            self.running = True
            
            # Get available interfaces
            if not self.interface:
                interfaces = scapy.get_if_list()
                self.interface = interfaces[0] if interfaces else None
            
            if not self.interface:
                self.packet_captured.emit({"error": "No network interface available"})
                return
                
            # Start packet capture
            scapy.sniff(
                iface=self.interface,
                filter=self.filter_expr if self.filter_expr else None,
                prn=self.process_packet,
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            self.packet_captured.emit({"error": f"Capture error: {str(e)}"})
        finally:
            self.capture_stopped.emit()
    
    def process_packet(self, packet):
        try:
            packet_data = self.analyze_packet(packet)
            self.packet_captured.emit(packet_data)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def analyze_packet(self, packet):
        packet_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "size": len(packet),
            "protocol": "Unknown",
            "src_ip": "",
            "dst_ip": "",
            "src_mac": "",
            "dst_mac": "",
            "port_src": "",
            "port_dst": "",
            "flags": [],
            "payload": "",
            "raw_hex": bytes(packet).hex()[:200] + "..." if len(bytes(packet)) > 200 else bytes(packet).hex()
        }
        
        # Ethernet layer
        if packet.haslayer(scapy.Ether):
            packet_info["src_mac"] = packet[scapy.Ether].src
            packet_info["dst_mac"] = packet[scapy.Ether].dst
        
        # IP layer
        if packet.haslayer(scapy.IP):
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["protocol"] = "IP"
            
            # TCP
            if packet.haslayer(scapy.TCP):
                packet_info["protocol"] = "TCP"
                packet_info["port_src"] = str(packet[scapy.TCP].sport)
                packet_info["port_dst"] = str(packet[scapy.TCP].dport)
                packet_info["flags"] = self.get_tcp_flags(packet[scapy.TCP].flags)
                
            # UDP
            elif packet.haslayer(scapy.UDP):
                packet_info["protocol"] = "UDP"
                packet_info["port_src"] = str(packet[scapy.UDP].sport)
                packet_info["port_dst"] = str(packet[scapy.UDP].dport)
                
            # ICMP
            elif packet.haslayer(scapy.ICMP):
                packet_info["protocol"] = "ICMP"
                
        # ARP
        elif packet.haslayer(scapy.ARP):
            packet_info["protocol"] = "ARP"
            packet_info["src_ip"] = packet[scapy.ARP].psrc
            packet_info["dst_ip"] = packet[scapy.ARP].pdst
            
        # HTTP
        if packet.haslayer(http.HTTPRequest):
            packet_info["protocol"] = "HTTP"
            packet_info["http_method"] = packet[http.HTTPRequest].Method.decode()
            packet_info["http_host"] = packet[http.HTTPRequest].Host.decode()
            packet_info["http_path"] = packet[http.HTTPRequest].Path.decode()
            
        elif packet.haslayer(http.HTTPResponse):
            packet_info["protocol"] = "HTTP"
            packet_info["http_status"] = packet[http.HTTPResponse].Status_Code
            
        # DNS
        if packet.haslayer(dns.DNS):
            packet_info["protocol"] = "DNS"
            if packet[dns.DNS].qd:
                packet_info["dns_query"] = packet[dns.DNS].qd.qname.decode()
                
        # Extract payload
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            try:
                packet_info["payload"] = raw_data.decode('utf-8', errors='ignore')[:100] + "..." if len(raw_data) > 100 else raw_data.decode('utf-8', errors='ignore')
            except:
                packet_info["payload"] = raw_data.hex()[:100] + "..." if len(raw_data) > 100 else raw_data.hex()
        
        return packet_info
    
    def get_tcp_flags(self, flags):
        flag_names = {
            0x01: "FIN",
            0x02: "SYN", 
            0x04: "RST",
            0x08: "PSH",
            0x10: "ACK",
            0x20: "URG",
            0x40: "ECE",
            0x80: "CWR"
        }
        
        active_flags = []
        for flag_value, flag_name in flag_names.items():
            if flags & flag_value:
                active_flags.append(flag_name)
        return active_flags
    
    def stop_capture(self):
        self.running = False

class WiFiScanThread(QThread):
    scan_complete = pyqtSignal(list)

    def run(self):
        try:
            # Real-time C++ integration
            import ctypes
            import platform
            
            # Load C++ library based on platform
            system = platform.system()
            if system == "Windows":
                lib_path = "src/cpp/wifi_analyzer.dll"
            elif system == "Darwin":
                lib_path = "src/cpp/wifi_analyzer.dylib"
            else:
                lib_path = "src/cpp/wifi_analyzer.so"
            
            wifi_lib = ctypes.CDLL(lib_path)
            
            # Define C++ function signatures
            wifi_lib.scan_networks.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
            wifi_lib.scan_networks.restype = ctypes.c_int
            
            # Get real networks
            result_ptr = ctypes.c_char_p()
            count = wifi_lib.scan_networks(ctypes.byref(result_ptr))
            
            if count > 0 and result_ptr.value:
                import json
                networks_data = json.loads(result_ptr.value.decode('utf-8'))
                self.scan_complete.emit(networks_data)
            else:
                self.scan_complete.emit([])
                
        except Exception as e:
            print(f"Real-time scan error: {e}")
            self.scan_complete.emit([])

class RealTimeChart(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.packet_counts = []
        self.timestamps = []
        self.max_points = 100
        
        self.axes.set_xlabel('Time')
        self.axes.set_ylabel('Packets/sec')
        self.axes.set_title('Real-time Packet Rate')
        self.axes.grid(True)
        
    def update_chart(self, packet_count):
        current_time = time.time()
        self.timestamps.append(current_time)
        self.packet_counts.append(packet_count)
        
        # Keep only recent data
        if len(self.timestamps) > self.max_points:
            self.timestamps = self.timestamps[-self.max_points:]
            self.packet_counts = self.packet_counts[-self.max_points:]
        
        # Clear and redraw
        self.axes.clear()
        self.axes.plot(self.timestamps, self.packet_counts, 'b-', linewidth=2)
        self.axes.set_xlabel('Time')
        self.axes.set_ylabel('Packets/sec')
        self.axes.set_title('Real-time Packet Rate')
        self.axes.grid(True)
        self.draw()

class PacketFilterWidget(QWidget):
    filter_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Filter group
        filter_group = QGroupBox("Packet Filters")
        filter_layout = QGridLayout()
        filter_group.setLayout(filter_layout)
        
        # Protocol filters
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "TCP", "UDP", "ICMP", "HTTP", "DNS", "ARP", "IP"])
        self.protocol_combo.currentTextChanged.connect(self.update_filter)
        filter_layout.addWidget(QLabel("Protocol:"), 0, 0)
        filter_layout.addWidget(self.protocol_combo, 0, 1)
        
        # IP address filters
        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("Source IP (e.g., 192.168.1.1)")
        self.src_ip_input.textChanged.connect(self.update_filter)
        filter_layout.addWidget(QLabel("Source IP:"), 1, 0)
        filter_layout.addWidget(self.src_ip_input, 1, 1)
        
        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("Destination IP")
        self.dst_ip_input.textChanged.connect(self.update_filter)
        filter_layout.addWidget(QLabel("Dest IP:"), 2, 0)
        filter_layout.addWidget(self.dst_ip_input, 2, 1)
        
        # Port filters
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g., 80, 443)")
        self.port_input.textChanged.connect(self.update_filter)
        filter_layout.addWidget(QLabel("Port:"), 3, 0)
        filter_layout.addWidget(self.port_input, 3, 1)
        
        # Custom filter expression
        self.custom_filter = QLineEdit()
        self.custom_filter.setPlaceholderText("Custom BPF filter (e.g., tcp port 80)")
        self.custom_filter.textChanged.connect(self.update_filter)
        filter_layout.addWidget(QLabel("Custom:"), 4, 0)
        filter_layout.addWidget(self.custom_filter, 4, 1)
        
        layout.addWidget(filter_group)
    
    def update_filter(self):
        filter_parts = []
        
        # Protocol filter
        protocol = self.protocol_combo.currentText()
        if protocol != "All":
            filter_parts.append(protocol.lower())
        
        # IP filters
        src_ip = self.src_ip_input.text().strip()
        if src_ip:
            filter_parts.append(f"src host {src_ip}")
            
        dst_ip = self.dst_ip_input.text().strip()
        if dst_ip:
            filter_parts.append(f"dst host {dst_ip}")
        
        # Port filter
        port = self.port_input.text().strip()
        if port:
            if port.isdigit():
                filter_parts.append(f"port {port}")
        
        # Custom filter
        custom = self.custom_filter.text().strip()
        if custom:
            filter_parts.append(custom)
        
        final_filter = " and ".join(filter_parts) if filter_parts else ""
        self.filter_changed.emit(final_filter)

class StatisticsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.protocol_stats = {}
        self.total_packets = 0
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Statistics group
        stats_group = QGroupBox("Protocol Statistics")
        stats_layout = QVBoxLayout()
        stats_group.setLayout(stats_layout)
        
        # Tree widget for protocol stats
        self.stats_tree = QTreeWidget()
        self.stats_tree.setHeaderLabels(["Protocol", "Packets", "Bytes", "%"])
        self.stats_tree.setColumnWidth(0, 150)
        stats_layout.addWidget(self.stats_tree)
        
        # Summary labels
        self.total_label = QLabel("Total Packets: 0")
        self.total_bytes_label = QLabel("Total Bytes: 0")
        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(self.total_bytes_label)
        
        layout.addWidget(stats_group)
    
    def update_stats(self, packet_data):
        protocol = packet_data.get("protocol", "Unknown")
        size = packet_data.get("size", 0)
        
        self.total_packets += 1
        
        if protocol not in self.protocol_stats:
            self.protocol_stats[protocol] = {"packets": 0, "bytes": 0}
        
        self.protocol_stats[protocol]["packets"] += 1
        self.protocol_stats[protocol]["bytes"] += size
        
        # Update display
        self.update_display()
    
    def update_display(self):
        self.total_label.setText(f"Total Packets: {self.total_packets:,}")
        
        total_bytes = sum(stats["bytes"] for stats in self.protocol_stats.values())
        self.total_bytes_label.setText(f"Total Bytes: {total_bytes:,}")
        
        # Update tree
        self.stats_tree.clear()
        for protocol, stats in self.protocol_stats.items():
            percentage = (stats["packets"] / self.total_packets * 100) if self.total_packets > 0 else 0
            item = QTreeWidgetItem([
                protocol,
                str(stats["packets"]),
                str(stats["bytes"]),
                f"{percentage:.1f}%"
            ])
            self.stats_tree.addTopLevelItem(item)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ultimate Professional Network Analyzer - Wireshark Edition")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Initialize data structures
        self.packets = []
        self.filtered_packets = []
        self.capture_thread = None
        self.is_capturing = False
        self.current_filter = ""
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize modules
        try:
            from data_decoder import DataDecoder, PacketAnalyzer
            self.packet_analyzer = PacketAnalyzer()
            self.data_decoder = DataDecoder()
        except ImportError:
            self.logger.warning("Data decoder modules not available")
            self.packet_analyzer = None
            self.data_decoder = None
        
        self.initUI()
        self.init_menu_bar()
        self.init_toolbar()
    
    def initUI(self):
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Create main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Navigation and filters
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        left_panel.setMaximumWidth(300)
        
        # Interface selection
        self.interface_group = QGroupBox("Network Interface")
        interface_layout = QVBoxLayout()
        self.interface_group.setLayout(interface_layout)
        
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        interface_layout.addWidget(self.interface_combo)
        
        self.refresh_interfaces_btn = QPushButton("Refresh Interfaces")
        self.refresh_interfaces_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(self.refresh_interfaces_btn)
        
        left_layout.addWidget(self.interface_group)
        
        # Packet filter widget
        self.filter_widget = PacketFilterWidget()
        self.filter_widget.filter_changed.connect(self.apply_filter)
        left_layout.addWidget(self.filter_widget)
        
        # Statistics widget
        self.stats_widget = StatisticsWidget()
        left_layout.addWidget(self.stats_widget)
        
        # Real-time chart
        self.chart_widget = RealTimeChart()
        left_layout.addWidget(self.chart_widget)
        
        left_layout.addStretch()
        
        # Right panel - Main content
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        # Tab widget for main content
        self.tabs = QTabWidget()
        right_layout.addWidget(self.tabs)
        
        # Initialize tabs
        self.init_packet_tab()
        self.init_network_tab()
        self.init_dashboard_tab()
        self.init_config_tab()
        
        # Add panels to splitter
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([300, 1300])
        
        main_layout.addWidget(main_splitter)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready - Select an interface and start capture")
        
        # Timer for real-time updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_realtime_display)
        self.update_timer.start(1000)  # Update every second
    
    def init_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        save_action = QAction('Save Capture', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_capture)
        file_menu.addAction(save_action)
        
        load_action = QAction('Load Capture', self)
        load_action.setShortcut('Ctrl+O')
        load_action.triggered.connect(self.load_capture)
        file_menu.addAction(load_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Capture menu
        capture_menu = menubar.addMenu('Capture')
        
        start_action = QAction('Start Capture', self)
        start_action.setShortcut('Ctrl+E')
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)
        
        stop_action = QAction('Stop Capture', self)
        stop_action.setShortcut('Ctrl+R')
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        reset_view_action = QAction('Reset View', self)
        reset_view_action.triggered.connect(self.reset_view)
        view_menu.addAction(reset_view_action)
    
    def init_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        # Capture controls
        self.start_capture_btn = QAction('Start Capture', self)
        self.start_capture_btn.triggered.connect(self.start_capture)
        toolbar.addAction(self.start_capture_btn)
        
        self.stop_capture_btn = QAction('Stop Capture', self)
        self.stop_capture_btn.triggered.connect(self.stop_capture)
        self.stop_capture_btn.setEnabled(False)
        toolbar.addAction(self.stop_capture_btn)
        
        toolbar.addSeparator()
        
        # Clear display
        clear_action = QAction('Clear', self)
        clear_action.triggered.connect(self.clear_display)
        toolbar.addAction(clear_action)
        
        toolbar.addSeparator()
        
        # Export
        export_action = QAction('Export', self)
        export_action.triggered.connect(self.export_data)
        toolbar.addAction(export_action)
    
    def init_packet_tab(self):
        layout = QVBoxLayout()
        self.packet_tab.setLayout(layout)
        
        # Create splitter for packet view
        packet_splitter = QSplitter(Qt.Vertical)
        
        # Top section - Packet list
        packet_list_group = QGroupBox("Captured Packets")
        packet_list_layout = QVBoxLayout()
        packet_list_group.setLayout(packet_list_layout)
        
        # Packet table with enhanced columns
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", 
            "Length", "Source Port", "Dest Port"
        ])
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSortingEnabled(True)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.itemSelectionChanged.connect(self.display_packet_details)
        
        # Set column widths
        self.packet_table.setColumnWidth(0, 50)   # No.
        self.packet_table.setColumnWidth(1, 100)  # Time
        self.packet_table.setColumnWidth(2, 150)  # Source
        self.packet_table.setColumnWidth(3, 150)  # Destination
        self.packet_table.setColumnWidth(4, 80)   # Protocol
        self.packet_table.setColumnWidth(5, 70)   # Length
        self.packet_table.setColumnWidth(6, 80)   # Source Port
        self.packet_table.setColumnWidth(7, 80)   # Dest Port
        
        packet_list_layout.addWidget(self.packet_table)
        
        # Bottom section - Packet details
        details_group = QGroupBox("Packet Details")
        details_layout = QVBoxLayout()
        details_group.setLayout(details_layout)
        
        # Create tab widget for packet details
        self.packet_details_tabs = QTabWidget()
        
        # Packet summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.packet_details_tabs.addTab(self.summary_text, "Summary")
        
        # Protocol tree tab
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(["Field", "Value"])
        self.packet_details_tabs.addTab(self.protocol_tree, "Protocol Tree")
        
        # Hex view tab
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Courier", 9))
        self.packet_details_tabs.addTab(self.hex_view, "Hex View")
        
        # Raw data tab
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(QFont("Courier", 9))
        self.packet_details_tabs.addTab(self.raw_text, "Raw Data")
        
        details_layout.addWidget(self.packet_details_tabs)
        
        packet_splitter.addWidget(packet_list_group)
        packet_splitter.addWidget(details_group)
        packet_splitter.setSizes([400, 300])
        
        layout.addWidget(packet_splitter)
    
    def init_network_tab(self):
        layout = QVBoxLayout()
        self.network_tab.setLayout(layout)
        
        # Network scan controls
        scan_group = QGroupBox("WiFi Network Scan")
        scan_layout = QHBoxLayout()
        scan_group.setLayout(scan_layout)
        
        self.scan_button = QPushButton("Scan Networks")
        self.scan_button.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_button)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)
        
        layout.addWidget(scan_group)
        
        # Network list
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(7)
        self.networks_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Channel", "Signal", "Security", 
            "Encryption", "Vendor"
        ])
        self.networks_table.setAlternatingRowColors(True)
        self.networks_table.setSortingEnabled(True)
        self.networks_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.networks_table.itemSelectionChanged.connect(self.display_network_details)
        
        # Set column widths
        self.networks_table.setColumnWidth(0, 150)  # SSID
        self.networks_table.setColumnWidth(1, 120)  # BSSID
        self.networks_table.setColumnWidth(2, 60)   # Channel
        self.networks_table.setColumnWidth(3, 70)   # Signal
        self.networks_table.setColumnWidth(4, 100)  # Security
        self.networks_table.setColumnWidth(5, 100)  # Encryption
        self.networks_table.setColumnWidth(6, 120)  # Vendor
        
        layout.addWidget(self.networks_table)
    
    def init_dashboard_tab(self):
        layout = QVBoxLayout()
        self.dashboard_tab.setLayout(layout)
        
        # Dashboard header
        header_label = QLabel("Network Analysis Dashboard")
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(header_label)
        
        # Stats grid
        stats_grid = QGridLayout()
        
        # Total packets
        self.total_packets_label = QLabel("Total Packets: 0")
        self.total_packets_label.setStyleSheet("font-size: 14px; font-weight: bold; color: blue;")
        stats_grid.addWidget(self.total_packets_label, 0, 0)
        
        # Capture duration
        self.capture_duration_label = QLabel("Duration: 00:00:00")
        self.capture_duration_label.setStyleSheet("font-size: 14px;")
        stats_grid.addWidget(self.capture_duration_label, 0, 1)
        
        # Average packet size
        self.avg_packet_size_label = QLabel("Avg Size: 0 bytes")
        self.avg_packet_size_label.setStyleSheet("font-size: 14px;")
        stats_grid.addWidget(self.avg_packet_size_label, 1, 0)
        
        # Packet rate
        self.packet_rate_label = QLabel("Rate: 0 pps")
        self.packet_rate_label.setStyleSheet("font-size: 14px;")
        stats_grid.addWidget(self.packet_rate_label, 1, 1)
        
        layout.addLayout(stats_grid)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        actions_group.setLayout(actions_layout)
        
        self.quick_start_btn = QPushButton("Start Capture")
        self.quick_start_btn.clicked.connect(self.start_capture)
        actions_layout.addWidget(self.quick_start_btn)
        
        self.quick_stop_btn = QPushButton("Stop Capture")
        self.quick_stop_btn.clicked.connect(self.stop_capture)
        self.quick_stop_btn.setEnabled(False)
        actions_layout.addWidget(self.quick_stop_btn)
        
        self.quick_clear_btn = QPushButton("Clear All")
        self.quick_clear_btn.clicked.connect(self.clear_display)
        actions_layout.addWidget(self.quick_clear_btn)
        
        layout.addWidget(actions_group)
    
    def init_config_tab(self):
        layout = QVBoxLayout()
        self.config_tab.setLayout(layout)
        
        # Capture settings
        capture_group = QGroupBox("Capture Settings")
        capture_layout = QFormLayout()
        capture_group.setLayout(capture_layout)
        
        # Buffer size
        self.buffer_size_spin = QSpinBox()
        self.buffer_size_spin.setRange(1000, 1000000)
        self.buffer_size_spin.setValue(10000)
        self.buffer_size_spin.setSingleStep(1000)
        capture_layout.addRow("Buffer Size:", self.buffer_size_spin)
        
        # Promiscuous mode
        self.promiscuous_check = QCheckBox()
        self.promiscuous_check.setChecked(True)
        capture_layout.addRow("Promiscuous Mode:", self.promiscuous_check)
        
        # Auto-scroll
        self.auto_scroll_check = QCheckBox()
        self.auto_scroll_check.setChecked(True)
        capture_layout.addRow("Auto-scroll:", self.auto_scroll_check)
        
        layout.addWidget(capture_group)
        
        # Display settings
        display_group = QGroupBox("Display Settings")
        display_layout = QFormLayout()
        display_group.setLayout(display_layout)
        
        # Time format
        self.time_format_combo = QComboBox()
        self.time_format_combo.addItems(["Seconds since beginning", "Time of day"])
        display_layout.addRow("Time Format:", self.time_format_combo)
        
        # Name resolution
        self.resolve_names_check = QCheckBox()
        self.resolve_names_check.setChecked(True)
        display_layout.addRow("Resolve Names:", self.resolve_names_check)
        
        layout.addWidget(display_group)
        layout.addStretch()
        self.packet_tab.setLayout(layout)
        
        # Contrôles de capture
        controls_layout = QHBoxLayout()
        
        self.bssid_input = QLineEdit()
        self.bssid_input.setPlaceholderText("Adresse MAC du réseau")
        controls_layout.addWidget(self.bssid_input)
        
        self.capture_duration = QComboBox()
        self.capture_duration.addItems(["10s", "30s", "1min", "5min", "Illimité"])
        controls_layout.addWidget(self.capture_duration)
        
        self.start_capture_btn = QPushButton("Démarrer capture")
        self.start_capture_btn.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_capture_btn)
        
        layout.addLayout(controls_layout)
        
        # Séparateur pour les données
        splitter = QSplitter(Qt.Horizontal)
        
        # Panneau gauche : paquets capturés
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(5)
        self.packets_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol", "Length"])
        left_layout.addWidget(self.packets_table)
        
        # Panneau droit : décodage multi-format
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        # Sélecteur de format
        self.format_combo = QComboBox()
        self.format_combo.addItems(["ASCII", "Binaire", "Hexadécimal", "Brut"])
        right_layout.addWidget(self.format_combo)
        
        self.decoded_data = QTextEdit()
        self.decoded_data.setReadOnly(True)
        right_layout.addWidget(self.decoded_data)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 300])
        
        layout.addWidget(splitter)
    
    def initConfigTab(self):
        layout = QVBoxLayout()
        self.config_tab.setLayout(layout)
        
        # Options de configuration
        config_group = QGroupBox("Options d'analyse")
        config_layout = QVBoxLayout()
        config_group.setLayout(config_layout)
        
        self.auto_save = QCheckBox("Sauvegarde automatique")
        config_layout.addWidget(self.auto_save)
        
        self.show_encrypted = QCheckBox("Afficher les réseaux chiffrés")
        self.show_encrypted.setChecked(True)
        config_layout.addWidget(self.show_encrypted)
        
        self.enable_logging = QCheckBox("Activer la journalisation")
        self.enable_logging.setChecked(True)
        config_layout.addWidget(self.enable_logging)
        
        layout.addWidget(config_group)
    
    def start_scan(self):
        self.statusBar().showMessage("Scan en cours...")
        self.scan_thread = WiFiScanThread()
        self.scan_thread.scan_complete.connect(self.display_networks)
        self.scan_thread.start()
    
    def start_capture(self):
        self.statusBar().showMessage("Capture en cours...")
        # Simulation de capture de paquets
        if self.packet_analyzer:
            # Ajouter des paquets fictifs
            test_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            self.packet_analyzer.add_packet(test_data)
            self.display_packets()
        self.statusBar().showMessage("Capture terminée")
    
    def display_networks(self, networks):
        # Afficher dans le tableau de bord
        self.networks_table.setRowCount(len(networks))
        for row, network in enumerate(networks):
            self.networks_table.setItem(row, 0, QTableWidgetItem(network['ssid']))
            self.networks_table.setItem(row, 1, QTableWidgetItem(network['bssid']))
            self.networks_table.setItem(row, 2, QTableWidgetItem(str(network['channel'])))
            self.networks_table.setItem(row, 3, QTableWidgetItem(str(network['rssi'])))
            self.networks_table.setItem(row, 4, QTableWidgetItem(network['encryption']))
        
        # Afficher dans l'onglet analyse
        self.networks_list.setRowCount(len(networks))
        for row, network in enumerate(networks):
            self.networks_list.setItem(row, 0, QTableWidgetItem(network['ssid']))
            self.networks_list.setItem(row, 1, QTableWidgetItem(network['bssid']))
            self.networks_list.setItem(row, 2, QTableWidgetItem(str(network['channel'])))
            self.networks_list.setItem(row, 3, QTableWidgetItem(str(network['rssi'])))
            self.networks_list.setItem(row, 4, QTableWidgetItem(network['encryption']))
        
        self.statusBar().showMessage(f"{len(networks)} réseaux trouvés")
    
    def display_packets(self):
        if not self.packet_analyzer:
            return
        
        packets = self.packet_analyzer.captured_packets
        self.packets_table.setRowCount(len(packets))
        
        for row, packet in enumerate(packets):
            self.packets_table.setItem(row, 0, QTableWidgetItem(packet['timestamp']))
            self.packets_table.setItem(row, 1, QTableWidgetItem(packet['source']))
            self.packets_table.setItem(row, 2, QTableWidgetItem(packet['destination']))
            self.packets_table.setItem(row, 3, QTableWidgetItem(packet['protocol']))
            self.packets_table.setItem(row, 4, QTableWidgetItem(str(packet['length'])))
    
    def export_data(self):
        if not self.packet_analyzer:
            QMessageBox.warning(self, "Export", "Aucune donnée à exporter")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Exporter les données", "wifi_analysis.txt", "Text Files (*.txt)"
        )
        
        if filename:
            success = self.packet_analyzer.export_to_txt(filename)
            if success:
                QMessageBox.information(self, "Export", "Données exportées avec succès")
            else:
                QMessageBox.warning(self, "Export", "Erreur lors de l'export")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())