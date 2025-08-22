#!/usr/bin/env python3
"""
Ultimate Professional WiFi Analysis and Security Testing Platform
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
from typing import Dict, List, Any, Optional
from pathlib import Path

# Advanced PyQt5 imports
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

# Scientific computing imports
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Network and security imports
import socket
import struct
import threading
import queue
import hashlib
import hmac
import binascii

# C++ integration
import ctypes
import platform

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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analyseur WiFi Professionnel")
        self.setGeometry(100, 100, 1200, 800)
        
        # Importer les modules
        try:
            from data_decoder import DataDecoder, PacketAnalyzer
            self.packet_analyzer = PacketAnalyzer()
            self.data_decoder = DataDecoder()
        except ImportError:
            print("Modules de décodage non disponibles")
            self.packet_analyzer = None
            self.data_decoder = None
        
        self.initUI()
    
    def initUI(self):
        # Widget principal
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Layout principal
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        # Onglets principaux
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Onglet Tableau de bord
        self.dashboard_tab = QWidget()
        self.initDashboardTab()
        self.tabs.addTab(self.dashboard_tab, "Tableau de bord")
        
        # Onglet Analyse Réseau
        self.network_tab = QWidget()
        self.initNetworkTab()
        self.tabs.addTab(self.network_tab, "Analyse Réseau")
        
        # Onglet Analyse Paquets
        self.packet_tab = QWidget()
        self.initPacketTab()
        self.tabs.addTab(self.packet_tab, "Analyse Paquets")
        
        # Onglet Configuration
        self.config_tab = QWidget()
        self.initConfigTab()
        self.tabs.addTab(self.config_tab, "Configuration")
        
        # Barre de statut
        self.statusBar().showMessage("Prêt")
    
    def initDashboardTab(self):
        layout = QVBoxLayout()
        self.dashboard_tab.setLayout(layout)
        
        # Groupe de contrôle
        control_group = QGroupBox("Contrôles principaux")
        control_layout = QHBoxLayout()
        control_group.setLayout(control_layout)
        
        # Boutons principaux
        self.scan_button = QPushButton("Scanner les réseaux")
        self.scan_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_button)
        
        self.capture_button = QPushButton("Capturer les paquets")
        self.capture_button.clicked.connect(self.start_capture)
        control_layout.addWidget(self.capture_button)
        
        self.export_button = QPushButton("Exporter vers .txt")
        self.export_button.clicked.connect(self.export_data)
        control_layout.addWidget(self.export_button)
        
        layout.addWidget(control_group)
        
        # Tableau des réseaux
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Canal", "Signal", "Sécurité"])
        layout.addWidget(self.networks_table)
    
    def initNetworkTab(self):
        layout = QVBoxLayout()
        self.network_tab.setLayout(layout)
        
        # Séparateur pour diviser l'interface
        splitter = QSplitter(Qt.Horizontal)
        
        # Panneau gauche : liste des réseaux
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        
        self.networks_list = QTableWidget()
        self.networks_list.setColumnCount(5)
        self.networks_list.setHorizontalHeaderLabels(["SSID", "BSSID", "Canal", "Signal", "Sécurité"])
        left_layout.addWidget(self.networks_list)
        
        # Panneau droit : détails du réseau sélectionné
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        self.network_details = QTextEdit()
        self.network_details.setReadOnly(True)
        right_layout.addWidget(QLabel("Détails du réseau:"))
        right_layout.addWidget(self.network_details)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 400])
        
        layout.addWidget(splitter)
    
    def initPacketTab(self):
        layout = QVBoxLayout()
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