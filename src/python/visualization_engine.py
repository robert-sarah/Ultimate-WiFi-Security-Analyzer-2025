import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import threading
import time
from collections import deque
from PyQt5.QtCore import QObject, pyqtSignal, QTimer
import seaborn as sns

class RealTimeVisualizer(QObject):
    data_updated = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.networks_data = {}
        self.packet_data = deque(maxlen=1000)
        self.threat_data = deque(maxlen=100)
        self.rssi_history = deque(maxlen=100)
        self.channel_usage = {}
        
        # Configuration des styles
        plt.style.use('dark_background')
        sns.set_palette("husl")
        
        self.setup_plots()
        self.start_real_time_updates()
    
    def setup_plots(self):
        # Figure principale avec sous-graphiques
        self.fig = Figure(figsize=(15, 10), facecolor='#1e1e1e')
        self.fig.suptitle('Noah WiFi Security Dashboard', fontsize=16, color='white')
        
        # Grille 3x3 pour les visualisations
        self.ax1 = self.fig.add_subplot(3, 3, 1)  # Réseaux détectés
        self.ax2 = self.fig.add_subplot(3, 3, 2)  # RSSI distribution
        self.ax3 = self.fig.add_subplot(3, 3, 3)  # Usage des canaux
        self.ax4 = self.fig.add_subplot(3, 3, 4)  # Menaces détectées
        self.ax5 = self.fig.add_subplot(3, 3, 5)  # Encryption types
        self.ax6 = self.fig.add_subplot(3, 3, 6)  # Signal strength over time
        self.ax7 = self.fig.add_subplot(3, 3, 7)  # Vendor distribution
        self.ax8 = self.fig.add_subplot(3, 3, 8)  # Security score radar
        self.ax9 = self.fig.add_subplot(3, 3, 9)  # Real-time packet flow
        
        self.configure_plot_styles()
    
    def configure_plot_styles(self):
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4, self.ax5, self.ax6, self.ax7, self.ax8, self.ax9]:
            ax.set_facecolor('#2d2d2d')
            ax.tick_params(colors='white')
            ax.xaxis.label.set_color('white')
            ax.yaxis.label.set_color('white')
            ax.title.set_color('white')
            for spine in ax.spines.values():
                spine.set_color('white')
    
    def update_network_data(self, networks):
        """Mettre à jour les données des réseaux"""
        current_time = datetime.now()
        
        for network in networks:
            key = network['bssid']
            if key not in self.networks_data:
                self.networks_data[key] = {
                    'ssid': network['ssid'],
                    'rssi_history': deque(maxlen=50),
                    'timestamps': deque(maxlen=50),
                    'encryption': network['encryption'],
                    'channel': network['channel'],
                    'vendor': network['vendor']
                }
            
            self.networks_data[key]['rssi_history'].append(network['rssi'])
            self.networks_data[key]['timestamps'].append(current_time)
            
            # Mise à jour de l'usage des canaux
            channel = network['channel']
            if channel not in self.channel_usage:
                self.channel_usage[channel] = 0
            self.channel_usage[channel] += 1
    
    def update_packet_data(self, packet_info):
        """Mettre à jour les données des paquets"""
        self.packet_data.append({
            'timestamp': datetime.now(),
            'type': packet_info.get('type', 'unknown'),
            'size': packet_info.get('size', 0),
            'source': packet_info.get('source', 'unknown'),
            'destination': packet_info.get('destination', 'unknown')
        })
    
    def update_threat_data(self, threat_info):
        """Mettre à jour les données des menaces"""
        self.threat_data.append({
            'timestamp': datetime.now(),
            'type': threat_info.get('type', 'unknown'),
            'severity': threat_info.get('severity', 'medium'),
            'network': threat_info.get('network', 'unknown'),
            'description': threat_info.get('description', '')
        })
    
    def plot_network_detection(self):
        """Graphique 1: Réseaux détectés au fil du temps"""
        self.ax1.clear()
        
        if self.networks_data:
            timestamps = []
            counts = []
            
            # Compter les réseaux uniques par intervalle de 5 secondes
            now = datetime.now()
            for i in range(20):
                time_point = now - timedelta(seconds=i*5)
                count = sum(1 for data in self.networks_data.values() 
                          if data['timestamps'] and 
                          abs((data['timestamps'][-1] - time_point).total_seconds()) < 5)
                
                timestamps.append(time_point)
                counts.append(count)
            
            self.ax1.plot(timestamps, counts[::-1], 'g-', linewidth=2)
            self.ax1.fill_between(timestamps, 0, counts[::-1], alpha=0.3, color='green')
            self.ax1.set_title('Networks Detected Over Time')
            self.ax1.set_ylabel('Count')
            self.ax1.tick_params(axis='x', rotation=45)
    
    def plot_rssi_distribution(self):
        """Graphique 2: Distribution RSSI"""
        self.ax2.clear()
        
        if self.networks_data:
            rssis = [list(data['rssi_history'])[-1] for data in self.networks_data.values() 
                    if data['rssi_history']]
            
            if rssis:
                self.ax2.hist(rssis, bins=20, alpha=0.7, color='skyblue', edgecolor='white')
                self.ax2.axvline(np.mean(rssis), color='red', linestyle='--', 
                               label=f'Mean: {np.mean(rssis):.1f}')
                self.ax2.set_title('RSSI Distribution')
                self.ax2.set_xlabel('RSSI (dBm)')
                self.ax2.set_ylabel('Count')
                self.ax2.legend()
    
    def plot_channel_usage(self):
        """Graphique 3: Usage des canaux"""
        self.ax3.clear()
        
        if self.channel_usage:
            channels = list(self.channel_usage.keys())
            counts = list(self.channel_usage.values())
            
            colors = ['red' if c in [1, 6, 11] else 'blue' for c in channels]
            bars = self.ax3.bar(channels, counts, color=colors, alpha=0.7)
            
            # Ajouter les valeurs sur les barres
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                self.ax3.text(bar.get_x() + bar.get_width()/2., height,
                            f'{count}', ha='center', va='bottom', color='white')
            
            self.ax3.set_title('Channel Usage')
            self.ax3.set_xlabel('Channel')
            self.ax3.set_ylabel('Network Count')
            self.ax3.set_xticks(range(1, 15))
    
    def plot_threat_detection(self):
        """Graphique 4: Menaces détectées"""
        self.ax4.clear()
        
        if self.threat_data:
            # Compter les menaces par type
            threat_counts = {}
            for threat in self.threat_data:
                threat_type = threat['type']
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            
            if threat_counts:
                types = list(threat_counts.keys())
                counts = list(threat_counts.values())
                
                # Diagramme en secteurs
                colors = ['red', 'orange', 'yellow', 'purple']
                wedges, texts, autotexts = self.ax4.pie(counts, labels=types, autopct='%1.1f%%',
                                                       colors=colors, startangle=90)
                
                for autotext in autotexts:
                    autotext.set_color('white')
                
                self.ax4.set_title('Threat Distribution')
    
    def plot_encryption_types(self):
        """Graphique 5: Types de chiffrement"""
        self.ax5.clear()
        
        if self.networks_data:
            encryption_counts = {}
            for data in self.networks_data.values():
                enc = data['encryption']
                encryption_counts[enc] = encryption_counts.get(enc, 0) + 1
            
            if encryption_counts:
                enc_types = list(encryption_counts.keys())
                counts = list(encryption_counts.values())
                
                # Diagramme en anneau
                colors = plt.cm.Set3(np.linspace(0, 1, len(enc_types)))
                wedges, texts = self.ax5.pie(counts, labels=enc_types, colors=colors,
                                           startangle=90, pctdistance=0.85)
                
                # Créer l'anneau
                centre_circle = plt.Circle((0, 0), 0.70, fc='#2d2d2d')
                self.ax5.add_artist(centre_circle)
                
                self.ax5.set_title('Encryption Types')
    
    def plot_signal_strength_time(self):
        """Graphique 6: Force du signal dans le temps"""
        self.ax6.clear()
        
        if self.networks_data:
            # Afficher les 5 réseaux avec le plus d'historique
            sorted_networks = sorted(self.networks_data.items(), 
                                   key=lambda x: len(x[1]['rssi_history']), reverse=True)[:5]
            
            for bssid, data in sorted_networks:
                if len(data['rssi_history']) > 1:
                    timestamps = list(data['timestamps'])
                    rssis = list(data['rssi_history'])
                    
                    # Lissage des courbes
                    if len(rssis) > 5:
                        rssis_smooth = pd.Series(rssis).rolling(window=3).mean()
                        self.ax6.plot(timestamps, rssis_smooth, label=data['ssid'][:10], linewidth=2)
                    else:
                        self.ax6.plot(timestamps, rssis, label=data['ssid'][:10], linewidth=2)
            
            self.ax6.set_title('Signal Strength Over Time')
            self.ax6.set_xlabel('Time')
            self.ax6.set_ylabel('RSSI (dBm)')
            self.ax6.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            self.ax6.tick_params(axis='x', rotation=45)
    
    def plot_vendor_distribution(self):
        """Graphique 7: Distribution des vendeurs"""
        self.ax7.clear()
        
        if self.networks_data:
            vendor_counts = {}
            for data in self.networks_data.values():
                vendor = data['vendor']
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            
            # Top 10 vendeurs
            top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if top_vendors:
                vendors = [v[0][:15] + '...' if len(v[0]) > 15 else v[0] for v in top_vendors]
                counts = [v[1] for v in top_vendors]
                
                bars = self.ax7.barh(vendors, counts, color='lightcoral')
                self.ax7.set_title('Top 10 Vendors')
                self.ax7.set_xlabel('Count')
                
                # Ajouter les valeurs
                for bar, count in zip(bars, counts):
                    width = bar.get_width()
                    self.ax7.text(width, bar.get_y() + bar.get_height()/2.,
                                f'{count}', ha='left', va='center', color='white')
    
    def plot_security_radar(self):
        """Graphique 8: Radar de sécurité"""
        self.ax8.clear()
        
        if self.networks_data:
            # Calculer les scores moyens
            encryption_scores = []
            signal_scores = []
            vendor_scores = []
            
            for data in self.networks_data.values():
                # Score encryption (0-100)
                enc = data['encryption']
                if 'WPA3' in enc:
                    encryption_scores.append(100)
                elif 'WPA2' in enc:
                    encryption_scores.append(80)
                elif 'WPA' in enc:
                    encryption_scores.append(60)
                elif 'WEP' in enc:
                    encryption_scores.append(20)
                else:
                    encryption_scores.append(0)
                
                # Score signal (basé sur RSSI)
                rssi = list(data['rssi_history'])[-1] if data['rssi_history'] else -70
                signal_scores.append(max(0, min(100, (rssi + 100) * 1.25)))
                
                # Score vendor (simplifié)
                vendor = data['vendor']
                vendor_scores.append(70)  # Score par défaut
            
            if encryption_scores and signal_scores and vendor_scores:
                categories = ['Encryption', 'Signal', 'Vendor', 'Stability', 'WPS']
                values = [
                    np.mean(encryption_scores),
                    np.mean(signal_scores),
                    np.mean(vendor_scores),
                    75,  # Stability score placeholder
                    90   # WPS score placeholder
                ]
                
                # Créer le radar chart
                angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
                values += values[:1]  # Fermer le cercle
                angles += angles[:1]
                
                self.ax8.plot(angles, values, 'o-', linewidth=2, color='cyan')
                self.ax8.fill(angles, values, alpha=0.25, color='cyan')
                self.ax8.set_xticks(angles[:-1])
                self.ax8.set_xticklabels(categories)
                self.ax8.set_ylim(0, 100)
                self.ax8.set_title('Security Radar')
                self.ax8.grid(True)
    
    def plot_packet_flow(self):
        """Graphique 9: Flux de paquets en temps réel"""
        self.ax9.clear()
        
        if self.packet_data:
            # Grouper par type de paquet
            packet_types = {}
            for packet in self.packet_data:
                ptype = packet['type']
                packet_types[ptype] = packet_types.get(ptype, 0) + 1
            
            if packet_types:
                types = list(packet_types.keys())
                counts = list(packet_types.values())
                
                # Heatmap simplifiée
                x = np.arange(len(types))
                y = np.arange(5)
                X, Y = np.meshgrid(x, y)
                Z = np.array([counts] * 5)
                
                im = self.ax9.imshow(Z, cmap='viridis', aspect='auto')
                self.ax9.set_xticks(range(len(types)))
                self.ax9.set_xticklabels(types, rotation=45)
                self.ax9.set_yticks([])
                self.ax9.set_title('Packet Flow Heatmap')
                
                # Colorbar
                cbar = plt.colorbar(im, ax=self.ax9)
                cbar.set_label('Count', color='white')
                cbar.ax.yaxis.set_tick_params(color='white')
    
    def update_all_plots(self):
        """Mettre à jour tous les graphiques"""
        try:
            self.plot_network_detection()
            self.plot_rssi_distribution()
            self.plot_channel_usage()
            self.plot_threat_detection()
            self.plot_encryption_types()
            self.plot_signal_strength_time()
            self.plot_vendor_distribution()
            self.plot_security_radar()
            self.plot_packet_flow()
            
            self.fig.tight_layout()
            self.data_updated.emit({
                'status': 'updated',
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour des graphiques: {e}")
    
    def start_real_time_updates(self):
        """Démarrer les mises à jour en temps réel"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_all_plots)
        self.timer.start(2000)  # Mettre à jour toutes les 2 secondes
    
    def export_dashboard(self, filename):
        """Exporter le tableau de bord"""
        self.fig.savefig(filename, dpi=300, bbox_inches='tight', 
                        facecolor='#1e1e1e', edgecolor='none')
    
    def get_canvas(self):
        """Obtenir le canvas pour PyQt5"""
        return FigureCanvas(self.fig)

class AdvancedChartEngine:
    """Moteur de graphiques avancés avec interactions"""
    
    def __init__(self):
        self.colors = {
            'primary': '#00ff88',
            'secondary': '#ff6b6b',
            'accent': '#4ecdc4',
            'background': '#1e1e1e',
            'text': '#ffffff'
        }
    
    def create_3d_network_map(self, networks):
        """Créer une carte 3D des réseaux"""
        fig = plt.figure(figsize=(12, 8))
        ax = fig.add_subplot(111, projection='3d')
        
        x_coords = []
        y_coords = []
        z_coords = []
        colors = []
        sizes = []
        
        for network in networks:
            x_coords.append(network.get('x', np.random.uniform(0, 100)))
            y_coords.append(network.get('y', np.random.uniform(0, 100)))
            z_coords.append(network.get('rssi', -50))
            
            # Couleur basée sur le niveau de sécurité
            security = network.get('security_score', 50)
            if security > 80:
                colors.append('green')
            elif security > 50:
                colors.append('yellow')
            else:
                colors.append('red')
            
            # Taille basée sur la puissance du signal
            sizes.append(max(20, abs(network.get('rssi', -50)) * 2))
        
        scatter = ax.scatter(x_coords, y_coords, z_coords, 
                           c=colors, s=sizes, alpha=0.7)
        
        ax.set_xlabel('X Position')
        ax.set_ylabel('Y Position')
        ax.set_zlabel('RSSI (dBm)')
        ax.set_title('3D Network Security Map')
        
        return fig
    
    def create_security_timeline(self, historical_data):
        """Créer une timeline de sécurité"""
        fig, ax = plt.subplots(figsize=(15, 6))
        
        # Préparer les données
        timestamps = [d['timestamp'] for d in historical_data]
        security_scores = [d['security_score'] for d in historical_data]
        threat_levels = [d['threat_level'] for d in historical_data]
        
        # Créer le graphique en aires
        ax.fill_between(timestamps, 0, security_scores, 
                       alpha=0.3, color='green', label='Security Score')
        ax.plot(timestamps, security_scores, color='green', linewidth=2)
        
        # Ajouter les menaces
        ax2 = ax.twinx()
        ax2.plot(timestamps, threat_levels, color='red', linewidth=2, 
                linestyle='--', label='Threat Level')
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Security Score', color='green')
        ax2.set_ylabel('Threat Level', color='red')
        
        plt.title('Security Timeline Analysis')
        fig.legend()
        
        return fig
    
    def create_correlation_matrix(self, networks):
        """Créer une matrice de corrélation"""
        # Extraire les caractéristiques
        features = []
        for network in networks:
            features.append([
                network.get('rssi', -50),
                network.get('channel', 6),
                len(network.get('encryption', '')),
                network.get('security_score', 50),
                network.get('wps_enabled', 0)
            ])
        
        if features:
            df = pd.DataFrame(features, 
                            columns=['RSSI', 'Channel', 'Encryption Length', 
                                   'Security Score', 'WPS Enabled'])
            
            correlation_matrix = df.corr()
            
            fig, ax = plt.subplots(figsize=(8, 6))
            sns.heatmap(correlation_matrix, annot=True, cmap='RdYlBu_r', 
                       center=0, ax=ax)
            ax.set_title('Network Security Correlation Matrix')
            
            return fig
        
        return None

# Classe principale pour l'interface
class DashboardManager:
    def __init__(self):
        self.visualizer = RealTimeVisualizer()
        self.chart_engine = AdvancedChartEngine()
        
    def get_main_dashboard(self):
        """Obtenir le tableau de bord principal"""
        return self.visualizer.get_canvas()
    
    def update_networks(self, networks):
        """Mettre à jour avec de nouveaux réseaux"""
        self.visualizer.update_network_data(networks)
    
    def update_packets(self, packet_info):
        """Mettre à jour avec des paquets"""
        self.visualizer.update_packet_data(packet_info)
    
    def update_threats(self, threat_info):
        """Mettre à jour avec des menaces"""
        self.visualizer.update_threat_data(threat_info)
    
    def export_analysis(self, filename):
        """Exporter l'analyse complète"""
        self.visualizer.export_dashboard(filename)

# Exemple d'utilisation
if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
    
    app = QApplication(sys.argv)
    
    # Créer une fenêtre de test
    window = QMainWindow()
    window.setWindowTitle("Noah WiFi Dashboard")
    window.setGeometry(100, 100, 1200, 800)
    
    # Créer le gestionnaire
    manager = DashboardManager()
    
    # Exemple de données
    sample_networks = [
        {'ssid': 'TestNetwork1', 'bssid': '00:11:22:33:44:55', 'rssi': -45, 
         'channel': 6, 'encryption': 'WPA2', 'vendor': 'Cisco', 'security_score': 85},
        {'ssid': 'TestNetwork2', 'bssid': 'AA:BB:CC:DD:EE:FF', 'rssi': -65, 
         'channel': 11, 'encryption': 'WPA', 'vendor': 'TP-LINK', 'security_score': 60},
    ]
    
    manager.update_networks(sample_networks)
    
    # Afficher
    canvas = manager.get_main_dashboard()
    
    central_widget = QWidget()
    layout = QVBoxLayout()
    layout.addWidget(canvas)
    central_widget.setLayout(layout)
    window.setCentralWidget(central_widget)
    
    window.show()
    sys.exit(app.exec_())