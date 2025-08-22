import time
import socket
import struct
import threading
import json
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import scapy.all as scapy
from scapy.layers import dot11, inet, l2
import logging

class DataDecoder:
    """Advanced real-time data decoder with multi-protocol support"""
    
    PROTOCOL_NAMES = {
        1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 47: 'GRE', 50: 'ESP',
        51: 'AH', 58: 'ICMPv6', 88: 'EIGRP', 89: 'OSPF', 103: 'PIM'
    }
    
    @staticmethod
    def decode_ascii(data: bytes) -> str:
        """Decode data to ASCII with error handling"""
        try:
            return data.decode('ascii', errors='ignore')
        except Exception as e:
            logging.warning(f"ASCII decode error: {e}")
            return "[ASCII_DECODE_ERROR]"
    
    @staticmethod
    def decode_utf8(data: bytes) -> str:
        """Decode data to UTF-8 with error handling"""
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception as e:
            logging.warning(f"UTF-8 decode error: {e}")
            return "[UTF8_DECODE_ERROR]"
    
    @staticmethod
    def decode_binary(data: bytes) -> str:
        """Convert data to binary representation"""
        return ' '.join(format(byte, '08b') for byte in data)
    
    @staticmethod
    def decode_hex(data: bytes) -> str:
        """Convert data to hexadecimal representation"""
        return ' '.join(format(byte, '02x') for byte in data)
    
    @staticmethod
    def decode_base64(data: bytes) -> str:
        """Decode base64 encoded data"""
        import base64
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return "[BASE64_DECODE_ERROR]"
    
    @staticmethod
    def decode_url(data: bytes) -> str:
        """URL decode data"""
        import urllib.parse
        try:
            return urllib.parse.unquote_plus(data.decode('utf-8', errors='ignore'))
        except Exception:
            return "[URL_DECODE_ERROR]"
    
    @staticmethod
    def analyze_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    @staticmethod
    def decode_all_formats(data: bytes) -> Dict[str, Any]:
        """Comprehensive data analysis and decoding"""
        return {
            'ascii': DataDecoder.decode_ascii(data),
            'utf8': DataDecoder.decode_utf8(data),
            'binary': DataDecoder.decode_binary(data),
            'hex': DataDecoder.decode_hex(data),
            'base64': DataDecoder.decode_base64(data),
            'url': DataDecoder.decode_url(data),
            'raw_hex': data.hex(),
            'length': len(data),
            'entropy': DataDecoder.analyze_entropy(data),
            'printable_ratio': sum(1 for b in data if 32 <= b <= 126) / len(data) if data else 0
        }

class RealTimePacketAnalyzer:
    """Real-time packet analyzer with live capture and analysis"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or self._get_default_interface()
        self.captured_packets: List[Dict[str, Any]] = []
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.protocol_stats = {}
        self.size_distribution = {}
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            interfaces = scapy.get_if_list()
            wifi_interfaces = [iface for iface in interfaces if 'wlan' in iface.lower() or 'wi' in iface.lower()]
            return wifi_interfaces[0] if wifi_interfaces else interfaces[0]
        except (IndexError, OSError):
            return "eth0"
    
    def _analyze_packet(self, packet) -> Dict[str, Any]:
        """Comprehensive packet analysis"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'packet_id': self.packet_count,
            'raw_length': len(bytes(packet)),
            'layers': [],
            'protocols': [],
            'security_flags': [],
            'metadata': {}
        }
        
        # Layer analysis
        if packet.haslayer(scapy.Ether):
            eth_layer = packet[scapy.Ether]
            analysis['layers'].append('Ethernet')
            analysis['src_mac'] = eth_layer.src
            analysis['dst_mac'] = eth_layer.dst
            analysis['eth_type'] = eth_layer.type
        
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            analysis['layers'].append('IP')
            analysis['src_ip'] = ip_layer.src
            analysis['dst_ip'] = ip_layer.dst
            analysis['protocol'] = ip_layer.proto
            analysis['ttl'] = ip_layer.ttl
            analysis['ip_flags'] = ip_layer.flags
            analysis['protocol_name'] = DataDecoder.PROTOCOL_NAMES.get(ip_layer.proto, str(ip_layer.proto))
            
            # Security analysis
            if ip_layer.flags & 0x4000:  # Don't Fragment
                analysis['security_flags'].append('DF_SET')
            if ip_layer.flags & 0x2000:  # More Fragments
                analysis['security_flags'].append('MF_SET')
        
        if packet.haslayer(scapy.IPv6):
            ipv6_layer = packet[scapy.IPv6]
            analysis['layers'].append('IPv6')
            analysis['src_ip'] = ipv6_layer.src
            analysis['dst_ip'] = ipv6_layer.dst
            analysis['protocol_name'] = 'IPv6'
        
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            analysis['layers'].append('TCP')
            analysis['src_port'] = tcp_layer.sport
            analysis['dst_port'] = tcp_layer.dport
            analysis['tcp_flags'] = str(tcp_layer.flags)
            analysis['window_size'] = tcp_layer.window
            analysis['seq_num'] = tcp_layer.seq
            analysis['ack_num'] = tcp_layer.ack
            
            # Port analysis
            common_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
                           80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS'}
            analysis['service'] = common_ports.get(tcp_layer.dport, common_ports.get(tcp_layer.sport, 'Unknown'))
        
        if packet.haslayer(scapy.UDP):
            udp_layer = packet[scapy.UDP]
            analysis['layers'].append('UDP')
            analysis['src_port'] = udp_layer.sport
            analysis['dst_port'] = udp_layer.dport
            analysis['udp_length'] = udp_layer.len
        
        if packet.haslayer(scapy.ICMP):
            icmp_layer = packet[scapy.ICMP]
            analysis['layers'].append('ICMP')
            analysis['icmp_type'] = icmp_layer.type
            analysis['icmp_code'] = icmp_layer.code
        
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            analysis['layers'].append('Raw')
            analysis['payload'] = raw_data
            analysis['payload_analysis'] = DataDecoder.decode_all_formats(raw_data)
            
            # Payload security analysis
            if len(raw_data) > 0:
                analysis['payload_entropy'] = DataDecoder.analyze_entropy(raw_data)
                analysis['is_encrypted'] = analysis['payload_entropy'] > 7.5
        
        if packet.haslayer(scapy.Dot11):
            dot11_layer = packet[scapy.Dot11]
            analysis['layers'].append('802.11')
            analysis['bssid'] = dot11_layer.addr3
            analysis['ssid'] = dot11_layer.info.decode('utf-8', errors='ignore') if hasattr(dot11_layer, 'info') else None
            analysis['channel'] = getattr(dot11_layer, 'channel', None)
            analysis['signal_strength'] = getattr(dot11_layer, 'dBm_AntSignal', None)
        
        return analysis
    
    def _update_stats(self, analysis: Dict[str, Any]):
        """Update real-time statistics"""
        protocol = analysis.get('protocol_name', 'Unknown')
        self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
        
        size_range = f"{len(str(analysis['raw_length']))} digits"
        self.size_distribution[size_range] = self.size_distribution.get(size_range, 0) + 1
    
    def start_capture(self, filter_expr: str = None, count: int = 0):
        """Start real-time packet capture"""
        if self.is_capturing:
            self.logger.warning("Capture already in progress")
            return False
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop, 
            args=(filter_expr, count)
        )
        self.capture_thread.start()
        self.logger.info(f"Started packet capture on {self.interface}")
        return True
    
    def _capture_loop(self, filter_expr: str, count: int):
        """Main capture loop running in separate thread"""
        try:
            scapy.sniff(
                iface=self.interface,
                filter=filter_expr,
                prn=self._process_packet,
                count=count if count > 0 else 0,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Capture error: {e}")
        finally:
            self.is_capturing = False
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        analysis = self._analyze_packet(packet)
        self.captured_packets.append(analysis)
        self._update_stats(analysis)
        
        # Keep only last 10000 packets to prevent memory issues
        if len(self.captured_packets) > 10000:
            self.captured_packets = self.captured_packets[-10000:]
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        self.logger.info("Packet capture stopped")
    
    def get_realtime_stats(self) -> Dict[str, Any]:
        """Get real-time capture statistics"""
        return {
            'total_packets': len(self.captured_packets),
            'protocol_distribution': self.protocol_stats,
            'size_distribution': self.size_distribution,
            'capture_active': self.is_capturing,
            'interface': self.interface,
            'last_update': datetime.now().isoformat()
        }
    
    def export_to_json(self, filename: str) -> bool:
        """Export analysis to JSON format"""
        try:
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_packets': len(self.captured_packets),
                    'interface': self.interface,
                    'statistics': self.get_realtime_stats()
                },
                'packets': self.captured_packets
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Data exported to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"JSON export error: {e}")
            return False
    
    def export_to_csv(self, filename: str) -> bool:
        """Export analysis to CSV format"""
        try:
            import csv
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if not self.captured_packets:
                    return True
                
                fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol_name', 
                             'src_port', 'dst_port', 'raw_length', 'layers', 'service']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for packet in self.captured_packets:
                    row = {k: packet.get(k, '') for k in fieldnames}
                    row['layers'] = ','.join(packet.get('layers', []))
                    writer.writerow(row)
            
            self.logger.info(f"Data exported to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"CSV export error: {e}")
            return False
    
    def export_to_txt(self, filename: str) -> bool:
        """Export detailed analysis to text format"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("REAL-TIME WIFI SECURITY ANALYSIS REPORT\n")
                f.write("=" * 60 + "\n\n")
                
                stats = self.get_realtime_stats()
                f.write(f"Analysis Summary:\n")
                f.write(f"  Total Packets: {stats['total_packets']}\n")
                f.write(f"  Capture Interface: {stats['interface']}\n")
                f.write(f"  Capture Active: {stats['capture_active']}\n")
                f.write(f"  Last Update: {stats['last_update']}\n\n")
                
                f.write("Protocol Distribution:\n")
                for protocol, count in stats['protocol_distribution'].items():
                    percentage = (count / stats['total_packets']) * 100 if stats['total_packets'] > 0 else 0
                    f.write(f"  {protocol}: {count} ({percentage:.1f}%)\n")
                f.write("\n")
                
                f.write("Detailed Packet Analysis:\n")
                f.write("-" * 60 + "\n\n")
                
                for i, packet in enumerate(self.captured_packets, 1):
                    f.write(f"PACKET {i}:\n")
                    f.write(f"  Timestamp: {packet['timestamp']}\n")
                    f.write(f"  Layers: {', '.join(packet['layers'])}\n")
                    
                    if 'src_ip' in packet:
                        f.write(f"  Source IP: {packet['src_ip']}\n")
                        f.write(f"  Destination IP: {packet['dst_ip']}\n")
                    
                    if 'src_mac' in packet:
                        f.write(f"  Source MAC: {packet['src_mac']}\n")
                        f.write(f"  Destination MAC: {packet['dst_mac']}\n")
                    
                    if 'protocol_name' in packet:
                        f.write(f"  Protocol: {packet['protocol_name']}\n")
                    
                    if 'service' in packet:
                        f.write(f"  Service: {packet['service']}\n")
                    
                    if 'payload_analysis' in packet:
                        f.write(f"  Payload Length: {packet['payload_analysis']['length']} bytes\n")
                        f.write(f"  Payload Entropy: {packet['payload_analysis']['entropy']:.2f}\n")
                        if packet.get('is_encrypted'):
                            f.write(f"  Encryption Detected: YES\n")
                    
                    f.write("\n" + "-" * 60 + "\n\n")
            
            self.logger.info(f"Data exported to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Text export error: {e}")
            return False
    
    def clear_packets(self):
        """Clear all captured packets"""
        self.captured_packets.clear()
        self.protocol_stats.clear()
        self.size_distribution.clear()
        self.packet_count = 0
        self.logger.info("All packets cleared")
    
    def get_recent_packets(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent packets"""
        return self.captured_packets[-count:] if self.captured_packets else []