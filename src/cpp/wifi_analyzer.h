#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#ifdef WINDOWS_PLATFORM
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#elif defined(APPLE_PLATFORM)
#include <CoreWLAN/CoreWLAN.h>
#include <SystemConfiguration/SystemConfiguration.h>
#elif defined(LINUX_PLATFORM)
#include <net/if.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#endif

namespace noah_wifi {

// Structures de données avancées
struct WiFiNetwork {
    std::string ssid;
    std::string bssid;
    int channel;
    int frequency;
    int rssi;
    int noise;
    std::string encryption;
    std::string auth_mode;
    bool wps_enabled;
    std::string vendor;
    std::chrono::system_clock::time_point last_seen;
    std::map<std::string, std::string> extended_info;
    
    WiFiNetwork() : channel(0), frequency(0), rssi(0), noise(0), wps_enabled(false) {}
};

struct PacketInfo {
    std::string source_mac;
    std::string dest_mac;
    std::string bssid;
    std::string type;
    int length;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> raw_data;
    std::map<std::string, std::string> metadata;
};

struct AttackResult {
    bool success;
    std::string message;
    std::string method;
    std::chrono::duration<double> duration;
    std::map<std::string, std::string> details;
};

// Configuration avancée
struct AdvancedConfig {
    bool enable_monitor_mode;
    bool enable_packet_injection;
    bool enable_deauth_attacks;
    bool enable_wps_attacks;
    bool enable_wpa3_bypass;
    int channel_hop_delay;
    int scan_timeout;
    std::string interface_name;
    std::string output_format;
    bool ethical_mode;
    std::string authorization_key;
    
    AdvancedConfig() : 
        enable_monitor_mode(true),
        enable_packet_injection(false),
        enable_deauth_attacks(false),
        enable_wps_attacks(false),
        enable_wpa3_bypass(false),
        channel_hop_delay(250),
        scan_timeout(5000),
        ethical_mode(true) {}
};

// Interface principale WiFi
class WiFiAnalyzer {
private:
    std::unique_ptr<class WiFiAnalyzerImpl> pImpl;
    std::atomic<bool> is_scanning;
    std::atomic<bool> is_capturing;
    std::thread scan_thread;
    std::thread capture_thread;
    std::mutex data_mutex;
    AdvancedConfig config;
    
public:
    WiFiAnalyzer();
    ~WiFiAnalyzer();
    
    // Configuration
    void set_config(const AdvancedConfig& config);
    AdvancedConfig get_config() const;
    
    // Scan réseaux
    std::vector<WiFiNetwork> scan_networks();
    void start_continuous_scan(std::function<void(const std::vector<WiFiNetwork>&)> callback);
    void stop_continuous_scan();
    
    // Capture paquets
    std::vector<PacketInfo> capture_packets(int duration_ms = 5000);
    void start_packet_capture(std::function<void(const PacketInfo&)> callback);
    void stop_packet_capture();
    
    // Attaques éthiques
    AttackResult perform_wps_pin_attack(const std::string& bssid, const std::string& pin);
    AttackResult perform_deauth_attack(const std::string& bssid, const std::string& client_mac = "");
    AttackResult perform_handshake_capture(const std::string& bssid, int timeout_ms = 30000);
    AttackResult perform_wpa3_bypass(const std::string& bssid);
    
    // Analyse avancée
    std::string analyze_encryption(const std::string& bssid);
    std::map<std::string, int> get_channel_usage();
    std::vector<std::string> detect_rogue_aps();
    std::map<std::string, double> calculate_signal_strength_map();
    
    // Outils système
    std::vector<std::string> get_available_interfaces();
    bool set_monitor_mode(const std::string& interface, bool enable);
    bool check_root_privileges();
    std::string get_system_info();
    
    // Gestion des données
    void export_data(const std::string& filename, const std::string& format);
    void clear_cache();
    size_t get_cache_size();
    
    // Éthique et sécurité
    bool check_authorization(const std::string& key);
    void enable_ethical_mode(bool enable);
    std::string get_security_report();
};

// Modules avancés
class PacketAnalyzer {
public:
    static std::string decode_packet(const PacketInfo& packet);
    static std::vector<std::string> extract_handshakes(const std::vector<PacketInfo>& packets);
    static std::map<std::string, int> analyze_traffic_patterns(const std::vector<PacketInfo>& packets);
    static bool detect_anomalies(const std::vector<PacketInfo>& packets);
};

class CryptographyEngine {
public:
    static std::string crack_wep(const std::vector<PacketInfo>& packets);
    static std::string crack_wpa(const std::vector<PacketInfo>& packets, const std::string& wordlist_path);
    static std::string decrypt_wpa3(const std::string& data, const std::string& key);
    static std::string generate_wordlist(const std::string& base_info);
};

class AIAnalyzer {
public:
    static std::map<std::string, double> predict_vulnerabilities(const WiFiNetwork& network);
    static std::string classify_device(const std::string& mac_address);
    static std::vector<std::string> generate_attack_recommendations(const WiFiNetwork& network);
    static double calculate_security_score(const WiFiNetwork& network);
};

// Exceptions personnalisées
class WiFiAnalyzerException : public std::exception {
private:
    std::string message;
public:
    explicit WiFiAnalyzerException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};

class AuthorizationException : public WiFiAnalyzerException {
public:
    explicit AuthorizationException(const std::string& msg) : WiFiAnalyzerException(msg) {}
};

class PlatformNotSupportedException : public WiFiAnalyzerException {
public:
    explicit PlatformNotSupportedException(const std::string& msg) : WiFiAnalyzerException(msg) {}
};

} // namespace noah_wifi