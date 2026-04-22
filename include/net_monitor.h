#pragma once
// ============================================================
//  net_monitor.h  –  Network Security & Monitoring Engine
//  Features: Device detection, traffic stats, attack detection,
//  deauth sniffing, rogue AP, brute force, port scanning
// ============================================================
#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <vector>
#include <map>

#define NET_MON_CFG_FILE     "/netmon_cfg.json"
#define NET_MON_LOG_FILE     "/netmon_log.json"
#define NET_MON_DEVICES_FILE "/netmon_devices.json"
#define NET_MON_MAX_DEVICES  64
#define NET_MON_MAX_ALERTS   128
#define NET_MON_MAX_LOG      256
#define NET_MON_SCAN_INTERVAL_MS  10000UL
#define TRAFFIC_SPIKE_THRESHOLD   500    // packets/sec
#define FLOOD_SAME_IP_THRESHOLD   100    // requests/sec from same IP
#define BRUTE_FORCE_THRESHOLD     10     // failed attempts / 30s
#define DEAUTH_THRESHOLD          5      // deauth frames / 5s
#define ROGUE_RSSI_DIFF           15     // dBm diff for rogue AP detection

// ── Device record ─────────────────────────────────────────────
struct NetDevice {
    String   mac;
    String   ip;
    String   hostname;
    String   vendor;         // MAC OUI lookup
    int8_t   rssi          = 0;
    bool     online        = false;
    bool     blocked       = false;
    uint32_t firstSeen     = 0;
    uint32_t lastSeen      = 0;
    uint32_t txBytes       = 0;
    uint32_t rxBytes       = 0;
    uint32_t dailyBytes    = 0;
    uint32_t monthlyBytes  = 0;
    uint32_t packetCount   = 0;
    bool     isNew         = false;       // flagged as newly detected
    bool     accessBlocked = false;       // internet access blocked
};

// ── Alert severity ────────────────────────────────────────────
enum class AlertSeverity { INFO, WARNING, CRITICAL };

// ── Alert types ───────────────────────────────────────────────
enum class AlertType {
    NEW_DEVICE,
    DEVICE_OFFLINE,
    TRAFFIC_SPIKE,
    FLOOD_DETECTED,
    DDOS_DETECTED,
    BRUTE_FORCE,
    DEAUTH_ATTACK,
    ROGUE_AP,
    SSID_SPOOF,
    PORT_SCAN_RESULT,
    UNUSUAL_ACTIVITY,
    BANDWIDTH_LIMIT,
    ACCESS_BLOCKED
};

struct NetAlert {
    uint32_t     id        = 0;
    AlertType    type      = AlertType::UNUSUAL_ACTIVITY;
    AlertSeverity severity = AlertSeverity::INFO;
    String       message;
    String       source;    // IP or MAC
    uint32_t     timestamp = 0;
    bool         read      = false;
};

// ── Log entry ─────────────────────────────────────────────────
struct NetLogEntry {
    uint32_t timestamp = 0;
    String   event;
    String   detail;
    String   mac;
};

// ── Open port result ──────────────────────────────────────────
struct PortScanResult {
    String   ip;
    uint16_t port    = 0;
    String   service;
    String   risk;   // "LOW", "MEDIUM", "HIGH", "CRITICAL"
};

// ── Network monitor config ────────────────────────────────────
struct NetMonConfig {
    bool    enabled           = true;
    bool    autoScan          = true;
    uint32_t scanIntervalMs   = NET_MON_SCAN_INTERVAL_MS;
    bool    alertNewDevices   = true;
    bool    alertTrafficSpike = true;
    bool    alertDeauth       = true;
    bool    alertRogueAP      = true;
    bool    alertBruteForce   = true;
    uint32_t bandwidthLimitMB = 0;   // 0 = no limit
    bool    parentalControl   = false;
    String  parentalBlockFrom = "22:00";
    String  parentalBlockTo   = "07:00";
};

// ── Deauth frame counter (per BSSID) ─────────────────────────
struct DeauthCounter {
    String       bssid;
    uint16_t     count     = 0;
    uint32_t     windowStart = 0;
};

// ── Brute force tracker (per IP) ─────────────────────────────
struct BruteForceEntry {
    String   ip;
    uint16_t attempts    = 0;
    uint32_t windowStart = 0;
    bool     alerted     = false;
};

// ── AP record for rogue/spoof detection ──────────────────────
struct ApRecord {
    String  ssid;
    String  bssid;
    int8_t  rssi     = 0;
    uint8_t channel  = 0;
    uint32_t seenAt  = 0;
};

class NetMonitor {
public:
    void begin();
    void loop();

    // Scan
    void startScan();
    void stopScan();
    bool isScanning() const { return _scanning; }
    void triggerManualScan();

    // Device management
    String devicesJson()    const;
    String deviceJson(const String& mac) const;
    bool   blockDevice(const String& mac, bool block);
    bool   setAccessControl(const String& mac, bool blocked);
    void   updateBandwidth(const String& mac, uint32_t tx, uint32_t rx);

    // Alerts
    String alertsJson()     const;
    String alertsJsonNew()  const;  // unread only
    bool   markAlertRead(uint32_t id);
    void   clearAlerts();
    int    unreadCount()    const;

    // Timeline log
    String logJson()        const;
    void   clearLog();

    // Port scan
    void   startPortScan(const String& ip);
    bool   isPortScanning() const { return _portScanning; }
    String portScanResultsJson() const;

    // Config
    void   saveConfig(const NetMonConfig& cfg);
    NetMonConfig loadConfig() const;
    String configJson() const;

    // Stats
    String statsJson() const;

    // Detection toggles (called from API)
    void   recordLoginAttempt(const String& ip, bool failed);
    void   recordDeauthFrame(const String& bssid);

private:
    bool   _scanning      = false;
    bool   _portScanning  = false;
    bool   _initialized   = false;
    uint32_t _lastScan    = 0;
    uint32_t _alertIdCounter = 1;
    uint32_t _scanCount   = 0;

    NetMonConfig _cfg;
    std::vector<NetDevice>      _devices;
    std::vector<NetAlert>       _alerts;
    std::vector<NetLogEntry>    _log;
    std::vector<PortScanResult> _portResults;
    std::vector<ApRecord>       _knownAPs;
    std::vector<DeauthCounter>  _deauthCounters;
    std::map<String, BruteForceEntry> _bruteForceMap;

    // Port scan state
    String   _portScanTarget;
    uint16_t _portScanCurrent = 0;
    uint32_t _portScanTimer   = 0;

    // Internal
    void _doWifiScan();
    void _doArpScan();
    void _checkTrafficSpikes();
    void _checkDeauthAttacks();
    void _checkRogueAPs();
    void _checkBruteForce();
    void _checkUnusualActivity();
    void _tickPortScan();
    void _addAlert(AlertType type, AlertSeverity sev, const String& msg, const String& src = "");
    void _addLog(const String& event, const String& detail, const String& mac = "");
    void _updateDevice(const String& mac, const String& ip, int8_t rssi, const String& hostname = "");
    bool _markDeviceOffline(const String& mac);
    String _lookupVendor(const String& mac) const;
    String _portService(uint16_t port) const;
    String _portRisk(uint16_t port) const;
    void _loadDevices();
    void _saveDevices() const;
    static const uint16_t SCAN_PORTS[];
    static const uint8_t SCAN_PORT_COUNT;
};

extern NetMonitor netMonitor;
