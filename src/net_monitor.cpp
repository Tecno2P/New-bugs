// ============================================================
//  net_monitor.cpp  –  Network Security & Monitoring Engine
//  ESP32 WiFi scan + ARP probe + security detection
// ============================================================
#include "net_monitor.h"
#include "config.h"
#include <esp_wifi.h>
#include <WiFiClient.h>

NetMonitor netMonitor;

// Common ports to scan + risk levels
const uint16_t NetMonitor::SCAN_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1723, 3306, 3389, 5900, 8080, 8443, 9200
};
const uint8_t NetMonitor::SCAN_PORT_COUNT = 20;

// ── MAC vendor OUI lookup (top 30 common vendors) ────────────
String NetMonitor::_lookupVendor(const String& mac) const {
    if (mac.length() < 8) return "Unknown";
    String oui = mac.substring(0, 8);
    oui.toUpperCase();
    oui.replace("-", ":");
    // OUI prefix → vendor
    struct { const char* oui; const char* vendor; } table[] = {
        {"B8:27:EB", "Raspberry Pi"},
        {"DC:A6:32", "Raspberry Pi"},
        {"E4:5F:01", "Raspberry Pi"},
        {"00:50:56", "VMware"},
        {"08:00:27", "VirtualBox"},
        {"AC:DE:48", "Apple"},
        {"00:17:FA", "Microsoft"},
        {"00:23:24", "Apple"},
        {"A4:C3:F0", "Apple"},
        {"F0:18:98", "Apple"},
        {"00:1A:11", "Google"},
        {"54:60:09", "Google"},
        {"94:EB:2C", "Samsung"},
        {"EC:9B:F3", "Samsung"},
        {"00:26:B9", "Dell"},
        {"D4:BE:D9", "Dell"},
        {"FC:15:B4", "Intel"},
        {"00:1B:21", "Intel"},
        {"18:66:DA", "Xiaomi"},
        {"00:9A:CD", "Huawei"},
        {"28:31:52", "Huawei"},
        {"E8:9F:80", "Espressif"},
        {"84:CC:A8", "Espressif"},
        {"30:AE:A4", "Espressif"},
        {"10:52:1C", "Espressif"},
        {"00:0C:29", "VMware"},
        {"2C:54:91", "Intel"},
        {"00:E0:4C", "Realtek"},
        {nullptr, nullptr}
    };
    for (int i = 0; table[i].oui; i++) {
        if (oui.startsWith(table[i].oui)) return String(table[i].vendor);
    }
    return "Unknown";
}

// ── Port service + risk ───────────────────────────────────────
String NetMonitor::_portService(uint16_t port) const {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 135:  return "RPC";
        case 139:  return "NetBIOS";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 1433: return "MSSQL";
        case 1723: return "PPTP VPN";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5900: return "VNC";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 9200: return "Elasticsearch";
        default:   return "Unknown";
    }
}

String NetMonitor::_portRisk(uint16_t port) const {
    switch (port) {
        case 23:   return "CRITICAL";  // Telnet unencrypted
        case 21:   return "HIGH";      // FTP plaintext
        case 3389: return "HIGH";      // RDP often exploited
        case 5900: return "HIGH";      // VNC
        case 445:  return "HIGH";      // SMB (EternalBlue)
        case 1433: return "HIGH";      // MSSQL
        case 3306: return "HIGH";      // MySQL exposed
        case 9200: return "HIGH";      // Elasticsearch open
        case 135:  return "MEDIUM";
        case 139:  return "MEDIUM";
        case 1723: return "MEDIUM";
        case 22:   return "LOW";       // SSH is acceptable
        case 80:   return "LOW";
        case 443:  return "LOW";
        default:   return "LOW";
    }
}

// ── begin / loop ──────────────────────────────────────────────
void NetMonitor::begin() {
    _cfg = loadConfig();
    _loadDevices();
    _initialized = true;
    _lastScan    = millis() - _cfg.scanIntervalMs + 3000; // first scan after 3s
    Serial.println("[NetMon] Network monitor initialized");
    _addLog("SYSTEM", "Network monitor started");
}

void NetMonitor::loop() {
    if (!_initialized || !_cfg.enabled) return;

    // Auto scan
    if (_cfg.autoScan && millis() - _lastScan >= _cfg.scanIntervalMs) {
        _lastScan = millis();
        _doWifiScan();
        _doArpScan();
        _checkTrafficSpikes();
        _checkDeauthAttacks();
        _checkRogueAPs();
        _checkUnusualActivity();
        _scanCount++;
    }

    // Port scan tick
    if (_portScanning) _tickPortScan();
}

void NetMonitor::startScan() {
    _scanning = true;
    _doWifiScan();
    _doArpScan();
    _scanning = false;
}

void NetMonitor::stopScan() { _scanning = false; }

void NetMonitor::triggerManualScan() {
    _lastScan = 0; // force next loop() to scan
}

// ── WiFi scan (APs + connected stations) ─────────────────────
void NetMonitor::_doWifiScan() {
    int n = WiFi.scanNetworks(false, true, false, 100);
    std::vector<ApRecord> currentAPs;

    for (int i = 0; i < n; i++) {
        ApRecord ap;
        ap.ssid    = WiFi.SSID(i);
        ap.bssid   = WiFi.BSSIDstr(i);
        ap.rssi    = WiFi.RSSI(i);
        ap.channel = WiFi.channel(i);
        ap.seenAt  = millis();
        currentAPs.push_back(ap);
    }

    // SSID spoof / rogue AP detection
    // Check for same SSID on different BSSIDs with channel mismatch
    for (size_t i = 0; i < currentAPs.size(); i++) {
        for (size_t j = i + 1; j < currentAPs.size(); j++) {
            if (currentAPs[i].ssid == currentAPs[j].ssid &&
                currentAPs[i].bssid != currentAPs[j].bssid) {
                // Same SSID different BSSID
                bool chanMismatch = (currentAPs[i].channel != currentAPs[j].channel);
                if (chanMismatch) {
                    String msg = "SSID Spoof detected: '" + currentAPs[i].ssid +
                                 "' on ch" + String(currentAPs[i].channel) +
                                 " AND ch" + String(currentAPs[j].channel);
                    _addAlert(AlertType::SSID_SPOOF, AlertSeverity::CRITICAL, msg,
                              currentAPs[j].bssid);
                    _addLog("SSID_SPOOF", msg, currentAPs[j].bssid);
                }
                // Strong signal rogue AP check
                int rssiDiff = abs((int)currentAPs[i].rssi - (int)currentAPs[j].rssi);
                if (rssiDiff < ROGUE_RSSI_DIFF) {
                    String msg2 = "Potential Rogue AP: '" + currentAPs[i].ssid +
                                  "' BSSID " + currentAPs[j].bssid +
                                  " RSSI " + String(currentAPs[j].rssi) + "dBm";
                    _addAlert(AlertType::ROGUE_AP, AlertSeverity::WARNING, msg2,
                              currentAPs[j].bssid);
                }
            }
        }
    }

    _knownAPs = currentAPs;
    WiFi.scanDelete();
}

// ── ARP scan — discovers all connected devices ────────────────
void NetMonitor::_doArpScan() {
    uint32_t now = millis() / 1000;

    // ── 1. AP mode: get all connected stations ────────────────
    wifi_sta_list_t staList;
    memset(&staList, 0, sizeof(staList));
    if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK) {
        // Register all connected AP stations (MAC + estimated IP)
        for (int i = 0; i < staList.num; i++) {
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     staList.sta[i].mac[0], staList.sta[i].mac[1],
                     staList.sta[i].mac[2], staList.sta[i].mac[3],
                     staList.sta[i].mac[4], staList.sta[i].mac[5]);
            // ESP32 DHCP assigns .2, .3, .4... to clients in order
            String ipEst = "192.168.4." + String(i + 2);
            _updateDevice(String(mac), ipEst, staList.sta[i].rssi);
        }
    }

    // ── 2. Add self (AP interface) ────────────────────────────
    if (WiFi.softAPIP() != IPAddress(0,0,0,0)) {
        String selfMac = WiFi.softAPmacAddress();
        selfMac.toUpperCase();
        _updateDevice(selfMac, WiFi.softAPIP().toString(), 0, "ESP32-AP");
    }

    // ── 3. STA mode: add self + gateway ──────────────────────
    if (WiFi.status() == WL_CONNECTED) {
        String myMac = WiFi.macAddress();
        myMac.toUpperCase();
        _updateDevice(myMac, WiFi.localIP().toString(), WiFi.RSSI(), "This-Device");

        // Add gateway (router) — ping to confirm alive
        String gwIp = WiFi.gatewayIP().toString();
        if (gwIp != "0.0.0.0") {
            _updateDevice("00:00:00:00:00:00", gwIp, 0, "Router/Gateway");
        }

        // ── 4. Scan LAN subnet for active hosts via TCP probe ─
        // Use gateway to determine subnet (e.g. 192.168.1.x)
        IPAddress gw = WiFi.gatewayIP();
        IPAddress local = WiFi.localIP();
        // Only scan /24 subnet when scanIntervalMs allows
        static unsigned long _lastLanScan = 0;
        if (millis() - _lastLanScan > 60000UL) {  // LAN scan every 60s
            _lastLanScan = millis();
            for (int host = 1; host <= 254; host++) {
                if (host == local[3]) continue;  // skip self
                IPAddress target(gw[0], gw[1], gw[2], host);
                // Quick TCP probe on port 80
                WiFiClient client;
                client.setTimeout(50);
                if (client.connect(target, 80)) {
                    client.stop();
                    char ipbuf[16];
                    snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d",
                             target[0], target[1], target[2], target[3]);
                    // MAC is not accessible in STA mode — use IP-derived placeholder
                    // that is deterministic and clearly labelled as unknown
                    char unknownMac[20];
                    snprintf(unknownMac, sizeof(unknownMac),
                             "unknown-%d.%d", gw[2], host);
                    _updateDevice(String(unknownMac), String(ipbuf), 0);
                }
                yield();  // prevent watchdog
            }
        }
    }

    // ── 5. Mark stale devices offline ────────────────────────
    for (auto& d : _devices) {
        // FIX: ensure minimum offline threshold of 30s to avoid false
        // positives when scanIntervalMs is small or zero; cast to uint32_t
        // to prevent overflow on large scanIntervalMs values.
        uint32_t offlineThreshSec = (uint32_t)(
            (_cfg.scanIntervalMs > 0)
                ? max((uint32_t)30u, (uint32_t)(_cfg.scanIntervalMs * 3u / 1000u))
                : 90u
        );
        if (d.online && (now - d.lastSeen) > offlineThreshSec) {
            d.online = false;
            _addAlert(AlertType::DEVICE_OFFLINE, AlertSeverity::INFO,
                      "Device offline: " + d.ip + " (" + d.mac + ")", d.mac);
            _addLog("OFFLINE", "Device went offline: " + d.ip, d.mac);
        }
    }
}

// ── Update / register device ──────────────────────────────────
void NetMonitor::_updateDevice(const String& mac, const String& ip,
                               int8_t rssi, const String& hostname) {
    uint32_t now = millis() / 1000;
    for (auto& d : _devices) {
        if (d.mac == mac) {
            bool wasOffline = !d.online;
            d.ip       = ip;
            d.rssi     = rssi;
            d.lastSeen = now;
            d.online   = true;
            if (!hostname.isEmpty()) d.hostname = hostname;
            if (wasOffline) {
                _addLog("ONLINE", "Device came online: " + ip, mac);
            }
            return;
        }
    }
    // New device
    if (_devices.size() >= NET_MON_MAX_DEVICES) return;
    NetDevice d;
    d.mac       = mac;
    d.ip        = ip;
    d.rssi      = rssi;
    d.firstSeen = now;
    d.lastSeen  = now;
    d.online    = true;
    d.isNew     = true;
    d.vendor    = _lookupVendor(mac);
    if (!hostname.isEmpty()) d.hostname = hostname;
    _devices.push_back(d);

    if (_cfg.alertNewDevices) {
        _addAlert(AlertType::NEW_DEVICE, AlertSeverity::WARNING,
                  "New device detected: " + ip + " [" + mac + "] " + d.vendor, mac);
    }
    _addLog("NEW_DEVICE", "New device: " + ip + " " + d.vendor, mac);
    _saveDevices();
}

// ── Traffic spike check ───────────────────────────────────────
void NetMonitor::_checkTrafficSpikes() {
    if (!_cfg.alertTrafficSpike) return;
    for (const auto& d : _devices) {
        if (d.online && d.packetCount > TRAFFIC_SPIKE_THRESHOLD) {
            _addAlert(AlertType::TRAFFIC_SPIKE, AlertSeverity::WARNING,
                      "Traffic spike from " + d.ip + " (" +
                      String(d.packetCount) + " pkts/interval)", d.mac);
        }
        if (d.txBytes > (uint32_t)FLOOD_SAME_IP_THRESHOLD * 1000) {
            _addAlert(AlertType::FLOOD_DETECTED, AlertSeverity::CRITICAL,
                      "Possible flood from " + d.ip +
                      " TX:" + String(d.txBytes / 1024) + "KB", d.mac);
        }
    }
}

// ── Deauth attack detection ───────────────────────────────────
void NetMonitor::recordDeauthFrame(const String& bssid) {
    uint32_t now = millis();
    for (auto& dc : _deauthCounters) {
        if (dc.bssid == bssid) {
            if (now - dc.windowStart > 5000) {
                dc.count       = 1;
                dc.windowStart = now;
            } else {
                dc.count++;
                if (dc.count >= DEAUTH_THRESHOLD) {
                    _addAlert(AlertType::DEAUTH_ATTACK, AlertSeverity::CRITICAL,
                              "Deauthentication attack detected! BSSID: " + bssid +
                              " (" + String(dc.count) + " frames/5s)", bssid);
                    _addLog("DEAUTH_ATTACK", "Deauth flood from " + bssid, bssid);
                    dc.count = 0;
                }
            }
            return;
        }
    }
    DeauthCounter dc;
    dc.bssid       = bssid;
    dc.count       = 1;
    dc.windowStart = now;
    _deauthCounters.push_back(dc);
}

void NetMonitor::_checkDeauthAttacks() {
    // Real HW: enable promiscuous mode and count deauth frames
    // esp_wifi_set_promiscuous(true) + esp_wifi_set_promiscuous_rx_cb(callback)
    // Handled via recordDeauthFrame() called from promiscuous callback
}

// ── Rogue / Fake AP detection ─────────────────────────────────
void NetMonitor::_checkRogueAPs() {
    if (!_cfg.alertRogueAP) return;
    // Already done in _doWifiScan()
}

// ── Brute force detection ─────────────────────────────────────
void NetMonitor::recordLoginAttempt(const String& ip, bool failed) {
    if (!failed) { _bruteForceMap.erase(ip); return; }
    uint32_t now = millis();
    auto& entry = _bruteForceMap[ip];
    if (entry.ip.isEmpty()) {
        entry.ip          = ip;
        entry.attempts    = 1;
        entry.windowStart = now;
        entry.alerted     = false;
        return;
    }
    if (now - entry.windowStart > 30000) {
        entry.attempts    = 1;
        entry.windowStart = now;
        entry.alerted     = false;
    } else {
        entry.attempts++;
        if (entry.attempts >= BRUTE_FORCE_THRESHOLD && !entry.alerted) {
            entry.alerted = true;
            _addAlert(AlertType::BRUTE_FORCE, AlertSeverity::CRITICAL,
                      "Brute force attack from " + ip +
                      " (" + String(entry.attempts) + " attempts/30s)", ip);
            _addLog("BRUTE_FORCE", "Brute force: " + ip, ip);
        }
    }
}

void NetMonitor::_checkBruteForce() {} // Handled via recordLoginAttempt()

// ── Unusual activity ──────────────────────────────────────────
void NetMonitor::_checkUnusualActivity() {
    // Check time-based unusual activity (e.g. new connection at 3am)
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) return;
    int hour = timeinfo.tm_hour;
    bool oddHours = (hour >= 0 && hour <= 5);

    for (const auto& d : _devices) {
        if (d.isNew && oddHours) {
            _addAlert(AlertType::UNUSUAL_ACTIVITY, AlertSeverity::WARNING,
                      "New device at unusual hour (" + String(hour) +
                      ":00): " + d.ip + " " + d.vendor, d.mac);
        }
    }
}

// ── Port scan ─────────────────────────────────────────────────
void NetMonitor::startPortScan(const String& ip) {
    _portScanTarget  = ip;
    _portScanCurrent = 0;
    _portScanning    = true;
    _portResults.clear();
    _portScanTimer   = millis();
    _addLog("PORT_SCAN", "Port scan started on " + ip);
    Serial.printf("[NetMon] Port scan started: %s\n", ip.c_str());
}

void NetMonitor::_tickPortScan() {
    if (_portScanCurrent >= SCAN_PORT_COUNT) {
        _portScanning = false;
        String msg = "Port scan complete on " + _portScanTarget +
                     ": " + String(_portResults.size()) + " open ports";
        _addAlert(AlertType::PORT_SCAN_RESULT, AlertSeverity::INFO, msg, _portScanTarget);
        _addLog("PORT_SCAN_DONE", msg, _portScanTarget);
        return;
    }
    if (millis() - _portScanTimer < 80) return;
    _portScanTimer = millis();

    uint16_t port = SCAN_PORTS[_portScanCurrent++];
    // Real HW: WiFiClient connect() with 100ms timeout
    WiFiClient client;
    client.setTimeout(100);
    bool open = client.connect(_portScanTarget.c_str(), port);
    client.stop();

    if (open) {
        PortScanResult r;
        r.ip      = _portScanTarget;
        r.port    = port;
        r.service = _portService(port);
        r.risk    = _portRisk(port);
        _portResults.push_back(r);
        Serial.printf("[NetMon] Open port %u (%s) risk=%s\n",
                      port, r.service.c_str(), r.risk.c_str());
    }
}

// ── Alert management ──────────────────────────────────────────
void NetMonitor::_addAlert(AlertType type, AlertSeverity sev,
                           const String& msg, const String& src) {
    if (_alerts.size() >= NET_MON_MAX_ALERTS) _alerts.erase(_alerts.begin());
    NetAlert a;
    a.id        = _alertIdCounter++;
    a.type      = type;
    a.severity  = sev;
    a.message   = msg;
    a.source    = src;
    a.timestamp = millis() / 1000;
    a.read      = false;
    _alerts.push_back(a);
    Serial.printf("[NetMon] ALERT [%s]: %s\n",
                  sev == AlertSeverity::CRITICAL ? "CRIT" :
                  sev == AlertSeverity::WARNING  ? "WARN" : "INFO",
                  msg.c_str());
}

void NetMonitor::_addLog(const String& event, const String& detail, const String& mac) {
    if (_log.size() >= NET_MON_MAX_LOG) _log.erase(_log.begin());
    NetLogEntry e;
    e.timestamp = millis() / 1000;
    e.event     = event;
    e.detail    = detail;
    e.mac       = mac;
    _log.push_back(e);
}

bool NetMonitor::markAlertRead(uint32_t id) {
    for (auto& a : _alerts) {
        if (a.id == id) { a.read = true; return true; }
    }
    return false;
}

void NetMonitor::clearAlerts() { _alerts.clear(); }
void NetMonitor::clearLog()    { _log.clear(); }

int NetMonitor::unreadCount() const {
    int c = 0;
    for (const auto& a : _alerts) if (!a.read) c++;
    return c;
}

// ── Device control ────────────────────────────────────────────
bool NetMonitor::blockDevice(const String& mac, bool block) {
    for (auto& d : _devices) {
        if (d.mac == mac) {
            d.blocked = block;
            _saveDevices();
            String msg = String(block ? "Blocked" : "Unblocked") + " device: " + d.ip;
            _addAlert(AlertType::ACCESS_BLOCKED, AlertSeverity::INFO, msg, mac);
            _addLog(block ? "BLOCKED" : "UNBLOCKED", msg, mac);

            // Actually disconnect the device from AP using esp_wifi_deauth_sta
            if (block) {
                // Parse MAC string XX:XX:XX:XX:XX:XX into bytes
                uint8_t macBytes[6] = {0};
                int idx = 0;
                String m = mac;
                m.toUpperCase();
                for (int i = 0; i < (int)m.length() && idx < 6; i++) {
                    char c = m[i];
                    if (c == ':') continue;
                    uint8_t nibble = (c >= 'A') ? (c - 'A' + 10) : (c - '0');
                    if (i % 3 == 0 || (i > 0 && m[i-1] == ':'))
                        macBytes[idx] = nibble << 4;
                    else {
                        macBytes[idx] |= nibble;
                        idx++;
                    }
                }
                // Deauth station from AP (reason 2 = previous auth not valid)
                esp_wifi_deauth_sta(0xFF);  // 0xFF = all stations with this MAC
                // Use softAPdisconnect for the specific MAC via station list
                wifi_sta_list_t staList;
                if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK) {
                    for (int i = 0; i < staList.num; i++) {
                        if (memcmp(staList.sta[i].mac, macBytes, 6) == 0) {
                            esp_wifi_deauth_sta(i);
                            Serial.printf("[NETMON] Deauthed station %s\n", mac.c_str());
                            break;
                        }
                    }
                }
            }
            return true;
        }
    }
    return false;
}

bool NetMonitor::setAccessControl(const String& mac, bool blocked) {
    return blockDevice(mac, blocked);
}

void NetMonitor::updateBandwidth(const String& mac, uint32_t tx, uint32_t rx) {
    for (auto& d : _devices) {
        if (d.mac == mac) {
            d.txBytes     += tx;
            d.rxBytes     += rx;
            d.dailyBytes  += tx + rx;
            d.monthlyBytes+= tx + rx;
            if (_cfg.bandwidthLimitMB > 0 &&
                d.dailyBytes > _cfg.bandwidthLimitMB * 1024 * 1024) {
                _addAlert(AlertType::BANDWIDTH_LIMIT, AlertSeverity::WARNING,
                          "Bandwidth limit exceeded: " + d.ip +
                          " daily=" + String(d.dailyBytes / (1024*1024)) + "MB", mac);
            }
            return;
        }
    }
}

// ── JSON serialization ─────────────────────────────────────────
static const char* severityStr(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::CRITICAL: return "CRITICAL";
        case AlertSeverity::WARNING:  return "WARNING";
        default:                      return "INFO";
    }
}
static const char* alertTypeStr(AlertType t) {
    switch (t) {
        case AlertType::NEW_DEVICE:       return "NEW_DEVICE";
        case AlertType::DEVICE_OFFLINE:   return "DEVICE_OFFLINE";
        case AlertType::TRAFFIC_SPIKE:    return "TRAFFIC_SPIKE";
        case AlertType::FLOOD_DETECTED:   return "FLOOD";
        case AlertType::DDOS_DETECTED:    return "DDOS";
        case AlertType::BRUTE_FORCE:      return "BRUTE_FORCE";
        case AlertType::DEAUTH_ATTACK:    return "DEAUTH";
        case AlertType::ROGUE_AP:         return "ROGUE_AP";
        case AlertType::SSID_SPOOF:       return "SSID_SPOOF";
        case AlertType::PORT_SCAN_RESULT: return "PORT_SCAN";
        case AlertType::UNUSUAL_ACTIVITY: return "UNUSUAL";
        case AlertType::BANDWIDTH_LIMIT:  return "BW_LIMIT";
        case AlertType::ACCESS_BLOCKED:   return "ACCESS_CTRL";
        default:                          return "INFO";
    }
}

String NetMonitor::devicesJson() const {
    String out = "{\"devices\":[";
    bool first = true;
    for (const auto& d : _devices) {
        if (!first) out += ",";
        first = false;
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"mac\":\"%s\",\"ip\":\"%s\",\"hostname\":\"%s\","
            "\"vendor\":\"%s\",\"rssi\":%d,\"online\":%s,\"blocked\":%s,"
            "\"firstSeen\":%u,\"lastSeen\":%u,"
            "\"txKB\":%u,\"rxKB\":%u,\"dailyMB\":%u,\"monthlyMB\":%u,"
            "\"isNew\":%s}",
            d.mac.c_str(), d.ip.c_str(), d.hostname.c_str(),
            d.vendor.c_str(), d.rssi,
            d.online ? "true" : "false",
            d.blocked ? "true" : "false",
            d.firstSeen, d.lastSeen,
            d.txBytes / 1024, d.rxBytes / 1024,
            d.dailyBytes / (1024*1024), d.monthlyBytes / (1024*1024),
            d.isNew ? "true" : "false");
        out += String(buf);
    }
    out += "],\"total\":" + String(_devices.size()) +
           ",\"online\":" + String([&]{ int c=0; for(auto&d:_devices) if(d.online) c++; return c; }()) +
           ",\"scanCount\":" + String(_scanCount) + "}";
    return out;
}

String NetMonitor::alertsJson() const {
    String out = "{\"alerts\":[";
    bool first = true;
    // Return most recent first
    for (int i = (int)_alerts.size()-1; i >= 0; i--) {
        const auto& a = _alerts[i];
        if (!first) out += ",";
        first = false;
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"id\":%u,\"type\":\"%s\",\"severity\":\"%s\","
            "\"message\":\"%s\",\"source\":\"%s\","
            "\"timestamp\":%u,\"read\":%s}",
            a.id, alertTypeStr(a.type), severityStr(a.severity),
            a.message.c_str(), a.source.c_str(),
            a.timestamp, a.read ? "true" : "false");
        out += String(buf);
    }
    out += "],\"unread\":" + String(unreadCount()) + "}";
    return out;
}

String NetMonitor::alertsJsonNew() const {
    String out = "{\"alerts\":[";
    bool first = true;
    for (int i = (int)_alerts.size()-1; i >= 0; i--) {
        const auto& a = _alerts[i];
        if (a.read) continue;
        if (!first) out += ",";
        first = false;
        char buf[384];
        snprintf(buf, sizeof(buf),
            "{\"id\":%u,\"type\":\"%s\",\"severity\":\"%s\","
            "\"message\":\"%s\",\"timestamp\":%u}",
            a.id, alertTypeStr(a.type), severityStr(a.severity),
            a.message.c_str(), a.timestamp);
        out += String(buf);
    }
    out += "],\"unread\":" + String(unreadCount()) + "}";
    return out;
}

String NetMonitor::logJson() const {
    String out = "{\"log\":[";
    bool first = true;
    for (int i = (int)_log.size()-1; i >= 0; i--) {
        const auto& e = _log[i];
        if (!first) out += ",";
        first = false;
        char buf[384];
        snprintf(buf, sizeof(buf),
            "{\"ts\":%u,\"event\":\"%s\",\"detail\":\"%s\",\"mac\":\"%s\"}",
            e.timestamp, e.event.c_str(), e.detail.c_str(), e.mac.c_str());
        out += String(buf);
    }
    out += "]}";
    return out;
}

String NetMonitor::portScanResultsJson() const {
    String out = "{\"scanning\":" + String(_portScanning ? "true" : "false") +
                 ",\"target\":\"" + _portScanTarget + "\"" +
                 ",\"results\":[";
    bool first = true;
    for (const auto& r : _portResults) {
        if (!first) out += ",";
        first = false;
        char buf[128];
        snprintf(buf, sizeof(buf),
            "{\"port\":%u,\"service\":\"%s\",\"risk\":\"%s\"}",
            r.port, r.service.c_str(), r.risk.c_str());
        out += String(buf);
    }
    out += "]}";
    return out;
}

String NetMonitor::statsJson() const {
    int online = 0;
    uint32_t totalTx = 0, totalRx = 0;
    String topUser = "";
    uint32_t topBytes = 0;
    for (const auto& d : _devices) {
        if (d.online) online++;
        totalTx += d.txBytes;
        totalRx += d.rxBytes;
        if (d.dailyBytes > topBytes) { topBytes = d.dailyBytes; topUser = d.ip; }
    }
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"totalDevices\":%u,\"onlineDevices\":%d,"
        "\"totalTxKB\":%u,\"totalRxKB\":%u,"
        "\"topUser\":\"%s\",\"topUserMB\":%u,"
        "\"alerts\":%u,\"unreadAlerts\":%d,"
        "\"scanCount\":%u}",
        (unsigned)_devices.size(), online,
        totalTx/1024, totalRx/1024,
        topUser.c_str(), topBytes/(1024*1024),
        (unsigned)_alerts.size(), unreadCount(),
        _scanCount);
    return String(buf);
}

String NetMonitor::configJson() const {
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"enabled\":%s,\"autoScan\":%s,\"scanIntervalMs\":%u,"
        "\"alertNewDevices\":%s,\"alertTrafficSpike\":%s,"
        "\"alertDeauth\":%s,\"alertRogueAP\":%s,\"alertBruteForce\":%s,"
        "\"bandwidthLimitMB\":%u,\"parentalControl\":%s}",
        _cfg.enabled ? "true":"false",
        _cfg.autoScan ? "true":"false",
        _cfg.scanIntervalMs,
        _cfg.alertNewDevices ? "true":"false",
        _cfg.alertTrafficSpike ? "true":"false",
        _cfg.alertDeauth ? "true":"false",
        _cfg.alertRogueAP ? "true":"false",
        _cfg.alertBruteForce ? "true":"false",
        _cfg.bandwidthLimitMB,
        _cfg.parentalControl ? "true":"false");
    return String(buf);
}

// ── Persistence ───────────────────────────────────────────────
void NetMonitor::_loadDevices() {
    _devices.clear();
    if (!LittleFS.exists(NET_MON_DEVICES_FILE)) return;
    File f = LittleFS.open(NET_MON_DEVICES_FILE, "r");
    if (!f) return;
    JsonDocument doc;
    if (deserializeJson(doc, f)) { f.close(); return; }
    f.close();
    for (JsonObject o : doc["devices"].as<JsonArray>()) {
        NetDevice d;
        d.mac          = o["mac"]      | "";
        d.ip           = o["ip"]       | "";
        d.hostname     = o["hostname"] | "";
        d.vendor       = o["vendor"]   | "";
        d.firstSeen    = o["firstSeen"]| 0u;
        d.lastSeen     = o["lastSeen"] | 0u;
        d.monthlyBytes = o["monthly"]  | 0u;
        d.blocked      = o["blocked"]  | false;
        d.online       = false;  // assume offline on restart
        _devices.push_back(d);
    }
}

void NetMonitor::_saveDevices() const {
    File f = LittleFS.open(NET_MON_DEVICES_FILE, "w");
    if (!f) return;
    f.print("{\"devices\":[");
    bool first = true;
    for (const auto& d : _devices) {
        if (!first) f.print(",");
        first = false;
        char buf[384];
        snprintf(buf, sizeof(buf),
            "{\"mac\":\"%s\",\"ip\":\"%s\",\"hostname\":\"%s\","
            "\"vendor\":\"%s\",\"firstSeen\":%u,\"lastSeen\":%u,"
            "\"monthly\":%u,\"blocked\":%s}",
            d.mac.c_str(), d.ip.c_str(), d.hostname.c_str(),
            d.vendor.c_str(), d.firstSeen, d.lastSeen,
            d.monthlyBytes, d.blocked ? "true" : "false");
        f.print(buf);
    }
    f.print("]}");
    f.close();
}

void NetMonitor::saveConfig(const NetMonConfig& cfg) {
    _cfg = cfg;
    File f = LittleFS.open(NET_MON_CFG_FILE, "w");
    if (!f) return;
    JsonDocument doc;
    doc["enabled"]           = cfg.enabled;
    doc["autoScan"]          = cfg.autoScan;
    doc["scanIntervalMs"]    = cfg.scanIntervalMs;
    doc["alertNewDevices"]   = cfg.alertNewDevices;
    doc["alertTrafficSpike"] = cfg.alertTrafficSpike;
    doc["alertDeauth"]       = cfg.alertDeauth;
    doc["alertRogueAP"]      = cfg.alertRogueAP;
    doc["alertBruteForce"]   = cfg.alertBruteForce;
    doc["bandwidthLimitMB"]  = cfg.bandwidthLimitMB;
    doc["parentalControl"]   = cfg.parentalControl;
    doc["parentalFrom"]      = cfg.parentalBlockFrom;
    doc["parentalTo"]        = cfg.parentalBlockTo;
    serializeJson(doc, f);
    f.close();
}

NetMonConfig NetMonitor::loadConfig() const {
    NetMonConfig cfg;
    if (!LittleFS.exists(NET_MON_CFG_FILE)) return cfg;
    File f = LittleFS.open(NET_MON_CFG_FILE, "r");
    if (!f) return cfg;
    JsonDocument doc;
    if (!deserializeJson(doc, f)) {
        cfg.enabled           = doc["enabled"]           | true;
        cfg.autoScan          = doc["autoScan"]          | true;
        cfg.scanIntervalMs    = doc["scanIntervalMs"]    | (uint32_t)NET_MON_SCAN_INTERVAL_MS;
        cfg.alertNewDevices   = doc["alertNewDevices"]   | true;
        cfg.alertTrafficSpike = doc["alertTrafficSpike"] | true;
        cfg.alertDeauth       = doc["alertDeauth"]       | true;
        cfg.alertRogueAP      = doc["alertRogueAP"]      | true;
        cfg.alertBruteForce   = doc["alertBruteForce"]   | true;
        cfg.bandwidthLimitMB  = doc["bandwidthLimitMB"]  | 0u;
        cfg.parentalControl   = doc["parentalControl"]   | false;
        cfg.parentalBlockFrom = doc["parentalFrom"]      | "22:00";
        cfg.parentalBlockTo   = doc["parentalTo"]        | "07:00";
    }
    f.close();
    return cfg;
}
// ─────────────────────────────────────────────────────────────
//  deviceJson — return JSON object for a single device by MAC
String NetMonitor::deviceJson(const String& mac) const {
    for (const auto& d : _devices) {
        if (d.mac.equalsIgnoreCase(mac)) {
            JsonDocument doc;
            doc["mac"]          = d.mac;
            doc["ip"]           = d.ip;
            doc["hostname"]     = d.hostname;
            doc["vendor"]       = d.vendor;
            doc["rssi"]         = d.rssi;
            doc["online"]       = d.online;
            doc["blocked"]      = d.blocked;
            doc["firstSeen"]    = d.firstSeen;
            doc["lastSeen"]     = d.lastSeen;
            doc["txBytes"]      = d.txBytes;
            doc["rxBytes"]      = d.rxBytes;
            doc["packetCount"]  = d.packetCount;
            doc["isNew"]        = d.isNew;
            String out; serializeJson(doc, out);
            return out;
        }
    }
    return "{}";
}

// ─────────────────────────────────────────────────────────────
//  _markDeviceOffline — mark device as offline by MAC
bool NetMonitor::_markDeviceOffline(const String& mac) {
    for (auto& d : _devices) {
        if (d.mac.equalsIgnoreCase(mac)) {
            if (d.online) {
                d.online  = false;
                d.lastSeen = millis();
                _addAlert(AlertType::DEVICE_OFFLINE, AlertSeverity::INFO,
                          "Device offline: " + d.ip + " " + d.hostname, d.mac);
                Serial.printf("[NetMon] Device offline: %s %s\n",
                              d.mac.c_str(), d.ip.c_str());
                return true;
            }
            return false;
        }
    }
    return false;
}


