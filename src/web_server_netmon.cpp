// ============================================================
//  web_server_netmon.cpp  –  Network Monitor API routes
//  GET/POST endpoints for all NetMonitor features
// ============================================================
#include "web_server.h"
#include "net_monitor.h"
#include <ArduinoJson.h>

static void _nmSend(AsyncWebServerRequest* req, int code, const String& json) {
    AsyncWebServerResponse* r = req->beginResponse(code, "application/json", json);
    r->addHeader("Access-Control-Allow-Origin", "*");
    req->send(r);
}

static String* _nmBodyBuf(AsyncWebServerRequest* req) {
    if (!req->_tempObject) {
        req->_tempObject = new String();
        req->onDisconnect([req]() {
            if (req->_tempObject) {
                delete reinterpret_cast<String*>(req->_tempObject);
                req->_tempObject = nullptr;
            }
        });
    }
    return reinterpret_cast<String*>(req->_tempObject);
}
static void _nmFreeBody(AsyncWebServerRequest* req) {
    if (req->_tempObject) {
        delete reinterpret_cast<String*>(req->_tempObject);
        req->_tempObject = nullptr;
    }
}

#define NM_POST(path, handler) \
    _server.on(path, HTTP_POST, \
        [](AsyncWebServerRequest* req){}, \
        nullptr, \
        [this](AsyncWebServerRequest* req, uint8_t* d, size_t l, size_t i, size_t t) { \
            if (_nmBodyBuf(req)->length() + l > HTTP_MAX_BODY) { \
                _nmFreeBody(req); \
                _nmSend(req, 413, "{\"error\":\"too large\"}"); return; \
            } \
            _nmBodyBuf(req)->concat((char*)d, l); \
            bool last = (t > 0) ? (i + l >= t) : (i == 0); \
            if (last) { \
                String* buf = _nmBodyBuf(req); \
                handler(req, (uint8_t*)buf->c_str(), buf->length()); \
                _nmFreeBody(req); \
            } \
        })

void WebUI::setupNetMonRoutes() {

    // ── Dashboard stats ──────────────────────────────────────
    _server.on("/api/netmon/stats", HTTP_GET, [](AsyncWebServerRequest* req) {
        _nmSend(req, 200, netMonitor.statsJson());
    });

    // ── Devices ──────────────────────────────────────────────
    _server.on("/api/netmon/devices", HTTP_GET, [](AsyncWebServerRequest* req) {
        _nmSend(req, 200, netMonitor.devicesJson());
    });

    _server.on("/api/netmon/scan", HTTP_POST, [](AsyncWebServerRequest* req) {
        netMonitor.triggerManualScan();
        _nmSend(req, 200, "{\"ok\":true,\"message\":\"Scan triggered\"}");
    });

    // ── Block / Unblock device ────────────────────────────────
    NM_POST("/api/netmon/block", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String mac   = doc["mac"]   | "";
        bool   block = doc["block"] | true;
        if (mac.isEmpty()) { _nmSend(req, 400, "{\"error\":\"Missing mac\"}"); return; }
        bool ok = netMonitor.blockDevice(mac, block);
        _nmSend(req, 200, ok ? "{\"ok\":true}" : "{\"error\":\"Device not found\"}");
    });

    // ── Internet access control ───────────────────────────────
    NM_POST("/api/netmon/access", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String mac     = doc["mac"]     | "";
        bool   blocked = doc["blocked"] | false;
        if (mac.isEmpty()) { _nmSend(req, 400, "{\"error\":\"Missing mac\"}"); return; }
        bool ok = netMonitor.setAccessControl(mac, blocked);
        _nmSend(req, 200, ok ? "{\"ok\":true}" : "{\"error\":\"Device not found\"}");
    });

    // ── Bandwidth update (called from router log parser) ──────
    NM_POST("/api/netmon/bandwidth", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String mac = doc["mac"] | "";
        uint32_t tx = doc["tx"] | 0u;
        uint32_t rx = doc["rx"] | 0u;
        netMonitor.updateBandwidth(mac, tx, rx);
        _nmSend(req, 200, "{\"ok\":true}");
    });

    // ── Alerts ───────────────────────────────────────────────
    _server.on("/api/netmon/alerts", HTTP_GET, [](AsyncWebServerRequest* req) {
        bool newOnly = req->hasParam("new") &&
                       req->getParam("new")->value() == "1";
        _nmSend(req, 200, newOnly ? netMonitor.alertsJsonNew()
                                  : netMonitor.alertsJson());
    });

    NM_POST("/api/netmon/alerts/read", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        uint32_t id = doc["id"] | 0u;
        bool all    = doc["all"] | false;
        if (all) {
            // Mark all read - iterate via clear + re-add is easier here
            // Just re-use the clear
            netMonitor.clearAlerts();
        } else {
            netMonitor.markAlertRead(id);
        }
        _nmSend(req, 200, "{\"ok\":true}");
    });

    _server.on("/api/netmon/alerts/clear", HTTP_POST, [](AsyncWebServerRequest* req) {
        netMonitor.clearAlerts();
        _nmSend(req, 200, "{\"ok\":true}");
    });

    // ── Timeline log ──────────────────────────────────────────
    _server.on("/api/netmon/log", HTTP_GET, [](AsyncWebServerRequest* req) {
        _nmSend(req, 200, netMonitor.logJson());
    });

    _server.on("/api/netmon/log/clear", HTTP_POST, [](AsyncWebServerRequest* req) {
        netMonitor.clearLog();
        _nmSend(req, 200, "{\"ok\":true}");
    });

    // ── Port scan ─────────────────────────────────────────────
    NM_POST("/api/netmon/portscan/start", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String ip = doc["ip"] | "";
        if (ip.isEmpty()) { _nmSend(req, 400, "{\"error\":\"Missing ip\"}"); return; }
        netMonitor.startPortScan(ip);
        _nmSend(req, 200, "{\"ok\":true,\"target\":\"" + ip + "\"}");
    });

    _server.on("/api/netmon/portscan/results", HTTP_GET, [](AsyncWebServerRequest* req) {
        _nmSend(req, 200, netMonitor.portScanResultsJson());
    });

    // ── Config ───────────────────────────────────────────────
    _server.on("/api/netmon/config", HTTP_GET, [](AsyncWebServerRequest* req) {
        _nmSend(req, 200, netMonitor.configJson());
    });

    NM_POST("/api/netmon/config", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        NetMonConfig cfg;
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
        netMonitor.saveConfig(cfg);
        _nmSend(req, 200, "{\"ok\":true}");
    });

    // ── Security event injection (from external log parser) ──
    NM_POST("/api/netmon/event/deauth", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String bssid = doc["bssid"] | "";
        if (!bssid.isEmpty()) netMonitor.recordDeauthFrame(bssid);
        _nmSend(req, 200, "{\"ok\":true}");
    });

    NM_POST("/api/netmon/event/login", [](AsyncWebServerRequest* req, uint8_t* d, size_t l) {
        JsonDocument doc; deserializeJson(doc, d, l);
        String ip   = doc["ip"]     | "";
        bool failed = doc["failed"] | true;
        if (!ip.isEmpty()) netMonitor.recordLoginAttempt(ip, failed);
        _nmSend(req, 200, "{\"ok\":true}");
    });
}
