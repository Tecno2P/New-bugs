// ============================================================
//  watchdog_manager.cpp  –  Batch 3: Self-Healing Watchdog
//  FIXED:
//    1. Loop stall detection now actually fires (was tracked but never checked)
//    2. Crash entry ID uses esp_random() instead of millis()=0 at boot
//    3. esp_task_wdt_init IDF4/IDF5 dual compat via #ifdef
//    4. setHwEnabled() saveConfig() skipped during begin() to avoid
//       redundant write (config just loaded)
//    5. _buildTimeStr() now used in _logCrashOnBoot() (was always "uptime:0s")
// ============================================================
#include "watchdog_manager.h"
#include "audit_manager.h"
#include <ctime>

WatchdogManager wdtMgr;

// ─────────────────────────────────────────────────────────────
WatchdogManager::WatchdogManager()
    : _hwEnabled(true), _hwStarted(false),
      _heapThreshold(WDT_HEAP_MIN_BYTES),
      _minHeapSeen(UINT32_MAX),
      _lastLoopMs(0), _lastHeapCheck(0),
      _beginDone(false) {}

// ─────────────────────────────────────────────────────────────
void WatchdogManager::begin() {
    loadConfig();

    // Log crash reason from previous boot
    _logCrashOnBoot();

    // Start hardware watchdog
    // _beginDone=false so setHwEnabled() skips saveConfig() here
    if (_hwEnabled) {
        _startHw();
    }

    _lastLoopMs   = millis();
    _lastHeapCheck = millis();
    _minHeapSeen  = ESP.getFreeHeap();
    _beginDone    = true;

    Serial.printf(WDT_TAG " Started — HW:%s  HeapMin:%u  Modules:%u\n",
                  _hwEnabled ? "ON" : "OFF",
                  _heapThreshold,
                  (unsigned)_modules.size());
}

// ─────────────────────────────────────────────────────────────
void WatchdogManager::loop() {
    unsigned long now = millis();

    // ── FIX 1: Software loop-stall detection ─────────────────
    // WDT_LOOP_MAX_MS is defined in header (10000 ms default).
    // If loop() hasn't been called for longer than this, it means
    // something is blocking (long delay, WiFi connect, OTA, etc.).
    // We only WARN here — a real stall would be caught by the HW WDT.
    if (_lastLoopMs != 0 && (now - _lastLoopMs) > WDT_LOOP_MAX_MS) {
        Serial.printf(WDT_TAG " WARNING: loop() stall detected! Gap=%lums\n",
                      now - _lastLoopMs);
        auditMgr.log(AuditSource::SYSTEM, "LOOP_STALL",
                     String("Gap: ") + (now - _lastLoopMs) + "ms", false);
    }

    // Feed hardware watchdog
    if (_hwEnabled && _hwStarted) {
        esp_task_wdt_reset();
    }

    // Track min heap
    uint32_t heap = ESP.getFreeHeap();
    if (heap < _minHeapSeen) _minHeapSeen = heap;

    // Heap critical alert — every 30s
    if (now - _lastHeapCheck > 30000UL) {
        _lastHeapCheck = now;
        if (heap < _heapThreshold) {
            Serial.printf(WDT_TAG " WARNING: Low heap! Free=%u bytes (threshold=%u)\n",
                          heap, _heapThreshold);
            auditMgr.log(AuditSource::SYSTEM, "HEAP_WARNING",
                         String("Free heap: ") + heap + " bytes", false);
        }
    }

    // Check stalled modules
    for (auto& m : _modules) {
        bool wasStalled = m.stalled;
        m.stalled = m.isStalled();
        if (m.stalled && !wasStalled) {
            Serial.printf(WDT_TAG " WARNING: Module '%s' stalled! No feed for %lums\n",
                          m.name.c_str(), now - m.lastFeedMs);
            auditMgr.log(AuditSource::SYSTEM, "MODULE_STALLED",
                         String("Module: ") + m.name, false);
        }
    }

    _lastLoopMs = now;
}

// ─────────────────────────────────────────────────────────────
void WatchdogManager::hwFeed() {
    if (_hwStarted) esp_task_wdt_reset();
}

// ── FIX 3: IDF4 / IDF5 dual-compatible HW watchdog start ─────
void WatchdogManager::_startHw() {
    if (_hwStarted) return;
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    // IDF 5.x API: esp_task_wdt_init takes a config struct
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms     = WDT_HW_TIMEOUT_S * 1000U,
        .idle_core_mask = 0,
        .trigger_panic  = true
    };
    esp_err_t err = esp_task_wdt_reconfigure(&wdt_config);
    if (err != ESP_OK) err = esp_task_wdt_init(&wdt_config);
#else
    // IDF 4.x API
    esp_err_t err = esp_task_wdt_init(WDT_HW_TIMEOUT_S, true);
#endif
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
        esp_task_wdt_add(NULL);   // watch current task (loop task)
        _hwStarted = true;
        Serial.printf(WDT_TAG " HW watchdog started (%ds timeout)\n",
                      WDT_HW_TIMEOUT_S);
    } else {
        Serial.printf(WDT_TAG " WARNING: HW watchdog init failed: %d\n", err);
    }
}

// ── FIX 4: setHwEnabled skips saveConfig() during begin() ────
void WatchdogManager::setHwEnabled(bool en) {
    _hwEnabled = en;
    if (en && !_hwStarted) {
        _startHw();
    } else if (!en && _hwStarted) {
        esp_task_wdt_delete(NULL);
        _hwStarted = false;
        Serial.println(WDT_TAG " HW watchdog stopped");
    }
    // Only persist after begin() is complete — avoids redundant write
    // right after loadConfig() in begin()
    if (_beginDone) saveConfig();
}

// ─────────────────────────────────────────────────────────────
//  Module health tracking
// ─────────────────────────────────────────────────────────────
uint8_t WatchdogManager::registerModule(const String& name, uint32_t timeoutMs) {
    WdtModuleHealth m;
    m.name      = name;
    m.lastFeedMs= millis();
    m.timeoutMs = timeoutMs;
    m.stalled   = false;
    _modules.push_back(m);
    uint8_t idx = (uint8_t)(_modules.size() - 1);
    Serial.printf(WDT_TAG " Registered module '%s' (idx=%u timeout=%ums)\n",
                  name.c_str(), idx, timeoutMs);
    return idx;
}

void WatchdogManager::feedModule(uint8_t idx) {
    if (idx < _modules.size()) {
        _modules[idx].lastFeedMs = millis();
        _modules[idx].stalled    = false;
    }
}

bool WatchdogManager::isModuleStalled(uint8_t idx) const {
    if (idx >= _modules.size()) return false;
    return _modules[idx].stalled;
}

// ─────────────────────────────────────────────────────────────
//  Status JSON
// ─────────────────────────────────────────────────────────────
String WatchdogManager::statusJson() const {
    JsonDocument doc;
    doc["hwEnabled"]      = _hwEnabled;
    doc["hwStarted"]      = _hwStarted;
    doc["hwTimeoutS"]     = WDT_HW_TIMEOUT_S;
    doc["heapFree"]       = ESP.getFreeHeap();
    doc["heapMin"]        = _minHeapSeen;
    doc["heapThreshold"]  = _heapThreshold;
    doc["heapCritical"]   = isHeapCritical();
    doc["uptimeS"]        = (uint32_t)(millis() / 1000);
    doc["loopStallMaxMs"] = WDT_LOOP_MAX_MS;

    JsonArray mods = doc["modules"].to<JsonArray>();
    for (const auto& m : _modules) {
        JsonObject o = mods.add<JsonObject>();
        o["name"]      = m.name;
        o["stalled"]   = m.stalled;
        o["lastFeedMs"]= (uint32_t)(millis() - m.lastFeedMs);
        o["timeoutMs"] = m.timeoutMs;
    }
    String out; serializeJson(doc, out);
    return out;
}

String WatchdogManager::crashLogJson() const {
    if (!LittleFS.exists(WDT_CRASH_FILE)) {
        return "{\"count\":0,\"crashes\":[]}";
    }
    File f = LittleFS.open(WDT_CRASH_FILE, "r");
    if (!f) return "{\"count\":0,\"crashes\":[]}";
    String content = f.readString();
    f.close();
    return content;
}

// ─────────────────────────────────────────────────────────────
//  Config
// ─────────────────────────────────────────────────────────────
bool WatchdogManager::loadConfig() {
    if (!LittleFS.exists(WDT_CFG_FILE)) return false;
    File f = LittleFS.open(WDT_CFG_FILE, "r");
    if (!f) return false;
    JsonDocument doc;
    if (deserializeJson(doc, f) != DeserializationError::Ok) { f.close(); return false; }
    f.close();
    _hwEnabled      = doc["hwEnabled"]      | true;
    _heapThreshold  = doc["heapThreshold"]  | (uint32_t)WDT_HEAP_MIN_BYTES;
    return true;
}

bool WatchdogManager::saveConfig() {
    File f = LittleFS.open(WDT_CFG_FILE, "w");
    if (!f) return false;
    JsonDocument doc;
    doc["hwEnabled"]     = _hwEnabled;
    doc["heapThreshold"] = _heapThreshold;
    serializeJson(doc, f);
    f.close();
    return true;
}

void WatchdogManager::setHeapThreshold(uint32_t bytes) {
    _heapThreshold = bytes;
    saveConfig();
}

// ─────────────────────────────────────────────────────────────
//  Crash logging
// ─────────────────────────────────────────────────────────────
void WatchdogManager::_logCrashOnBoot() {
    esp_reset_reason_t reason = esp_reset_reason();

    // Only log if it was an unclean reset
    if (reason == ESP_RST_POWERON || reason == ESP_RST_SW) return;

    WdtCrashEntry entry;
    // FIX 2: Use esp_random() for unique ID instead of millis() which is
    // always ~0 at boot, causing all boot-crash entries to have id=0
    entry.id         = esp_random();
    entry.timestamp  = 0;
    // FIX 5: Use _buildTimeStr() — was hardcoded "uptime:0s" even when RTC valid
    entry.timeStr    = _buildTimeStr();
    entry.reason     = _resetReasonStr(reason);
    entry.heapAtCrash= ESP.getFreeHeap();
    entry.uptimeSec  = (uint32_t)(millis() / 1000);

    Serial.printf(WDT_TAG " Previous boot crash detected: %s\n",
                  entry.reason.c_str());

    _saveCrash(entry);
}

void WatchdogManager::_saveCrash(const WdtCrashEntry& entry) {
    // Load existing crashes
    JsonDocument doc;
    if (LittleFS.exists(WDT_CRASH_FILE)) {
        File f = LittleFS.open(WDT_CRASH_FILE, "r");
        if (f) { deserializeJson(doc, f); f.close(); }
    }

    JsonArray arr = doc["crashes"].is<JsonArray>()
                  ? doc["crashes"].as<JsonArray>()
                  : doc["crashes"].to<JsonArray>();

    // Rotate — keep max WDT_MAX_CRASHES
    while (arr.size() >= WDT_MAX_CRASHES) {
        arr.remove(0);
    }

    JsonObject o = arr.add<JsonObject>();
    o["id"]      = entry.id;
    o["ts"]      = entry.timestamp;
    o["time"]    = entry.timeStr;
    o["reason"]  = entry.reason;
    o["heap"]    = entry.heapAtCrash;
    o["uptime"]  = entry.uptimeSec;

    doc["count"] = arr.size();

    File f = LittleFS.open(WDT_CRASH_FILE, "w");
    if (f) { serializeJson(doc, f); f.close(); }
}

String WatchdogManager::_resetReasonStr(esp_reset_reason_t r) const {
    switch (r) {
        case ESP_RST_POWERON:   return "Power-on reset";
        case ESP_RST_EXT:       return "External pin reset";
        case ESP_RST_SW:        return "Software reset";
        case ESP_RST_PANIC:     return "PANIC / Exception";
        case ESP_RST_INT_WDT:   return "Interrupt watchdog";
        case ESP_RST_TASK_WDT:  return "Task watchdog";
        case ESP_RST_WDT:       return "Other watchdog";
        case ESP_RST_DEEPSLEEP: return "Deep sleep wakeup";
        case ESP_RST_BROWNOUT:  return "Brownout (power drop)";
        case ESP_RST_SDIO:      return "SDIO reset";
        default:                return "Unknown reason";
    }
}

String WatchdogManager::_buildTimeStr() const {
    time_t now; time(&now);
    if (now > 1000000000UL) {
        struct tm t; localtime_r(&now, &t);
        char buf[24];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                 t.tm_year+1900, t.tm_mon+1, t.tm_mday,
                 t.tm_hour, t.tm_min, t.tm_sec);
        return String(buf);
    }
    return String("uptime:") + (millis()/1000) + "s";
}
