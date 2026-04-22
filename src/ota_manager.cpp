// ============================================================
//  ota_manager.cpp
// ============================================================
#include "ota_manager.h"
#include "ir_receiver.h"   // to pause IR ISR during flash writes
#include <LittleFS.h>

OtaManager otaMgr;

OtaManager::OtaManager()
    : _updating       (false),
      _restartPending (false),
      _lastPct        (255),     // 255 = "never sent yet"
      _lastChunkMs    (0),
      _totalReceived  (0)
{}

// ── handleUploadChunk ─────────────────────────────────────────
void OtaManager::handleUploadChunk(const String& target,
                                    uint8_t*      data,
                                    size_t        len,
                                    size_t        index,
                                    bool          final)
{
    // First chunk: initialise — guard against concurrent uploads
    if (index == 0) {
        if (_updating) {
            // If a new upload starts while one is in progress, the previous
            // upload connection was likely dropped. Abort the stale one cleanly
            // so the new upload can proceed.
            Serial.println(DEBUG_TAG " OTA: new upload started — aborting stale in-progress update");
            abortUpdate("Upload restarted (connection was interrupted)");
        }
        beginUpdate(target);
        if (!_updating) return;   // beginUpdate() failed
        _lastChunkMs = millis();  // start chunk watchdog
        _totalReceived = 0;
    }

    if (!_updating) return;       // an earlier chunk failed

    // Stale-index guard: if index is non-zero but we just restarted
    // (index == 0 path above), this chunk belongs to a ghost connection.
    // Update.write() will catch bad data anyway, but let's be explicit.
    if (index != _totalReceived) {
        // Non-contiguous chunk — partial upload / connection restart.
        // This can happen if the browser retries with a new request but
        // ESPAsyncWebServer delivers old buffered chunks after a reset.
        Serial.printf(DEBUG_TAG " OTA: non-contiguous chunk (expected %u, got %u) — aborting\n",
                      (unsigned)_totalReceived, (unsigned)index);
        abortUpdate("Upload interrupted — non-contiguous chunk received");
        return;
    }

    // Write to flash
    if (Update.write(data, len) != len) {
        abortUpdate(String("Write error: ") + Update.errorString());
        return;
    }
    _totalReceived += len;
    _lastChunkMs = millis();  // update watchdog timestamp

    // Progress – throttled to integer-percent steps to limit WS traffic.
    // We don't know the exact total file size (UPDATE_SIZE_UNKNOWN was passed
    // to Update.begin), but Update.progress() / Update.size() gives us the
    // bytes written and the space allocated so far.
    if (_progressCb) {
        size_t written = Update.progress();
        size_t total   = Update.size();   // partition size, not file size
        if (total > 0) {
            uint8_t pct = static_cast<uint8_t>((written * 100UL) / total);
            if (pct != _lastPct) {
                _lastPct = pct;
                _progressCb(written, total);
            }
        }
    }

    // Last chunk
    if (final) {
        finishUpdate();
    }
}

// ── beginUpdate ───────────────────────────────────────────────
void OtaManager::beginUpdate(const String& target) {
    _updating       = true;
    _restartPending = false;
    _lastError      = "";
    _lastPct        = 255;
    _lastChunkMs    = millis();
    _totalReceived  = 0;

    // Pause IR ISR — Update.write() does SPI flash operations;
    // keeping the IR ISR active is safe (different peripherals) but
    // pausing avoids any spurious callbacks during the critical window.
    irReceiver.pause();

    // Validate target FIRST — before any side effects (LittleFS.end, etc.)
    if (target != "firmware" && target != "filesystem") {
        abortUpdate(String("Unknown OTA target: ") + target);
        return;
    }

    int updateType;
    if (target == "filesystem") {
        updateType = U_SPIFFS;
        // MUST unmount LittleFS before writing to its partition
        LittleFS.end();
        Serial.println(DEBUG_TAG " OTA: LittleFS unmounted for filesystem update");
    } else {
        updateType = U_FLASH;
    }

    Serial.printf(DEBUG_TAG " OTA: starting %s update\n",
                  target == "filesystem" ? "filesystem" : "firmware");

    // UPDATE_SIZE_UNKNOWN: Update library sizes the partition itself,
    // avoiding any mismatch with multipart content-length.
    if (!Update.begin(UPDATE_SIZE_UNKNOWN, updateType)) {
        abortUpdate(String("begin() failed: ") + Update.errorString());
        return;
    }

    Serial.println(DEBUG_TAG " OTA: update started — receiving data");
}

// ── finishUpdate ──────────────────────────────────────────────
void OtaManager::finishUpdate() {
    if (!Update.end(true)) {   // true = commit boot partition
        abortUpdate(String("end() failed: ") + Update.errorString());
        return;
    }

    _updating       = false;
    _restartPending = true;    // main loop() will restart after delay

    Serial.println(DEBUG_TAG " OTA: image accepted — reboot pending");

    if (_endCb) _endCb(true, "Update successful — rebooting in 1s");
    // NOTE: ESP.restart() is intentionally NOT called here.
    // main.cpp loop() polls restartPending() and restarts after allowing
    // the HTTP response and WS message to be fully transmitted.
}

// ── abortUpdate ───────────────────────────────────────────────
void OtaManager::abortUpdate(const String& reason) {
    Update.abort();
    _updating  = false;
    _lastError = reason;
    Serial.printf(DEBUG_TAG " OTA ERROR: %s\n", reason.c_str());

    // Resume IR receiver on failure (on success we reboot so no need)
    irReceiver.resume();

    // If the filesystem partition was unmounted for the update,
    // re-mount it so IR database and config saves keep working.
    if (!LittleFS.begin(true)) {
        Serial.println(DEBUG_TAG " WARNING: LittleFS re-mount after OTA abort failed");
    }

    if (_endCb) _endCb(false, reason);
}

// ── tickWatchdog ──────────────────────────────────────────────
// Call from main loop(). If an OTA upload is in progress but no
// chunk has arrived for OTA_CHUNK_TIMEOUT_MS, abort the update.
// This prevents the device from being permanently stuck in
// _updating=true state after a dropped network connection.
void OtaManager::tickWatchdog() {
    if (!_updating) return;
    if ((millis() - _lastChunkMs) >= OTA_CHUNK_TIMEOUT_MS) {
        Serial.printf(DEBUG_TAG " OTA: watchdog timeout — no data for %lus, aborting.\n",
                      OTA_CHUNK_TIMEOUT_MS / 1000U);
        abortUpdate("Upload timed out — connection dropped during transfer");
    }
}

// ── clearError ───────────────────────────────────────────────
// Resets the last error so the UI can restart an OTA attempt
// without the user needing to reboot. Safe to call at any time.
void OtaManager::clearError() {
    // Only clear if: (a) not currently updating, AND
    //                (b) a restart is NOT already pending (i.e. OTA success)
    // Clearing after a successful OTA would prevent the device from rebooting.
    if (!_updating && !_restartPending) {
        _lastError = "";
        _lastPct   = 255;
        Serial.println(DEBUG_TAG " OTA: error state cleared — ready for retry");
    }
}
