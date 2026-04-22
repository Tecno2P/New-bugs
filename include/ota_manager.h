#pragma once
// ============================================================
//  ota_manager.h  –  OTA firmware + filesystem update
//
//  Receives a .bin file via multipart HTTP POST upload,
//  writes it to the inactive OTA partition using the ESP32
//  Arduino Update library, then signals main loop to reboot.
//
//  Supported targets
//    "firmware"   → U_FLASH   (application binary)
//    "filesystem" → U_SPIFFS  (LittleFS image)
//
//  Key design decisions
//    • UPDATE_SIZE_UNKNOWN is used so Update.begin() works
//      regardless of multipart content-length inaccuracies.
//    • The "final" flag from ESPAsyncWebServer's upload handler
//      is the authoritative end-of-file signal (not index+len).
//    • ESP.restart() is NOT called inside OtaManager.  Instead
//      a _restartPending flag is set; main loop() polls it and
//      restarts after 1 s, giving the HTTP response and WS
//      message time to be delivered first.
//    • Progress is throttled: WS broadcast only when the
//      integer percentage advances, capping at ~100 messages.
//    • LittleFS is unmounted before a filesystem update to
//      prevent partition corruption.
//    • IR receiver is paused for the duration of the update.
// ============================================================
#include <Arduino.h>
#include <Update.h>
#include <functional>
#include "config.h"

// OTA upload watchdog: abort if no chunk arrives within this window.
// 60 s is generous — a 1 MB file at even 64 kbps takes <15 s on WiFi.
#ifndef OTA_CHUNK_TIMEOUT_MS
  #define OTA_CHUNK_TIMEOUT_MS  60000UL
#endif

using OtaProgressCallback = std::function<void(size_t done, size_t total)>;
using OtaEndCallback      = std::function<void(bool success, const String& msg)>;

class OtaManager {
public:
    OtaManager();

    void onProgress(OtaProgressCallback cb) { _progressCb = cb; }
    void onEnd     (OtaEndCallback      cb) { _endCb      = cb; }

    // Called by the web server upload handler for every incoming chunk.
    //   target    : "firmware" or "filesystem"
    //   data/len  : chunk bytes
    //   index     : byte offset of this chunk within the file
    //   final     : true on the last chunk (set by ESPAsyncWebServer)
    void handleUploadChunk(const String& target,
                           uint8_t*      data,
                           size_t        len,
                           size_t        index,
                           bool          final);

    // True while an update is in progress
    bool isUpdating() const { return _updating; }

    // True after a successful update — main loop() should call restart()
    bool restartPending() const { return _restartPending; }

    // Last error message; empty if no error
    const String& lastError() const { return _lastError; }

    // Call from main loop() every iteration.
    // Aborts stale uploads that lost their TCP connection.
    void tickWatchdog();

    // Clears the last error without rebooting — allows retrying OTA
    // from the UI after a failed upload without a power cycle.
    void clearError();

private:
    OtaProgressCallback _progressCb;
    OtaEndCallback      _endCb;
    volatile bool       _updating;          // written from async task, read from loop()
    volatile bool       _restartPending;   // same — must be volatile
    String              _lastError;
    uint8_t             _lastPct;          // for progress throttle
    unsigned long       _lastChunkMs;      // timestamp of last received chunk (watchdog)
    size_t              _totalReceived;    // bytes received so far (stale-index guard)

    void beginUpdate  (const String& target);
    void finishUpdate ();
    void abortUpdate  (const String& reason);
};

extern OtaManager otaMgr;
