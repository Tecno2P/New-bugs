# IR Remote Web GUI v4.0.0 — Flashing Instructions

## Quick Start

Flash **4 files** in the correct order using `esptool.py`.

### Windows (one command)

```bat
esptool.py --chip esp32 --port COM3 --baud 921600 ^
  write_flash ^
  0x1000   bootloader.bin ^
  0x8000   partitions.bin ^
  0x10000  firmware.bin ^
  0x390000 littlefs.bin
```

### macOS / Linux

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 \
  write_flash \
  0x1000   bootloader.bin \
  0x8000   partitions.bin \
  0x10000  firmware.bin \
  0x390000 littlefs.bin
```

> Replace `COM3` / `/dev/ttyUSB0` with your actual port.

---

## Flash Map (4MB ESP32)

| File             | Address    | Description                              |
|------------------|------------|------------------------------------------|
| `bootloader.bin` | `0x1000`   | ESP32 first-stage bootloader             |
| `partitions.bin` | `0x8000`   | Custom partition table                   |
| `firmware.bin`   | `0x10000`  | Application firmware (IR Remote v2.0.0)  |
| `littlefs.bin`   | `0x390000` | Web GUI files + storage (LittleFS)       |

---

## Partition Layout

```
Name       Type   SubType   Offset     Size
nvs        data   nvs       0x9000     24KB
otadata    data   ota       0xf000     8KB
ota_0      app    ota_0     0x10000    1.6MB   ← main firmware slot
ota_1      app    ota_1     0x1A0000   1.6MB   ← OTA update slot
spiffs     data   spiffs    0x390000   1.25MB  ← LittleFS (Web GUI + data)
```

---

## Building from Source (PlatformIO)

### Prerequisites

- [PlatformIO Core](https://platformio.org/install/cli) or PlatformIO IDE (VSCode extension)
- Python 3.8+
- USB driver for CP2102 / CH340 chip on your ESP32 board

### Build & Flash Steps

```bash
# Clone or extract the project
cd ir_remote_v2

# Build firmware only
pio run -e esp32dev

# Build filesystem (LittleFS) image only
pio run -e esp32dev -t buildfs

# Upload firmware via USB
pio run -e esp32dev -t upload

# Upload filesystem via USB (MUST be done separately!)
pio run -e esp32dev -t uploadfs

# Monitor serial output
pio device monitor --baud 115200
```

> **Important:** The filesystem (`uploadfs`) must be flashed at least once.
> The firmware will start, but the Web GUI will be missing until `littlefs.bin` is flashed.

---

## OTA (Over-The-Air) Update

Once the device is running, you can update firmware or filesystem wirelessly:

1. Connect to the `IR-Remote` Wi-Fi network (password: `irremote123`)
2. Open `http://192.168.4.1` in your browser
3. Go to **Settings → OTA Firmware Update**
4. Select target: `Firmware` or `Filesystem / LittleFS`
5. Drag & drop the `.bin` file
6. Click **⬆ Flash** and wait for completion

---

## First Boot

1. Power on the ESP32.
2. It creates a Wi-Fi access point:
   - **SSID:** `IR-Remote`
   - **Password:** `irremote123`
   - **URL:** `http://192.168.4.1`
3. Open `http://192.168.4.1` in a browser on any device.

---

## Connecting to Your Router (STA Mode)

AP mode stays active at all times. To also connect to your home router:

1. Open **Settings → Wi-Fi Configuration**
2. Enable **"Connect to Router (STA mode)"**
3. Click **📡 Scan** to find your network, or type the SSID manually
4. Enter your Wi-Fi password
5. Click **💾 Save Config**

The ESP32 will immediately attempt to connect. The AP stays live — you
will not lose access. Once connected, the STA IP appears in:
- **Settings → System Status → STA** field
- Serial monitor: `[IR] STA: connecting to 'MyRouter'…`

---

## Hardware Wiring

| ESP32 GPIO | Component         | Notes                           |
|------------|-------------------|---------------------------------|
| GPIO 14    | TSOP4838 DATA pin | IR Receiver (default)           |
| GPIO 27    | NPN transistor base via 1kΩ | IR Emitter (default) |
| GND        | TSOP4838 GND      | Also NPN emitter                |
| 3.3V       | TSOP4838 VCC      |                                 |

GPIO assignments can be changed live in **Settings → GPIO Pin Configuration**.

---

## v2.0.0 New Features

| Feature                    | Where in UI                          |
|----------------------------|--------------------------------------|
| Button Groups / Presets    | Groups tab + Remote tab              |
| Group tabs on Remote screen| Remote tab → group selector          |
| Per-button repeat count    | Monitor capture card + Edit modal    |
| Per-button repeat delay    | Monitor capture card + Edit modal    |
| Protocol repeat defaults   | "↺ Protocol defaults" button         |
| Scheduled IR transmission  | Scheduler tab                        |
| NTP time sync              | Scheduler tab → NTP section          |
| Timezone configuration     | Scheduler tab → UTC Offset field     |
| Wi-Fi network scanner      | Settings → Router SSID → 📡 Scan    |
| SSID dropdown / datalist   | Settings → Router SSID field         |
| Raw IR waveform SVG viewer | Monitor tab → captured signal card  |
| Waveform zoom slider       | Monitor tab → waveform controls      |
| Hover timing tooltip       | Monitor tab → hover over pulses      |
| System Status Dashboard    | Settings tab → System Status section |
| Live heap/uptime/RSSI bar  | Status bar (bottom) + Settings       |
| AP+STA reliable dual-mode  | Wi-Fi stack — always on              |
| Auto STA reconnect         | Background — exponential back-off    |

---

## Troubleshooting

| Symptom                     | Fix                                              |
|-----------------------------|--------------------------------------------------|
| Web GUI shows "FS not flashed" | Flash `littlefs.bin` at `0x390000`           |
| Can't connect to AP         | Check SSID `IR-Remote`, password `irremote123`  |
| STA never connects          | Check SSID/password in Settings; check router band (2.4GHz only) |
| No IR received              | Check TSOP4838 wiring; verify RX GPIO in Settings → GPIO |
| IR TX not working           | Check NPN circuit; verify TX GPIO in Settings → GPIO |
| Scheduler not firing        | Ensure NTP is synced (needs STA + internet); check timezone |
| OTA failed                  | Use stock `firmware.bin` not a debug build; check baud rate |

---

## Serial Debug Output

At 115200 baud you will see:

```
╔══════════════════════════════════════════════╗
║   IR Remote Web GUI   v2.0.0                 ║
╚══════════════════════════════════════════════╝
[IR] LittleFS: total=1280KB  used=116KB
[IR] Groups loaded: 1
[IR] AP up: SSID='IR-Remote' IP=192.168.4.1 ch=1 WPA2
[IR] STA: connecting to 'MyRouter'...
[IR] HTTP server on port 80
[IR] Ready v2.0.0  AP: http://192.168.4.1
[IR] RX=GPIO14  TX-active=1  Groups=1  Schedules=0  Heap=242688
[IR] NTP sync started (tz=0 dst=0)
```
