# MeshWatch — M5Burner listing

Everything needed to publish MeshWatch in M5Burner. Two routes:

- **A. In-app Publish** (fastest — appears in your account, shareable by code)
- **B. Catalog pull request** (appears in M5Burner's public store for everyone)

The cover is [`cover.png`](cover.png) (1280×720). The flashable image is
[`firmware/meshwatch_0x0.bin`](firmware/meshwatch_0x0.bin) — a full 8 MB image
that burns at offset `0x0`.

---

## A. Publish from inside M5Burner

1. Log in with your M5Stack community account (top of M5Burner).
2. Bottom-left → **USER CUSTOM** → **Publish**.
3. Fill the form with the values below, attach the cover and the firmware, then **Upload**.
4. Use **Detail** to edit later, **Publish** to toggle public, **Share** to get a share code.

| Field | Value |
|---|---|
| **Name** | `MeshWatch` |
| **Version** | `1.4.0` |
| **Device Type** | `M5StickS3` |
| **Github link** | `https://github.com/Korrie71/meshwatch` |
| **Firmware** | `m5burner/firmware/meshwatch_0x0.bin` (flash offset `0x0`) |
| **Cover** | `m5burner/cover.png` |
| **Description** | paste the block below |

### Description (paste into the form)

```
MeshWatch turns an M5Stack StickS3 into a passive counter-surveillance scanner
and an off-grid MeshCore messenger — no phone required.

It listens on WiFi and BLE (it never transmits at the devices it detects) and
flags, with a confidence score, sound and an on-screen banner:

• Flock Safety ALPR cameras, Penguin battery packs and Raven gunshot sensors
• Axon body cameras / Tasers and other law-enforcement gear
• Item trackers — AirTag / Find My, Tile, Samsung SmartTag, Chipolo, Google FMD
  (warns when one has been following you)
• Consumer & CCTV WiFi cameras — Ring, Wyze, Reolink, Hikvision, Dahua, Arlo…
• Drones broadcasting Remote ID (WiFi and BLE)
• Rogue access points (karma / Pineapple-style SSID floods)
• Attack tools — Flipper Zero (incl. BadKB), BLE advertisement spam, Pwnagotchi
• Card-skimmer Bluetooth modules, WiFi deauth floods, iBeacon / Eddystone
• MeshCore and Meshtastic radios

Messaging & field tools
• Pair a MeshCore companion radio over Bluetooth and read/send mesh messages
  right from the stick — channels and contacts, with preset quick-replies.
• Signal finder with a CLOSER/FARTHER direction cue to walk a device down.
• Baseline watch: learn a safe area, then alert on anything new.
• Evidence log saved to flash (survives reboot), optionally geotagged.
• Stealth mode, auto-report to the mesh, team alerts, and a device lock with a
  duress wipe code.

Controls: two buttons. A = select, B = next, hold B = next screen / back.

Detection is for passive, defensive use only. An empty screen is not proof that
an area is free of surveillance. Signatures adapted from the flock-you and
nyanBOX projects; camera OUIs from the public IEEE registry.

Source & docs: https://github.com/Korrie71/meshwatch
```

---

## B. Submit to the public M5Burner catalog (pull request)

The catalog route reads [`m5burner.json`](m5burner.json) + the `firmware/`
folder (files named `name_0xADDRESS`). This folder already follows that layout.

1. Fork https://github.com/m5stack/M5Stack-Firmware
2. Add this repo (`https://github.com/Korrie71/meshwatch`) to `firmware-repo.list`.
3. Open a pull request. Review happens only on the first submission.

> Note: M5Stack's reference points the manifest at the repo root. This repo keeps
> the M5Burner files under `m5burner/` so they don't collide with the PlatformIO
> `firmware/` source tree. If the reviewer wants them at the root, move
> `m5burner/m5burner.json` and `m5burner/firmware/` up one level.

---

## Rebuilding the image after code changes

```sh
cd firmware && pio run
B=.pio/build/m5sticks3
BOOT=$(find ~/.platformio/packages/framework-arduinoespressif32 -name boot_app0.bin | head -1)
python -m esptool --chip esp32s3 merge_bin -o ../m5burner/firmware/meshwatch_0x0.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0 $B/bootloader.bin 0x8000 $B/partitions.bin 0xe000 "$BOOT" 0x10000 $B/firmware.bin
```

Then bump `version` in `m5burner.json` and the name in `dist/`.
