"""Debug helper: press buttons on the stick over USB and save screenshots.

usage: shot.py OUT_PREFIX STEP [STEP...]   where STEP is a, b, A, B or shot
"""
import glob, struct, sys, time, zlib
import serial


def png(path, w, h, rgb):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    raw = b"".join(b"\x00" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def main():
    prefix, steps = sys.argv[1], sys.argv[2:]
    s = serial.Serial(glob.glob("/dev/cu.usbmodem*")[0], 115200, timeout=2)
    time.sleep(0.5)
    n = 0
    for step in steps:
        s.write((step + "\n").encode())
        if step != "shot":
            time.sleep(0.45)
            continue
        while not s.readline().startswith(b"SHOT"):
            pass
        rgb = bytearray()
        for _ in range(135):
            row = bytes.fromhex(s.readline().strip().decode())
            for i in range(0, 480, 2):
                v = (row[i] << 8) | row[i + 1]
                rgb += bytes(((v >> 11) * 255 // 31, ((v >> 5) & 63) * 255 // 63, (v & 31) * 255 // 31))
        n += 1
        png(f"{prefix}{n}.png", 240, 135, bytes(rgb))
        print("saved", f"{prefix}{n}.png")


main()
