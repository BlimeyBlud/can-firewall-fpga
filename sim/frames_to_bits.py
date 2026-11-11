"""Convert CSV frames to stuffed CAN bitstreams + expected parser outputs.

Writes:
  tb/frames.hex    one bit per line (0 or 1), fed to the parser 1 bit/clock
  tb/expected.txt  one line per frame: 20 hex digits = {1'b0, id[10:0], dlc[3:0], data[63:0]}
  tb/params.vh     `define NBITS / NFRAMES for the testbench
"""
import csv
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def to_bits(value, width):
    return [(value >> i) & 1 for i in range(width - 1, -1, -1)]


def crc15(bits):
    crc = 0
    for b in bits:
        top = (crc >> 14) & 1
        crc = (crc << 1) & 0x7FFF
        if top ^ b:
            crc ^= 0x4599
    return crc


def stuff(bits):
    """After 5 identical bits insert the opposite bit (stuff bit starts the next run)."""
    out, run, last = [], 0, None
    for b in bits:
        out.append(b)
        if b == last:
            run += 1
        else:
            run, last = 1, b
        if run == 5:
            s = 1 - b
            out.append(s)
            last, run = s, 1
    return out


def frame_bits(cid, dlc, data_hex):
    data = bytes.fromhex(data_hex) if data_hex else b""
    assert len(data) == dlc
    body = [0] + to_bits(cid, 11) + [0, 0, 0] + to_bits(dlc, 4)  # SOF, ID, RTR, IDE, r0, DLC
    for byte in data:
        body += to_bits(byte, 8)
    body += to_bits(crc15(body), 15)
    tail = [1, 0, 1] + [1] * 7 + [1] * 3  # CRC delim, ACK(dominant), ACK delim, EOF, IFS
    return stuff(body) + tail


def main():
    with open(os.path.join(ROOT, "data", "traffic.csv"), newline="") as f:
        rows = list(csv.DictReader(f))
    # 80 first frames (mostly normal) + 20 fuzz frames (odd IDs/lengths)
    chosen = rows[:80] + [r for r in rows if r["label"] == "3"][:20]

    bits = [1] * 20  # idle bus at start
    expected = []
    for r in chosen:
        cid = int(r["id"], 16)
        dlc = int(r["dlc"])
        d = r["data"]
        bits += frame_bits(cid, dlc, d) + [1, 1]
        data64 = int(d.ljust(16, "0"), 16)  # first byte in the top bits
        expected.append(f"{cid:03X}{dlc:X}{data64:016X}")
    bits += [1] * 20

    tb = os.path.join(ROOT, "tb")
    os.makedirs(tb, exist_ok=True)
    with open(os.path.join(tb, "frames.hex"), "w", newline="\n") as f:
        f.write("\n".join(str(b) for b in bits) + "\n")
    with open(os.path.join(tb, "expected.txt"), "w", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    with open(os.path.join(tb, "params.vh"), "w", newline="\n") as f:
        f.write(f"`define NBITS {len(bits)}\n`define NFRAMES {len(chosen)}\n")
    print(f"{len(chosen)} frames, {len(bits)} bits written to tb/")


if __name__ == "__main__":
    main()