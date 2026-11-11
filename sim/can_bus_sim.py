"""CAN bus traffic simulator: 5 ECUs, CAN 2.0A, 500 kbit/s, with attacks.

Writes:
  data/traffic_normal.csv  (normal only, for training)
  data/traffic.csv         (normal + spoof + dos + fuzz attacks)
Columns: timestamp,id,dlc,data,label,tx_pos_m
Labels: 0 normal, 1 spoof, 2 dos, 3 fuzz
"""
import csv
import heapq
import os
import random

BIT_T = 1 / 500_000  # seconds per bit at 500 kbit/s
ECUS = [  # (can_id, period_s, dlc, position_m)
    (0x0A0, 0.010, 8, 1.0),
    (0x120, 0.020, 8, 3.0),
    (0x1F0, 0.020, 8, 5.0),
    (0x2B0, 0.100, 4, 7.0),
    (0x3C0, 0.100, 2, 9.0),
]
ATTACKER_POS = 8.0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rand_data(rng, dlc):
    return bytes(rng.randrange(256) for _ in range(dlc)).hex().upper()


def build_events(rng, duration, attacks):
    """Return list of (release_time, id, dlc, data_hex, label, pos_m)."""
    ev = []
    # Normal ECUs: periodic with ~1% timing jitter
    for cid, period, dlc, pos in ECUS:
        t = rng.uniform(0, period)
        while t < duration:
            ev.append((t, cid, dlc, rand_data(rng, dlc), 0, pos))
            t += period + rng.gauss(0, period * 0.01)

    # Spoof: legit ID 0x1F0 sent from 8 m at a wrong rate (every 5 ms)
    if "spoof" in attacks:
        s, e = attacks["spoof"]
        t = s
        while t < e:
            ev.append((t, 0x1F0, 8, rand_data(rng, 8), 1, ATTACKER_POS))
            t += 0.005

    # DoS: ID 0x000 flooded nearly back to back
    if "dos" in attacks:
        s, e = attacks["dos"]
        t = s
        while t < e:
            ev.append((t, 0x000, 8, "00" * 8, 2, ATTACKER_POS))
            t += 0.0002

    # Fuzz: random IDs, random length, random data (~1 ms apart on average)
    if "fuzz" in attacks:
        s, e = attacks["fuzz"]
        t = s
        while t < e:
            dlc = rng.randint(0, 8)
            ev.append((t, rng.randrange(0x800), dlc, rand_data(rng, dlc), 3, ATTACKER_POS))
            t += rng.expovariate(1 / 0.001)
    return ev


def simulate(events):
    """Bus model: one sender at a time; lowest ID wins arbitration, losers retry."""
    events.sort(key=lambda e: e[0])
    ready = []  # heap ordered by (id, release_time, seq)
    out = []
    i, seq, t = 0, 0, 0.0
    while i < len(events) or ready:
        if not ready and t < events[i][0]:
            t = events[i][0]  # bus idle: jump to next frame
        while i < len(events) and events[i][0] <= t:
            e = events[i]
            heapq.heappush(ready, (e[1], e[0], seq, e))
            seq += 1
            i += 1
        _, _, _, e = heapq.heappop(ready)  # lowest ID wins
        _, cid, dlc, data, label, pos = e
        out.append((round(t, 6), cid, dlc, data, label, pos))
        bits = 47 + 8 * dlc + 3  # frame + interframe space (stuffing ignored)
        t += bits * BIT_T
    return out


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "id", "dlc", "data", "label", "tx_pos_m"])
        for ts, cid, dlc, data, label, pos in rows:
            w.writerow([f"{ts:.6f}", f"0x{cid:03X}", dlc, data, label, pos])


def summary(name, rows):
    counts = {}
    for r in rows:
        counts[r[4]] = counts.get(r[4], 0) + 1
    print(f"{name}: {len(rows)} frames, per label {dict(sorted(counts.items()))}")


def main():
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    normal = simulate(build_events(random.Random(1), 60, {}))
    write_csv(os.path.join(ROOT, "data", "traffic_normal.csv"), normal)
    summary("traffic_normal.csv", normal)

    attacks = {"spoof": (15, 25), "dos": (30, 35), "fuzz": (45, 55)}
    mixed = simulate(build_events(random.Random(2), 60, attacks))
    write_csv(os.path.join(ROOT, "data", "traffic.csv"), mixed)
    summary("traffic.csv", mixed)


if __name__ == "__main__":
    main()