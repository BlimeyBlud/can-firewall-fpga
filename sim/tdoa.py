"""TDoA sender verification model + combination with the firewall model.

Measured TDoA = (L - 2x) * 5 ns + Gaussian noise. A frame is flagged if its
measured value is outside expected(ID) +/- TOL, or if the ID is not whitelisted.
Combined mode: flagged frames are blocked and NOT counted by the rate limiter,
so a spoofer cannot use up the real ECU's rate budget.

Writes docs/tdoa_results.csv
"""
import csv
import os
import random

from firewall_model import Firewall, NAMES, ROOT

NS_PER_M = 5.0
BUS_L = 10.0
SIGMA = 2.0
TOL = 6.0
ECU_POS = {0x0A0: 1.0, 0x120: 3.0, 0x1F0: 5.0, 0x2B0: 7.0, 0x3C0: 9.0}
EXPECTED = {cid: (BUS_L - 2 * x) * NS_PER_M for cid, x in ECU_POS.items()}


def tdoa_ok(cid, pos_m, rng, sigma):
    measured = (BUS_L - 2 * pos_m) * NS_PER_M + rng.gauss(0, sigma)
    if cid not in EXPECTED:
        return False
    return abs(measured - EXPECTED[cid]) <= TOL


def load_rows():
    with open(os.path.join(ROOT, "data", "traffic.csv"), newline="") as f:
        return list(csv.DictReader(f))


def evaluate(rows, sigma):
    rng = random.Random(3)
    fw_rate = Firewall()   # rate limiter only
    fw_comb = Firewall()   # rate limiter + TDoA
    stats = {lab: [0, 0, 0, 0] for lab in range(4)}  # n, tdoa_flagged, rate_blocked, comb_blocked
    cur_ms = 0
    for r in rows:
        ms = round(float(r["timestamp"]) * 1e6) // 1000
        while cur_ms < ms:
            fw_rate.tick()
            fw_comb.tick()
            cur_ms += 1
        cid = int(r["id"], 16)
        lab = int(r["label"])
        ok = tdoa_ok(cid, float(r["tx_pos_m"]), rng, sigma)
        rate_allow = fw_rate.frame(cid)
        comb_allow = fw_comb.frame(cid) if ok else False
        s = stats[lab]
        s[0] += 1
        s[1] += (not ok)
        s[2] += (not rate_allow)
        s[3] += (not comb_allow)
    return stats


def main():
    rows = load_rows()
    stats = evaluate(rows, SIGMA)

    print("Expected TDoA (ns):", {f"0x{c:03X}": v for c, v in EXPECTED.items()},
          "| attacker at 8 m:", (BUS_L - 16) * NS_PER_M)
    print(f"\nsigma = {SIGMA} ns, window = +/-{TOL} ns")
    print(f"{'type':8} {'frames':>7} {'TDoA only':>10} {'rate only':>10} {'combined':>10}")
    out = [["type", "frames", "tdoa_only_pct", "rate_only_pct", "combined_pct"]]
    for lab in range(4):
        n, tf, rb, cb = stats[lab]
        p = [100.0 * v / n for v in (tf, rb, cb)]
        print(f"{NAMES[lab]:8} {n:7d} {p[0]:9.2f}% {p[1]:9.2f}% {p[2]:9.2f}%")
        out.append([NAMES[lab], n] + [f"{v:.2f}" for v in p])
    print("(normal row = false positive rate; attack rows = detection rate)")

    print("\nNoise sweep (TDoA only):")
    print(f"{'sigma ns':>8} {'normal FP %':>12} {'spoof detect %':>15}")
    out.append([])
    out.append(["sigma_ns", "normal_fp_pct", "spoof_detect_pct"])
    for sg in (0, 2, 4, 6):
        st = evaluate(rows, sg)
        fp = 100.0 * st[0][1] / st[0][0]
        sd = 100.0 * st[1][1] / st[1][0]
        print(f"{sg:8d} {fp:12.2f} {sd:15.2f}")
        out.append([sg, f"{fp:.2f}", f"{sd:.2f}"])

    with open(os.path.join(ROOT, "docs", "tdoa_results.csv"), "w", newline="") as f:
        csv.writer(f).writerows(out)


if __name__ == "__main__":
    main()