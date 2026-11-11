"""Python model of can_firewall.v. Also writes the testbench input and answer key.

Writes: tb/fw_in.txt (events: 8000 = tick, 0xxx = frame with ID xxx),
        tb/fw_exp.txt (1 = allow, 0 = block, one line per frame),
        tb/fw_params.vh, docs/firewall_results.csv
"""
import csv
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WL = {0x0A0: 0, 0x120: 1, 0x1F0: 2, 0x2B0: 3, 0x3C0: 4}
WINDOW, LIMIT, N_CLEAN = 100, 12, 3
NAMES = {0: "normal", 1: "spoof", 2: "dos", 3: "fuzz"}


class Firewall:
    def __init__(self):
        self.cnt = [0] * 5
        self.clean = [0] * 5
        self.blocked = [False] * 5
        self.wcnt = 0

    def tick(self):
        if self.wcnt == WINDOW - 1:
            self.wcnt = 0
            for k in range(5):
                if self.cnt[k] > LIMIT:
                    self.blocked[k] = True
                    self.clean[k] = 0
                elif self.blocked[k]:
                    if self.clean[k] + 1 >= N_CLEAN:
                        self.blocked[k] = False
                        self.clean[k] = 0
                    else:
                        self.clean[k] += 1
                self.cnt[k] = 0
        else:
            self.wcnt += 1

    def frame(self, cid, tdoa_ok=True):
        """Return True = allow."""
        if cid not in WL:
            return False
        k = WL[cid]
        self.cnt[k] = min(255, self.cnt[k] + 1)
        over = self.cnt[k] > LIMIT
        return not (self.blocked[k] or over or not tdoa_ok)


def main():
    with open(os.path.join(ROOT, "data", "traffic.csv"), newline="") as f:
        rows = list(csv.DictReader(f))
    fw = Firewall()
    events, expected, labels = [], [], []
    cur_ms = 0
    for r in rows:
        ms = round(float(r["timestamp"]) * 1e6) // 1000
        while cur_ms < ms:
            fw.tick()
            events.append(0x8000)
            cur_ms += 1
        cid = int(r["id"], 16)
        allow = fw.frame(cid)
        events.append(cid)
        expected.append(1 if allow else 0)
        labels.append(int(r["label"]))

    tb = os.path.join(ROOT, "tb")
    with open(os.path.join(tb, "fw_in.txt"), "w", newline="\n") as f:
        f.write("\n".join(f"{e:04X}" for e in events) + "\n")
    with open(os.path.join(tb, "fw_exp.txt"), "w", newline="\n") as f:
        f.write("\n".join(str(e) for e in expected) + "\n")
    with open(os.path.join(tb, "fw_params.vh"), "w", newline="\n") as f:
        f.write(f"`define NEV {len(events)}\n`define NFR {len(expected)}\n")

    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    print(f"{'type':8} {'frames':>7} {'blocked':>8} {'blocked %':>10}")
    out = [["type", "frames", "blocked", "blocked_pct"]]
    for lab in range(4):
        idx = [i for i, l in enumerate(labels) if l == lab]
        if not idx:
            continue
        blk = sum(1 for i in idx if expected[i] == 0)
        pct = 100.0 * blk / len(idx)
        print(f"{NAMES[lab]:8} {len(idx):7d} {blk:8d} {pct:9.2f}%")
        out.append([NAMES[lab], len(idx), blk, f"{pct:.2f}"])
    with open(os.path.join(ROOT, "docs", "firewall_results.csv"), "w", newline="") as f:
        csv.writer(f).writerows(out)


if __name__ == "__main__":
    main()