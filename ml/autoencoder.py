"""Autoencoder anomaly detector on 100 ms windows of CAN traffic.

Features per window: counts for 5 IDs + other, mean inter-arrival time (ms),
ID entropy (bits), bus load (fraction). Train on normal-only traffic.
Threshold = 99th percentile of reconstruction error on normal training windows.
Writes docs/autoencoder_results.csv, docs/ae_error_timeline.png, docs/ae_error_hist.png
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = 0.1  # seconds
IDS = [0x0A0, 0x120, 0x1F0, 0x2B0, 0x3C0]
NAMES = {0: "normal", 1: "spoof", 2: "dos", 3: "fuzz"}


def featurize(path):
    df = pd.read_csv(path, dtype={"id": str, "data": str})
    df["idn"] = df["id"].apply(lambda s: int(s, 16))
    df["w"] = (df["timestamp"] // WIN).astype(int)
    feats, wins, labs = [], [], []
    for w, g in df.groupby("w"):
        ids = g["idn"].values
        counts = [int((ids == i).sum()) for i in IDS]
        other = len(ids) - sum(counts)
        ts = np.sort(g["timestamp"].values)
        ia = np.diff(ts).mean() * 1000 if len(ts) > 1 else WIN * 1000
        _, c = np.unique(ids, return_counts=True)
        p = c / c.sum()
        ent = float(-(p * np.log2(p)).sum())
        bits = float((47 + 8 * g["dlc"].values).sum())
        load = bits / (500_000 * WIN)
        feats.append(counts + [other, ia, ent, load])
        wins.append(w)
        labs.append(int((g["label"] > 0).any()))
    wins = np.array(wins)
    # per-window attack type (majority non-normal label), 0 if clean
    typ = []
    for w in wins:
        l = df.loc[df["w"] == w, "label"].values
        typ.append(int(np.bincount(l[l > 0]).argmax()) if (l > 0).any() else 0)
    return np.array(feats, float), wins, np.array(typ)


def main():
    Xn, _, _ = featurize(os.path.join(ROOT, "data", "traffic_normal.csv"))
    Xa, wa, ta = featurize(os.path.join(ROOT, "data", "traffic.csv"))

    sc = StandardScaler().fit(Xn)
    Zn, Za = sc.transform(Xn), sc.transform(Xa)

    ae = MLPRegressor(hidden_layer_sizes=(8, 4, 8), activation="tanh",
                      max_iter=3000, random_state=0)
    ae.fit(Zn, Zn)

    def err(Z):
        return ((ae.predict(Z) - Z) ** 2).mean(axis=1)

    en, ea = err(Zn), err(Za)
    thr = float(np.percentile(en, 99))
    flag = ea > thr
    print(f"Threshold (99th pct of normal error): {thr:.4f}")
    print(f"Training windows: {len(Zn)}, test windows: {len(Za)}")

    rows = [["type", "windows", "detection_rate_pct", "latency_windows", "latency_ms"]]
    print(f"\n{'type':8} {'windows':>8} {'detected %':>11} {'latency (win)':>14}")
    for lab in (1, 2, 3):
        idx = np.where(ta == lab)[0]
        det = 100.0 * flag[idx].mean()
        first = idx[0]
        hit = np.where(flag[first:])[0]
        lat = int(hit[0]) if len(hit) else -1
        print(f"{NAMES[lab]:8} {len(idx):8d} {det:10.1f}% {lat:14d}")
        rows.append([NAMES[lab], len(idx), f"{det:.1f}", lat, lat * 100 if lat >= 0 else -1])
    clean = np.where(ta == 0)[0]
    fpr = 100.0 * flag[clean].mean()
    acc = 100.0 * ((flag == (ta > 0)).mean())
    print(f"\nFalse positive rate on clean windows: {fpr:.2f}%")
    print(f"Overall window accuracy: {acc:.1f}%")
    rows.append(["clean_fpr_pct", len(clean), f"{fpr:.2f}", "", ""])
    rows.append(["overall_accuracy_pct", len(ta), f"{acc:.1f}", "", ""])
    with open(os.path.join(ROOT, "docs", "autoencoder_results.csv"), "w", newline="") as f:
        csv.writer(f).writerows(rows)

    # Plots
    fig, ax = plt.subplots(figsize=(10, 4))
    t = wa * WIN
    ax.semilogy(t, ea + 1e-6, lw=1, color="tab:blue", label="reconstruction error")
    ax.axhline(thr, color="red", ls="--", label="threshold")
    colors = {1: "orange", 2: "red", 3: "purple"}
    for lab in (1, 2, 3):
        m = ta == lab
        ax.scatter(t[m], ea[m] + 1e-6, s=14, color=colors[lab], label=NAMES[lab], zorder=3)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("error (log)")
    ax.set_title("Autoencoder reconstruction error per 100 ms window")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(ROOT, "docs", "ae_error_timeline.png"), dpi=150)

    fig, ax = plt.subplots(figsize=(6, 4))
    bins = np.logspace(-4, np.log10(max(ea.max(), 1)), 40)
    ax.hist(en, bins=bins, alpha=0.6, label="normal (train)")
    ax.hist(ea[ta > 0], bins=bins, alpha=0.6, label="attack windows")
    ax.axvline(thr, color="red", ls="--", label="threshold")
    ax.set_xscale("log")
    ax.set_xlabel("reconstruction error")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(ROOT, "docs", "ae_error_hist.png"), dpi=150)
    print("\nSaved plots to docs/")


if __name__ == "__main__":
    main()