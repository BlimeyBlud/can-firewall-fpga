# can-firewall-fpga
# FPGA Hardware Firewall and Real-Time Anomaly Detector for CAN Bus Networks

Open Lab I (23ECE381 / 23EAC381), Team TID96: Dhipin Krishna P, Ekansh G, Arun B.
Guide: Dr. Chinthala Ramesh.

Simulation and RTL only (Icarus Verilog + Python). No hardware or synthesis.

## Architecture

```
traffic sim -> bitstream -> [can_parser.v] -> [can_firewall.v] -> allow / block
                                                  ^
                                   TDoA sender check (Python model)
traffic windows -> [autoencoder (Python)] -> anomaly flag
```

- `sim/can_bus_sim.py` simulates 5 ECUs (CAN 2.0A, 500 kbit/s) with arbitration, plus spoof, DoS and fuzz attacks.
- `rtl/can_parser.v` reads one bit per clock, destuffs, and outputs ID, DLC and data.
- `rtl/can_firewall.v` applies an ID whitelist and a per-ID rate limit with hysteresis.
- `sim/firewall_model.py` is the Python twin of the firewall and matches the RTL on every frame.
- `sim/tdoa.py` verifies the sender by time-difference-of-arrival (5 ns/m, 10 m bus).
- `ml/autoencoder.py` detects anomalous 100 ms windows (MLP autoencoder, one threshold).

## How to run

Requirements: Python 3.12+ (numpy, pandas, scikit-learn, matplotlib), Icarus Verilog, GTKWave.

Everything at once (PowerShell):
```
powershell -ExecutionPolicy Bypass -File .\test.ps1
```

Piece by piece:
```
python sim\can_bus_sim.py          # writes data/traffic.csv and data/traffic_normal.csv
python sim\frames_to_bits.py       # writes tb/frames.hex and tb/expected.txt
iverilog -g2012 -I tb -o tb\parser.vvp tb\tb_can_parser.v rtl\can_parser.v
vvp tb\parser.vvp                  # expect PASS (100 frames exact match)
python sim\firewall_model.py       # writes tb/fw_in.txt, tb/fw_exp.txt, docs/firewall_results.csv
iverilog -g2012 -I tb -o tb\fw.vvp tb\tb_firewall.v rtl\can_firewall.v
vvp tb\fw.vvp                      # expect PASS (RTL matches model on all frames)
python sim\tdoa.py                 # writes docs/tdoa_results.csv
python ml\autoencoder.py           # writes docs/autoencoder_results.csv and plots
```

## Results

**Parser:** 100 / 100 frames match the Python reference exactly (includes fuzz frames).

**Firewall (rate limit + whitelist), RTL equals Python model on 50,125 frames:**

| Traffic | Frames | Blocked | Blocked % |
|---|---|---|---|
| normal | 13201 | 1828 | 13.85% (false positives) |
| spoof | 2001 | 1991 | 99.50% |
| dos | 25001 | 25001 | 100.00% |
| fuzz | 9922 | 9899 | 99.77% |

**TDoA (sigma = 2 ns, window +/- 6 ns):**

| Traffic | TDoA only | Rate only | Combined |
|---|---|---|---|
| normal (FP) | 0.31% | 13.85% | 10.20% |
| spoof | 100.00% | 99.50% | 100.00% |
| dos | 100.00% | 100.00% | 100.00% |
| fuzz | 100.00% | 99.77% | 100.00% |

Noise sweep (TDoA only): normal false positives are 0.00% at 0 ns, 0.31% at 2 ns, 13.68% at 4 ns and 32.10% at 6 ns. Spoof detection stays at 100%.

**Autoencoder (threshold = 99th percentile of normal error):**

| Attack | Windows | Detected | Latency |
|---|---|---|---|
| spoof | 101 | 99.0% | 1 window (100 ms) |
| dos | 58 | 100.0% | 0 windows |
| fuzz | 101 | 100.0% | 0 windows |

False positive rate on clean windows: 0.88%. Overall window accuracy: 99.3%.

Plots: `docs/ae_error_timeline.png`, `docs/ae_error_hist.png`.
Waveform of a block event: `docs/gtkwave_block_event.png`.

## Findings and limitations

- Rate limiting alone cannot separate a spoofer from the real ECU that owns the same ID, and a DoS leaves a backlog burst of real frames that trips the limiter. Both cause false positives (13.85%).
- TDoA separates the spoofer (8 m, -30 ns) from the real sender (5 m, 0 ns), but it needs low timing noise (about 2 ns or better).
- The autoencoder works on window behavior and has very low false positives, but it flags windows, not individual frames.
- Traffic is synthetic. Bit stuffing is ignored in the simulator's bus timing. The RTL parser does not check the CRC (the CRC is generated in the test data but skipped by the parser).

## Future work

- CARRY4 delay-line TDC for sub-nanosecond TDoA measurement in hardware.
- Autoencoder inference in Verilog with 8-bit fixed-point weights.
- Vivado synthesis and utilization report on a Basys 3 board.
- CRC-15 check in the parser.