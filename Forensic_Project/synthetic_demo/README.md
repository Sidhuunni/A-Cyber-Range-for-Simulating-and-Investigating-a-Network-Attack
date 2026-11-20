# Vedh's network analysis demo

This folder lets you show all three implemented detection rules **without running a VM**. It combines an unchanged copy of Prashnik's real October reconnaissance packets with clearly generated practice traffic from 2 November. It is a mixed demonstration file, **not one real attack capture**.

## Open this first

Double-click `DEMO_RESULTS.html`. It is a self-contained browser page showing the three alerts and exactly which are real or generated.
`DEMO_SCREENSHOT.png` is a quick presentation image of the same labelled result.

For the interactive version, open a terminal in this folder and run:

```powershell
python -m streamlit run demo_dashboard.py
```

The dashboard checks the real and mixed capture hashes against `provenance.json` and the saved databases. It shows the real/synthetic packet counts, labelled alerts, charts, and connection table. The Python packages are listed in the main `network_analysis/requirements.txt` (or `person2-network-analysis/requirements.txt` in the workspace).

## What to say while showing it

> "The first 2,570 frames are the real reconnaissance capture Prashnik sent. My tool detects the 1,000-port scan in those packets. The next 147 frames are generated practice traffic using separate IP addresses and a different date, so I can demonstrate my SSH connection-count and possible-transfer rules. Those two alerts are tests of my code, not claims that the later attack happened."

| Alert | Origin | Evidence shown | Meaning |
|---|---|---|---|
| Port scan: `.10` to `.20` | **Real**, frames 1-2,570, 5 October | 1,000 destination ports; same alert and UTC interval as real-only analysis | Reconnaissance pattern |
| SSH brute force: `.11` to `.21` | **Synthetic**, part of frames 2,571-2,717, 2 November | 31 initial TCP connections to port 22 | Rule test only; no password attempt or login result is represented |
| Large flow / possible exfil: `.21` to `.11:4444` | **Synthetic**, part of frames 2,571-2,717, 2 November | 45,056 bytes of benign labelled TCP payload | Rule test only; no file theft is represented |

The capture has 2,717 total frames: 2,570 real and 147 synthetic. Of these, 2,715 are IPv4 packets. The synthetic IPs `.11` and `.21` are intentionally different from the real Kali `.10` and Metasploitable `.20`, so the real scan alert does not absorb the synthetic SSH SYNs. The October-to-November time gap is intentional.

## Rebuild and verify

The original real capture copy in this folder has SHA-256 `6ecd14cb06b1a7038e4c9eed535d55ba6192a5097f38677859d1f6aa1755fb25`. `generate_hybrid_demo.py` checks that hash, generates the two PCAPs, and verifies that the real frame bytes remain unchanged in the mixed file. `provenance.json` records exact frame ranges, timestamps, endpoint roles, and source hashes.

From this folder in the **workspace**:

```powershell
python generate_hybrid_demo.py
python ..\..\person2-network-analysis\analyze.py DEMO_MIXED_real_recon_plus_synthetic.pcap --receiver-ip 192.168.56.11 --write-traffic
python build_static_demo.py
```

From this folder in the **extracted submission ZIP**, use `..\network_analysis\analyze.py` in the second command instead. All outputs stay in this demo folder, separate from Vedh's real-only databases.

The separate `DEMO_SYNTHETIC_append_only.pcap` contains just the 147 generated frames. The real source is `lab_recon_capture.pcapng`. The combined file is `DEMO_MIXED_real_recon_plus_synthetic.pcap`. Do not rename it to `full_attack_capture.pcapng` or use it to support the unverified SSH, exploit, Windows, or file-transfer claims in the final investigation report. The 1 November Nmap and Hydra text files also belong to a different run and are not synchronized to this demo.
