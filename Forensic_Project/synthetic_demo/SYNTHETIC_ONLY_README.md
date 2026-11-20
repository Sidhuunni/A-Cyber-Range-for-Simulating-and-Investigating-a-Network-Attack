# Synthetic host forensics demonstration

This folder is entirely a **generated teaching scenario**, separate from the real reconnaissance case. It uses Vedh's `DEMO_SYNTHETIC_append_only.pcap` (147 generated frames, SHA-256 `642a2ef5c60d7e4afa7ce05a52f4e70f2e0b4c19acaf610428437088ba39cac0`) and his provenance manifest. The addresses `.11` and `.21` are demo endpoints, not the real Kali `.10` and Metasploitable `.20` pair.

`synthetic_packets.db` contains only the 147 generated packet rows filtered from Vedh's mixed traffic database by the documented 2 November time boundary. `reconstructed_demo_payload.bin` contains 45056 bytes concatenated from the generated TCP payload on `.21` to `.11:4444`; SHA-256 `def00065c7f3ce2efadccbcb598539934fe561a0234e01eed697a49b1e7c7413`. It is a packet-derived demo artifact, not a file recovered from a real host.

`synthetic_host_events.csv` and `synthetic_attacker_events.csv` are **constructed labels** for practicing timeline correlation. They are not independent logs, memory findings, successful login evidence, or proof of theft. The case mode must remain `SYNTHETIC DEMO`. Open `case/reports/report.html` for the generated case timeline. Present the real case separately for actual findings.
