# Sidharth forensic project

This is the runnable continuation of the supplied handoff ZIP. Open `case/reports/report.html` or run `OPEN_RESULTS.bat`. The case contains the original reconnaissance capture, Prashnik's two newer handover documents, the Metasploitable RAM hash and byte-offset excerpts, and selected Linux filesystem artifacts recovered from the VMDK download. `RUN_ANALYSIS.bat` refreshes the combined case report. The source code and structured exports remain available for demonstration.

## What is completed

- The original 2,570-frame reconnaissance capture is ingested. Its SHA-256 is `6ecd14cb06b1a7038e4c9eed535d55ba6192a5097f38677859d1f6aa1755fb25`. The capture runs 2026-10-05 19:17:24–19:25:10 UTC, or 2026-10-06 00:47:24–00:55:10 IST. It shows Nmap probing and service responses. It does not show an SSH authentication exchange, FTP `USER`, port 6200, or port 4444 exfiltration.
- The VirtualBox ELF RAM image is registered at `C:\Users\nittu\Downloads\metasploitable_ram.elf`, SHA-256 `2dbf3408ed6ad91331996c1e00e263a865c9b2aec845b96083d2bcc502a7d779`. `extract_memory_excerpts.py` produced `evidence/memory_excerpts.csv` with exact byte offsets. These are string observations, not a complete process or socket analysis.
- `extract_linux_disk.py` reads the VMDK sparse mapping, LVM root volume, and ext3 filesystem without modifying the source. Selected logs, `/etc/timezone`, and directory inventory are in `evidence/disk_extraction_provisional`. The Apache access log explicitly uses `-0400`; `/etc/timezone` says `US/Eastern`. Its Nmap request at 2026-10-05 15:22:50 -0400 equals 2026-10-06 00:52:50 IST and correlates with the supplied capture. FTP, SSH, SMTP, and system log entries from the same probing interval are imported into the case as reviewed host events.
- The extracted `/var/log/auth.log` shows an SSH connection that did not receive an identification string during the captured scan. The extracted `/var/log/vsftpd.log` shows a connection from Kali, not a login. `/tmp` has no `target_shadow.txt` in the inspected filesystem; the named `system_test.sh` is absent from `/var/www/twiki/bin`. The latter are observations about this image state only.
- The `/etc/inetd.conf` entry for `ingreslock` is present, but this image alone does not establish that the attacker added it or that it is persistence from this run. The Windows payload and Run key in Prashnik's first handover are explicitly simulated and have no supplied Windows image.

## Important integrity and run limits

The disk source remains `C:\Users\nittu\Downloads\Unconfirmed 264724.crdownload`. Its size at intake is 1,886,472,530 bytes, which is not sector aligned; about 39 MB of VMDK grain data referenced by its tables are missing. Its current SHA-256, `0a603ea97e1f839344384937573c50c31952513974cefe667a01055175ccafb5`, is **provisional**, not a final acquisition hash. The extractor stops on missing grains. The selected files it successfully exported are in accessible grains, but the whole disk cannot be certified until the complete download and sender hash arrive. The disk and RAM themselves are external to this small ZIP; the case verifier expects the paths in Downloads.

The newer `red_team_action_log.docx` claims a 15:20–15:27 IST full attack run and names `full_attack_capture.pcapng`, which was not supplied. The earlier `attacker_deliverables.docx` places Nmap near 00:52 IST and the shell at 01:10 IST. The two accounts conflict or describe different runs; the supplied PCAP supports the earlier reconnaissance interval only. The newer document's MD5 value for the claimed 1,048-byte stolen file is the standard empty-file MD5, so its stated hash/size pair is inconsistent. The inspected disk's `/etc/shadow` is 1,207 bytes; its first five lines are 196 bytes. The staged file is absent. The attacker documents remain **reported claims** in the case, not verified exfiltration findings.

## Files to demonstrate

- `case/reports/report.html`, `timeline.csv`, `correlations.csv`, and `evidence_manifest.csv`: updated case and traceability.
- `evidence/disk_extraction_provisional/extraction_manifest.csv`: paths, inode IDs, file sizes, Unix modification times, SHA-256 hashes, and extraction errors.
- `evidence/disk_extraction_provisional/directory_inventory.csv`: inspected `/tmp` and TWiki bin entries.
- `evidence/memory_excerpts.csv`: exact strings and RAM byte offsets.
- `results/probed_ports.csv` and `results/service_evidence.csv`: earlier capture review outputs. `results/review.html` describes the original handoff before these new host images arrived, so use the updated case report for current status.

## Reproduce and extend

`python forensics.py verify --case case` rehashes registered files. `python forensics.py report --case case` regenerates the case report. `python extract_linux_disk.py "C:\Users\nittu\Downloads\Unconfirmed 264724.crdownload" --output evidence\disk_extraction_provisional` repeats the targeted disk extraction. `python extract_memory_excerpts.py "C:\Users\nittu\Downloads\metasploitable_ram.elf"` repeats the RAM string search. The older `build_results.py` regenerates only the original capture dashboard; it does not rebuild new host findings.

Prashnik is the attacker, Vedh handles network evidence, and Sidharth handles forensics. `TEAM_REQUEST.txt` names the exact inputs still needed to substantiate the claimed later stages. Do not fill acquisition or custody fields with guessed times or hashes.

## 1 November 2026 additional files

The later `lab_recon_capture (2).pcapng` is an exact SHA-256 match to the existing reconnaissance capture, so it adds no new packets. `evidence/nmap_output_nov1.txt` records an Nmap scan on 1 November 2026 at 05:10, but there is no supplied PCAP from that time. `evidence/hydra_output_nov1.txt` contains only the Hydra startup line at 05:16:20; it contains no attempt count, result, or credential success. These files are registered as evidence and are not imported as proven attack outcomes. `VIRTUALBOX_CHECK.txt` gives Prashnik safe host performance checks; a Hyper-V/VBS conflict is a possible cause, not a diagnosis from the files received.

## 2 November 2026 synthetic artifact summary

`evidence/synthetic_artifacts_summary.docx` is registered as a teammate-supplied document, SHA-256 `8c8875d299225b49bb05f6fe21aabd41fa00874d2be1798140c8c994aad02832`. Its title explicitly calls the artifacts synthetic. It describes a 14:15–14:27 IST run, but the named `full_attack_capture.pcapng`, `hydra_full.txt`, `metasploit_full.txt`, `listener_full.txt`, and source/received files were not supplied separately. Its two purported 1,248-byte files are assigned `e3b0c442...`, the SHA-256 of zero bytes. This is internally inconsistent and cannot substantiate a transfer or matching file integrity. The document is kept as a labelled scenario/reference, not imported as observed attack or host events. The verified forensic conclusion remains reconnaissance only.

## Vedh network demo integrated as a separate forensic case

Vedh supplied a labelled synthetic PCAP and provenance manifest in `IS lab project.zip`. `synthetic_demo/` contains a **separate case with mode `SYNTHETIC DEMO`**, 147 generated packet rows, two constructed host observations, two constructed scenario events, two rule hypotheses, and eight candidate links. `reconstructed_demo_payload.bin` is 45,056 bytes extracted from the generated TCP stream, not a file taken from a real VM. Its SHA-256 is `def00065c7f3ce2efadccbcb598539934fe561a0234e01eed697a49b1e7c7413`.

For the professor, open the real `case/reports/report.html` first to show verified reconnaissance and provisional host logs. Then open `synthetic_demo/case/reports/report.html` to demonstrate how the same timeline tool handles the generated SSH-connection and transfer patterns. The latter is a rule/workflow test, not a claim of successful login, exploitation, data theft, or independent host corroboration. See `synthetic_demo/SYNTHETIC_ONLY_README.md` for exact provenance.
