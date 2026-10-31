# Challenge 1 — supplementary rule references

These are **reference copies**, not challenge exercises. The graded/runnable hunts live directly in
`hunts/CH1/`:

- `1 - Certutil LOLBins (ADE3-01 …)` · `2 - Malware in the recycle bin (ADE2-03 …)` · `3 - PowerShell Downloads (ADE1-01 …)` — the three core steps
- `0 - New Child of w3wp (Step 0 logic bug + ADE3-02)` and `1b - Certutil Download-Abuse (ADE3-01 + ADE2-04)` — the two additional **bugged** step detections (they carry an ADE bug and are wired to run against the watchlists via the wrapper functions)

The rules **below** are the ones cited in [`challenge-1-host.md`](../../../challenge-1-host.md) that do
**not** themselves carry the bug — they are the **"caught by"** fixes and the **rarity/anomaly catches**
— plus one Step 0 analog. They are kept here verbatim (upstream YAML) for reading alongside the challenge;
they are **not** wired into `_index.csv`, and several key on fields/tables the flat CTF watchlist schema
doesn't carry, so they won't all run unmodified against `_GetWatchlist(...)`. Canonical copies live under
[`external/rulesets/`](../../../external/rulesets/) (source: Azure/Azure-Sentinel @ `f6cc435`, MIT).

| File | Role in the chain | On the attack row | Note |
|------|-------------------|-------------------|------|
| `WindowsBinariesLolbinsRenamed.yaml` | Step 1 — "caught by" (the ADE3-01 fix) | **fires** | keys on Sysmon EID 1 `OriginalFileName` (= `CertUtil.exe`) not the renamed `Image` |
| `inProcess_SignedBinaryProxyExecutionRundll32.yaml` | Step 2 — "caught by" / decoy | **fires** | bare `Process has "rundll32.exe"` |
| `imProcess_uncommon_processes.yaml` | rename catch (compensating hunt) | **fires (surfaces)** | rarity of `svc_update.exe` |
| `ProcessEntropy.yaml` | rename catch (compensating hunt) | **fires (surfaces)** | entropy of `svc_update.exe` |
| `COMEventSystemLoadingNewDLL.yaml` | Step 0 analog (ImageLoad join) | **misses** | same Sysmon 7→1 join as the compensating control, but scoped to `svchost.exe`, not `w3wp.exe` |

Also relevant and already in the reference library (`hunts/_reference-CH1/`): `Windows Binaries Executed
from Non-Default Directory.kql` (a Step 2 **miss** — it checks `NewProcessName`, but `rundll32` runs from
System32 and the recycle-bin path is only in the DLL argument) and `Base64 encoded Windows process
command-lines Normalized Process Events.kql` (≈ `imProcess_base64_encoded_pefile`, a Step 1 miss).
