# Challenge 1 — Real-World Grounding

Challenge 1's intrusion (see [challenge-1-host.md](challenge-1-host.md)) is a synthetic
teaching composite — no single incident matches it step-for-step — but every individual
technique in the chain has a documented real-world precedent. This write-up tells the
scenario as a narrative, with the public reporting that grounds each step, so participants
(and reviewers) can see this isn't a contrived puzzle: every move is something a real
threat actor has actually done.

> **What's genuinely grounded vs. illustrative.** Steps 0, 1 (the rename/`-decode` pattern),
> and the WMI parent-laundering are each backed by a named campaign or a published detection
> engineering writeup — see the table below. The choice of **`$Recycle.Bin`** specifically as
> the staging location (Step 1/2) is **illustrative, not lifted from a named campaign** — the
> searches behind this document turned up only commodity-malware forum reports for that
> specific path, not a polished APT writeup. The *concept* it teaches (location-based rule
> evasion) is well established; the specific path is a teaching choice. The doc is explicit
> about this so nobody mistakes "plausible" for "documented."

## The scenario

**`WEB01`, a public-facing IIS host, goes down this path:**

A threat actor in the mold of **Gold Melody** (tracked by Unit42 as **TGR-CRI-0045**, overlapping
industry reporting on **UNC961** / **Prophet Spider**) reaches `WEB01`'s ASP.NET application and
gets code execution inside `w3wp.exe` **without ever writing a file or spawning a process**. Unit42's
2025 reporting on this cluster describes exactly this shape of intrusion: stolen or leaked ASP.NET
machine keys used to craft malicious **ViewState** payloads that execute **entirely in memory**,
deploying the **Godzilla** (aka **BLUEBEAM**) in-memory web shell — a .NET assembly decoded from an
HTTP request and loaded directly into the worker process's memory, with nothing touching disk.

Challenge 1's foothold uses a different delivery mechanism (an in-process **Roslyn** compile —
`CSharpCompilation.Emit` to a `MemoryStream`, then `Assembly.Load(bytes)` — rather than a
deserialization gadget), but the **resulting detection gap is identical** to what Unit42 and
Wiz both describe for this technique class: the worker process executes attacker code, and
**no 4688 process-creation event exists for it at all.** The only surviving trace, in both the
real campaigns and the synthetic data, is a **behavioral one** — an unusual module loaded inside
`w3wp.exe` (Sysmon EventID 7 here; .NET `AssemblyLoad`/AMSI telemetry in the real incidents).

From there, the implant stages its next tool **under a renamed, signed copy of `certutil.exe`**
and decodes a locally-staged blob with `-decode` — never touching the network. This is not a
novel idea: Netskope's writeup on a **Lazarus Group** sample documents the identical pattern —
copying `certutil.exe` to a new location, renaming it (`DriverUpdateRx.exe` in their sample,
`svc_update.exe` here), specifically **to defeat detections that match on the literal string
"certutil."** The fix side is just as real: FalconForce's public FalconFriday detection logic
is built around exactly this gap, matching a binary's **`OriginalFileName`** (from its PE header,
which survives a rename) against its actual on-disk name — which is precisely the patched rule
in this challenge.

To keep the tooling from hanging directly off `w3wp.exe` — which would be just as loud as the
classic `w3wp → cmd.exe` IOC it's trying to avoid — the implant routes execution through
**`WmiPrvSE.exe`** via `Win32_Process.Create`. Red Canary, Elastic, and Splunk all document this
as an established technique in its own right: spawning tooling as a child of the WMI provider
host specifically to **break the parent-child lineage** that process-tree-based detections rely on.

The staged DLL then runs under `rundll32.exe`, and a PowerShell cradle — built entirely from
**concatenated strings** (`'Net.We'+'bClient'`, `'Down'+'loadFile'`) rather than literal cmdlet
names — downloads and runs the final payload, which beacons out. The substring-evasion pattern
here is the same defeat-the-literal-match idea documented across both the certutil and the
WMI findings above: a rule written against surface-level string/parent matching misses a
trivial rewrite of the same behavior.

## Kill chain ↔ real-world grounding

| Step | Synthetic chain | Real-world precedent | Grounding |
|---|---|---|---|
| 0 — Foothold | Roslyn `Emit→MemoryStream→Assembly.Load(bytes)` inside `w3wp.exe`; no child, no disk, no 4688 | **Gold Melody / TGR-CRI-0045 (UNC961, Prophet Spider)**: ViewState deserialization → in-memory **Godzilla/BLUEBEAM** web shell, zero-disk-footprint execution inside `w3wp.exe` | Named campaign, active reporting |
| 1 — Staging | Renamed, signed `certutil.exe` (`svc_update.exe`) runs `-decode` on a locally-staged blob | **Lazarus Group** sample: `certutil.exe` copied + renamed (`DriverUpdateRx.exe`) specifically to defeat string-based detection, then run with `-decode` | Named campaign |
| 1 — Patched rule | `OriginalFileName` match survives the rename | **FalconForce FalconFriday**: public detection logic keyed on PE-header `OriginalFileName` vs. actual filename | Published detection engineering |
| Supporting — parent laundering | `WmiPrvSE.exe` (via `Win32_Process.Create`) hosts the tooling instead of `w3wp.exe` | Documented as its own technique by **Red Canary**, **Elastic**, **Splunk** — WMI used specifically to break parent-child correlation | Multiple independent detection-engineering sources |
| 2 — Execution location | `rundll32` runs the staged DLL from `$Recycle.Bin\<SID>\`, missed by a legacy `recycler`-string rule | *(illustrative — see caveat above; location-based rule evasion is a well-established class, this specific path isn't drawn from a named campaign)* | Not independently grounded |
| 3 — C2 cradle | PowerShell cradle built from concatenated strings (`'Net.We'+'bClient'`) | Same defeat-the-literal-match principle documented in the certutil/WMI findings above; this exact PowerShell pattern is a standard, widely-taught AMSI/string-match bypass | Conceptually well established |

## References

- [GoldMelody's Hidden Chords: Initial Access Broker In-Memory IIS Modules Revealed](https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/) — Unit42 (Palo Alto Networks)
- [In-Memory IIS Attacks via View State Deserialization](https://threats.wiz.io/all-incidents/in-memory-iis-attacks-via-view-state-deserialization) — Wiz
- [Not Laughing: Malicious Office Documents using LoLBins](https://www.netskope.com/blog/not-laughing-malicious-office-documents-using-lolbins) — Netskope
- [FalconFriday — Masquerading: Renamed executables of interest (Windows)](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0015-Masquerading-Renamed-executables-of-interest-Win.md) — FalconForce
- [Windows Management Instrumentation](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/) — Red Canary Threat Detection Report
- [Enumeration Command Spawned via WMIPrvSE](https://www.elastic.co/guide/en/security/current/enumeration-command-spawned-via-wmiprvse.html) — Elastic
- [Detection: Wmiprsve LOLBAS Execution Process Spawn](https://research.splunk.com/endpoint/95a455f0-4c04-11ec-b8ac-3e22fbd008af/) — Splunk Research
