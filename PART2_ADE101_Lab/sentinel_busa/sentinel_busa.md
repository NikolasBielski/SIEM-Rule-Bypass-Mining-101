# sentinel_busa — run the CH1 detections locally with Hayabusa

> Companion to the CH1 hunts. When Sentinel isn't reachable — the lab's WEF
> forwarding is down, or you're validating from a remote VM — you can run the
> CH1 rules against a **local Sysmon EVTX** with [Hayabusa](https://github.com/Yamato-Security/hayabusa)
> instead of querying the `Sysmon` table in Sentinel.

## What it is

[`sentinel_busa/`](../../../sentinel_busa/) is a set of Sigma ports of the
**buggy** CH1 Sentinel rules — the exact rules each ADE bypass is built to
defeat. Running them over your atomic‑chain EVTX reproduces the Sentinel
**misses locally**, and the contrast against Hayabusa's *built‑in* Sigma
(which catches some of them) is the ADE lesson in two reports.

## Rule map

| CH1 hunt (Sentinel KQL) | sentinel_busa Sigma | ADE bug | Misses the atomic because |
|---|---|---|---|
| [1 - Certutil LOLBins](1%20-%20Certutil%20LOLBins%20%28ADE3-01%20Process%20Cloning%29.kql) | [certutil_lolbins_ade3-01.yml](../../../sentinel_busa/certutil_lolbins_ade3-01.yml) | ADE3‑01 | name‑only → renamed `svc_update.exe` never matches |
| [1b - Certutil Download-Abuse](1b%20-%20Certutil%20Download-Abuse%20%28ADE3-01%20+%20ADE2-04%29.kql) | [certutil_download_abuse_ade3-01_ade2-04.yml](../../../sentinel_busa/certutil_download_abuse_ade3-01_ade2-04.yml) | ADE3‑01 + ADE2‑04 | name **and** a required URL; the local `-decode` has neither |
| [2 - Malware in the recycle bin](2%20-%20Malware%20in%20the%20recycle%20bin%20%28ADE2-03%20Locations%29.kql) | [malware_in_recyclebin_ade2-03.yml](../../../sentinel_busa/malware_in_recyclebin_ade2-03.yml) | ADE2‑03 | legacy `recycler` only → misses the modern `$Recycle.Bin` |
| [3 - PowerShell Downloads](3%20-%20PowerShell%20Downloads%20%28ADE1-01%20Substring%29.kql) | [powershell_downloads_ade1-01.yml](../../../sentinel_busa/powershell_downloads_ade1-01.yml) | ADE1‑01 (+ADE2‑02) | literal tokens; the concat cradle splits them; also omits `pwsh.exe` |
| [0 - New Child of w3wp](0%20-%20New%20Child%20of%20w3wp%20%28Step%200%20logic%20bug%20+%20ADE3-02%29.kql) | [new_child_of_w3wp_step0.yml](../../../sentinel_busa/new_child_of_w3wp_step0.yml) | Step 0 logic bug | only sees a spawned child; the fileless foothold spawns none |

## Run it

Buggy Sentinel rules only — expect them to **not** flag the bypass rows:
```powershell
.\hayabusa.exe csv-timeline -f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -r C:\lab\sentinel_busa -w -o C:\lab\sentinel_busa_out.csv -H C:\lab\sentinel_busa_report.html
```

Built‑in Sigma — the "catches it" side, for the contrast:
```powershell
.\hayabusa.exe csv-timeline -f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -w -o C:\lab\builtin_out.csv -H C:\lab\builtin_report.html
```

## What you should see

- **`sentinel_busa` run:** no hit on the specific bypass atomics — `svc_update.exe`,
  the `$Recycle.Bin\…\p.dll,Start` rundll32, the split‑string cradle. (It *will*
  fire on benign same‑name activity; the point is it misses the attack rows.)
- **Built‑in run:** the renamed certutil **fires** via
  `proc_creation_win_renamed_binary_highly_relevant` (keys on `OriginalFileName`).