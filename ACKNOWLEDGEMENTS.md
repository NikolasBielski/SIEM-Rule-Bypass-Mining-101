# Acknowledgements

**SIEM Rule Bypass Mining 101 (ADE101)** stands on a lot of other people's amazing work.
This workshop would not exist without the open-source tools, the communities
behind them, and the people who gave their time to build and run it. Kia ora.

---

## People

### Randy Pragman & the DEATHCon crew
For DEATHCon, the event, the community, and the opportunity to lead this workshop.
Thank you for building something that brings defenders together no matter where they are, in the interest of learning and sharing. Huge thank you! I've really enjoyed developing this workshop!

### Daniel Koifman
Co-lead of the Adversarial Detection Engineering (ADE) org. Thank you for the partnership, the direction, contributions, which is elating to my output quality, because you are an absolute beast and machine.

### The detection-rule authors
Every example in this workshop is built on a real, published detection. A special thank-you to everyone who writes detection logic **in  public**. It's difficult to put your ideas and contributions out there in the open, because some people love to criticize. You are making the world a more peaceful place by making threats easier to catch, and you continue push the industry forward.

Specific authors named in the rules used in the lab:
- **Shain** — `COMEventSystemLoadingNewDLL` (Microsoft Sentinel community rule)
Thank you Shain for contributing to open source!

And collectively, the contributors behind the rulesets, huge thank you:

- **Microsoft Sentinel / [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)** community (MIT) — the ASIM process hunting queries and analytic rules (Certutil LOLBins, Certutil Download-Abuse, Malware in the Recycle Bin, New Child of w3wp, and others)
- **[SigmaHQ](https://github.com/SigmaHQ/sigma)** (DRL-1.1). SigmaHQ constantly drives society forward, enabling tons of tools (like Hayabusa and ADE). 

---

*Tools and rules are credited to their respective authors and licenses; see each
project's repository for full terms.*

## Tools

### EvidenceForge
> [github.com/Cisco-Talos/EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) · Cisco Systems, Inc. (Talos) · MIT

The realistic **benign baseline** behind Challenge 1 was created with EvidenceForge 2.0. It generated causally-consistent host telemetry, Windows Security `4688` events
with real process trees, plus Sysmon `1/3/7/11`, over a short lab window. That
benign noise is where malicious bypass rows are added into, so the
hunts have to separate real attacker behaviour from ordinary activity instead of
spotting obviously-synthetic events. Thank you for making this tool avaliable via MIT!

### Hayabusa
> [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) · Yamato Security · GPL-3.0

Hayabusa is how you run the query logic **without a lab connection**. I.e Sigma over
a local Sysmon EVTX, DFIR-style. The `sentinel_busa` companion uses it to
reproduce the Sentinel misses locally and to enable participants to compare the buggy rules against Hayabusa's built-in Sigma set (with July 2026 bug fixes). Thank you Yamato Security!

### Claude Code
> [claude.com/claude-code](https://claude.com/claude-code) · Anthropic
Used as a pair-debugging partner while building the labs and workbook. Helped me avoid making assumptions that aren't true, helped with developing the rehydration scripts into the .csv etc. Big up to Anthropic.