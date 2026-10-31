## Setup (≈10 minutes)

This is only if you perfer to use your own tenant and MS workspace. You should all have access to DEATHLAB.net MS Sentinel. If you don't, then raise it in the I.T Support channel.

---

You can use a **Microsoft Sentinel / Log Analytics** workspace (recommended — the
rules and watchlist functions are built for it) or any KQL-capable environment.

1. **Upload the watchlists.** In Sentinel → *Watchlists* → *New*, upload each CSV in
   `watchlists/` with the alias equal to the filename stem
   (`c1-securityevent`, `c1-sysmon`, `c2-signinlogs`, `c2-auditlogs`,
   `c2-officeactivity`). See [`watchlists/README.md`](watchlists/README.md) for the
   file→table→alias map.
2. **Save the wrapper functions.** Open
   [`functions/wrapper_functions.kql`](functions/wrapper_functions.kql). Each block
   has a `functionAlias:` comment — save each block as a **saved function** by that
   name (`SigninLogs_CH2`, `AuditLogs_CH2`, `OfficeActivity_CH2`, `ProcessCreate_CH1`,
   `Event_CH1`, `SecurityEvent_CH1`, …). These present each watchlist as if it were
   the real Sentinel table, so the hunts and the real rule queries run unchanged.
3. **Set your time range.** The data spans ~2 years of synthetic history. Set the
   Logs time picker to **Last 2 years** (or trust the `ago(730d)` already inside the
   functions). If a query returns nothing, this is the first thing to check.
4. **Smoke test:** `SigninLogs_CH2 | count` should return a few thousand rows.
