## Progressive Hints Help Us Learn <3

# ADE 101 — Progressive Hints (Challenges 1 & 2)

Stuck? Read **one hint at a time** and go back to hunting before opening the next.
Each rule has three tiers:

- **Nudge** — where to look / what question to ask.
- **Field** — the exact table + column the rule uses.
- **Mechanism** — the ADE bug itself (stops just short of the fix — that's for you ;) )

Plus, per rule: a **📖 link to the real Sentinel rule**, a **🔎 link to the starter
hunt** in `Setup/hunts/`, a **▶ Workshop version** you paste straight into your Sentinel
(it uses the CTF wrapper functions)

The full fixes and flags for both challenges are released **after DEATHcon** — apply
your own reasoning first to earn the digital badge!

Wrapper functions (present each watchlist as the real table): `SecurityEvent_CH1`,
`Event_CH1`, `ProcessCreate_CH1`, `SigninLogs_CH2`, `AuditLogs_CH2`, `OfficeActivity_CH2`


In Event_CH1, to parse out the EventData XmL, add the following at the end of your query to beautify the output.
```
| extend ParsedXML = parse_xml(EventData)
| mv-apply DataNode = ParsedXML.DataItem.EventData.Data on (
    summarize DynamicProps = make_bag(pack(tostring(DataNode.["@Name"]), tostring(DataNode.["#text"]))))
| evaluate bag_unpack(DynamicProps)
| project-away ParsedXML
```
---

# Challenge 1 — Host intrusion (`WEB01`)

## Rule 0 — IIS worker spawns a child process

**Goal:** Find the bugs.

📖 Rule: [NewChildProcessOfW3WP.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Hunting%20Queries/NewChildProcessOfW3WP.yaml)  ·  🔎 Hunt: [0 - New Child of w3wp…kql](<../Setup/hunts/CH1/0 - New Child of w3wp (Step 0 logic bug + ADE3-02).kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions)</summary>

```kql
SecurityEvent_CH1
| where ParentProcessName has "w3wp.exe"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```
</details>


<details><summary>Nudge</summary>

Run it on SecurityEvent_CH1 — you'll see only benign `w3wp → csc.exe` compilation noise. Ask yourself: what if the implant **never spawns a child at all**?
</details>

<details><summary>Field</summary>

`SecurityEvent_CH1`, `ParentProcessName has "w3wp.exe"` — there is **no 4688** for the
foothold. Pivot to `Event_CH1`, EventID **7** (ImageLoad), `Image` = `w3wp.exe`,
`ImageLoaded has "Microsoft.CodeAnalysis"`.
</details>

<details><summary>Mechanism (logic/scope bug + ADE3-02)</summary>

The implant compiles **in-process** with Roslyn and runs via `Assembly.Load(bytes)` —
no `csc`/`VBCSCompiler`, no DLL on disk, **no child, no 4688**, so the rule can't
observe it at all (a scope/logic flaw). It *also* carries **ADE3-02**: the 14-day
"new child" baseline is poisonable. Only trace: **Sysmon 7** — `w3wp` loading
`Microsoft.CodeAnalysis*`.
</details>

---

## Rule 1 — [ADE101 CH1] Certutil (LOLBins and LOLScripts, Normalized Process Events)

**Goal:** a LOLBin staged a payload, but the certutil rule never fires.

📖 Rules: [imProcess_Certutil-LOLBins.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/ASimProcess/imProcess_Certutil-LOLBins.yaml) · [Certutil-Download-Abuse.yaml](https://github.com/Azure/Azure-Sentinel/blob/f6cc4352c34b84d781735967808cfc953376e7f2/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/Certutil-Download-Abuse.yaml)  ·  🔎 Hunt: [1 - Certutil LOLBins…kql](<../Setup/hunts/CH1/1 - Certutil LOLBins (ADE3-01 Process Cloning).kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions)</summary>

```kql
ProcessCreate_CH1
| where Process has "certutil.exe"
// Uncomment the next line and add your commandLine Whitelisted/ignore terms.For example "urlcache"
// | where CommandLine !contains ("urlcache") 
| extend HostCustomEntity = Dvc, AccountCustomEntity = User
```
</details>

<details><summary>Nudge</summary>

Compare the binary's **filename on disk** to what it actually *is*. A tool can be
copied and renamed — but what inside the file never changes?
</details>

<details><summary>Field</summary>

The rule identifies the tool by **process name** (`Process has "certutil.exe"`). Check
`Event_CH1` EventID 1 and read **`OriginalFileName`** (the PE-header name).
</details>

<details><summary>Mechanism (ADE3-01 — Process Cloning)</summary>

The attacker ran a **renamed signed copy** (`svc_update.exe`) — same certutil, same
`-decode` — so the name match misses, but **`OriginalFileName` is still `CertUtil.exe`**.
`Certutil-Download-Abuse` also requires a URL in the command line, but `-decode` reads a
**local** file (no URL) — a second miss (**ADE2-04**). Fix: key on `OriginalFileName`.
</details>

---

## Rule 2 — [ADE101 CH1] Malware in the recycle bin (Normalized Process Events)

**Goal:** a LOLBin ran from the recycle bin, yet the rule doesn't flag.

📖 Rule: [imProcess_malware_in_recyclebin.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/ASimProcess/imProcess_malware_in_recyclebin.yaml)  ·  🔎 Hunt: [2 - Malware in the recycle bin…kql](<../Setup/hunts/CH1/2 - Malware in the recycle bin (ADE2-03 Locations).kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions)</summary>

```kql
let procList = dynamic(["cmd.exe","ftp.exe","schtasks.exe","powershell.exe","rundll32.exe","regsvr32.exe","msiexec.exe"]);  
  ProcessCreate_CH1
  | where CommandLine has "recycler"
  | where Process has_any (procList)
  | extend FileName = tostring(split(Process, '\\')[-1])
  | where FileName in~ (procList)
  | project TimeGenerated, Dvc, User, Process, FileName, CommandLine, ActingProcessName  // EventVendor, EventProduct not included in data, no impact on logic bug.
  | extend AccountName = tostring(split(User, @'\')[1]), AccountNTDomain = tostring(split(User, @'\')[0])
  | extend HostName = tostring(split(Dvc, ".")[0]), DomainIndex = toint(indexof(Dvc, '.'))
  | extend HostNameDomain = iff(DomainIndex != -1, substring(Dvc, DomainIndex + 1), Dvc)
  | project-away DomainIndex
```
</details>

<details><summary>Nudge</summary>

The payload really is in the bin. Compare the **exact path** it ran from to the single
**string** the rule searches for.
</details>

<details><summary>Field</summary>

`ProcessCreate_CH1`, `CommandLine has "recycler"`. The payload path contains
`$Recycle.Bin`, not `recycler`.
</details>

<details><summary>Mechanism (ADE2-03 — Locations)</summary>

The rule matches only the **legacy** string `recycler` (`C:\RECYCLER`). The payload
runs from the **modern** bin `C:\$Recycle.Bin\<SID>\`, which contains `$Recycle.Bin`
and **not** `recycler` — so it's missed. Fix: also match `"$Recycle.Bin"`.
</details>

---

## Rule 3 — [ADE101 CH1] PowerShell download cradle


**Goal:** PowerShell fetched the next stage, but the download rule missed it.

📖 Rule: [imProcess_powershell_downloads.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/ASimProcess/imProcess_powershell_downloads.yaml)  ·  🔎 Hunt: [3 - PowerShell Downloads…kql](<../Setup/hunts/CH1/3 - PowerShell Downloads (ADE1-01 Substring).kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions)</summary>

```kql
ProcessCreate_CH1
| where Process has_any ("powershell.exe","powershell_ise.exe")
| where CommandLine has_any ("Net.WebClient","DownloadFile","Invoke-WebRequest","Invoke-Shellcode","http:","https:")
```

</details>

<details><summary>Nudge</summary>

Read the command line character by character. Is `Net.WebClient` actually *spelled out*
anywhere in it?
</details>

<details><summary>Field</summary>

`ProcessCreate_CH1`, the rule does `has_any("Net.WebClient","DownloadFile",…)` — literal
strings. Look at how those tokens are written in the cradle's command line.
</details>

<details><summary>Mechanism (ADE1-01 — Substring Manipulation)</summary>

The cradle is built by **concatenation** (`'Net.We'+'bClient'`, `'Down'+'loadFile'`,
`'ht'+'tp://'`), so none of the literal tokens ever appear. Fix: **normalize** (strip
quotes/`+`/backticks) *then* match, or flag the `New-Object` + concatenation pattern.
</details>

---

# Challenge 2 — Cloud identity takeover

## Rule 1 — [ADE101 CH2]  Password spray attack against Microsoft Entra ID application


**Goal:** how did the attacker get a foothold without raising an alert, and *which* account succeeded?

📖 Rule: [SigninPasswordSpray.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninPasswordSpray.yaml)  ·  🔎 Hunt: [Password spray…kql](<../Setup/hunts/CH2/Password spray attack against Microsoft Entra ID application.kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions — full runnable hunt)</summary>

```kql
let timeRange = 730d;
let lookBack = 730d;
let authenticationWindow = 20m;
let authenticationThreshold = 5;
let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}";
let failureCodes = dynamic([50053, 50126, 50055]); // invalid password, account is locked - too many sign ins, expired password
let successCodes = dynamic([0, 50055, 50057, 50155, 50105, 50133, 50005, 50076, 50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129]);
// Lookup up resolved identities from last 7 days
let aadFunc = (tableName:string){
let identityLookup = table(tableName)
| where TimeGenerated >= ago(730d)
| where not(Identity matches regex isGUID)
| where isnotempty(UserId)
| summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName, Type;
// collect window threshold breaches
table(tableName)
| where TimeGenerated > ago(730d)
| where ResultType in(failureCodes)
| summarize FailedPrincipalCount = dcount(UserPrincipalName) by bin(TimeGenerated, authenticationWindow), IPAddress, AppDisplayName, Type
| where FailedPrincipalCount >= authenticationThreshold
| summarize WindowThresholdBreaches = count() by IPAddress, Type
| join kind= inner (
// where we breached a threshold, join the details back on all failure data
table(tableName)
| where TimeGenerated > ago(730d)
| where ResultType in(failureCodes)
| extend LocationDetails = todynamic(LocationDetails)
| extend FullLocation = strcat(LocationDetails.countryOrRegion,'|', LocationDetails.state, '|', LocationDetails.city)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), make_set(ClientAppUsed,20), make_set(FullLocation,20), FailureCount = count() by IPAddress, AppDisplayName, UserPrincipalName, UserDisplayName, Identity, UserId, Type
// lookup any unresolved identities
| extend UnresolvedUserId = iff(Identity matches regex isGUID, UserId, "")
| join kind= leftouter (
 identityLookup
) on $left.UnresolvedUserId==$right.UserId
| extend UserDisplayName=iff(isempty(lu_UserDisplayName), UserDisplayName, lu_UserDisplayName)
| extend UserPrincipalName=iff(isempty(lu_UserPrincipalName), UserPrincipalName, lu_UserPrincipalName)
| summarize StartTime = min(StartTime), EndTime = max(EndTime), make_set(UserPrincipalName,20), make_set(UserDisplayName,20), make_set(set_ClientAppUsed,20), make_set(set_FullLocation,20), make_list(FailureCount,20) by IPAddress, AppDisplayName, Type
| extend FailedPrincipalCount = array_length(set_UserPrincipalName)
) on IPAddress
| project IPAddress, StartTime, EndTime, TargetedApplication=AppDisplayName, FailedPrincipalCount, UserPrincipalNames=set_UserPrincipalName, UserDisplayNames=set_UserDisplayName, ClientAppsUsed=set_set_ClientAppUsed, Locations=set_set_FullLocation, FailureCountByPrincipal=list_FailureCount, WindowThresholdBreaches, Type
| join kind= inner (
table(tableName) // get data on success vs. failure history for each IP
| where TimeGenerated > ago(730d)
| where ResultType in(successCodes) or ResultType in(failureCodes) // success or failure types
| summarize GlobalSuccessPrincipalCount = dcountif(UserPrincipalName, (ResultType in (successCodes))), ResultTypeSuccesses = make_set_if(ResultType, (ResultType in (successCodes))), GlobalFailPrincipalCount = dcountif(UserPrincipalName, (ResultType in (failureCodes))), ResultTypeFailures = make_set_if(ResultType, (ResultType in (failureCodes))) by IPAddress, Type
| where GlobalFailPrincipalCount > GlobalSuccessPrincipalCount // where the number of failed principals is greater than success - eliminates FPs from IPs who authenticate successfully alot and as a side effect have alot of failures
) on IPAddress
| project-away IPAddress1
| extend timestamp=StartTime
};
let aadSignin = aadFunc("SigninLogs_CH2");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
```
</details>

<details><summary>Nudge</summary>

One source IP tries many accounts with the same low-effort outcome, then succeeds once.
Count **distinct accounts per source IP over time**. A human doesn't fail against 24 people.
</details>

<details><summary>Field</summary>

`SigninLogs_CH2` — pivot on `IPAddress`, `dcount(UserPrincipalName)`, filter `ResultType`
to failures (`50053`,`50055`,`50126`) vs the one success (`0`). The rule bins per **20-min** window.
</details>

<details><summary>Mechanism (ADE3-02 — Aggregation Hijacking)</summary>

The rule fires at **≥5 distinct failed UPNs from one IP inside a 20-min bin**. The spray is
paced ~1 attempt / 6 min, so **no 20-min window holds 5** — even across 24 sprayed accounts.
The single success hands you the compromised UPN. **Widen the window / lower the count.**
→ pivot that UPN into Rule 2.
</details>

---

## Rule 2 — [ADE101 CH2] Guest Users Invited to Tenant by New Inviters


**Goal:** the compromised user invites a guest — why doesn't the "new inviter" rule fire?

📖 Rule: [GuestUsersInvitedtoTenantbyNewInviters.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/GuestUsersInvitedtoTenantbyNewInviters.yaml)  ·  🔎 Hunt: [Guest Users Invited…kql](<../Setup/hunts/CH2/Guest Users Invited to Tenant by New Inviters.kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions — full runnable hunt)</summary>

```kql
let inviting_users = (AuditLogs_CH2
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where OperationName =~ "Invite external user"
  | where Result =~ "success"
  | extend InitiatingUserPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | where isnotempty(InitiatingUserPrincipalName)
  | summarize by InitiatingUserPrincipalName);
  AuditLogs_CH2
  | where TimeGenerated > ago(730d)
  | where OperationName =~ "Invite external user"
  | where Result =~ "success"
  | extend InitiatingUserPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
  | extend InitiatingIPAddress = tostring(InitiatedBy.user.ipAddress)
  | where isnotempty(InitiatingUserPrincipalName) and InitiatingUserPrincipalName !in (inviting_users)
  | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | extend TargetAadUserId = tostring(TargetResources[0].id)
  | extend invitingUser = InitiatingUserPrincipalName, invitedUserPrincipalName = TargetUserPrincipalName
  | extend InitiatingAccountName = tostring(split(InitiatingUserPrincipalName, "@")[0]), InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalName, "@")[1])
  | extend TargetAccountName = tostring(split(TargetUserPrincipalName, "@")[0]), TargetAccountUPNSuffix = tostring(split(TargetUserPrincipalName, "@")[1])
  | project-reorder TimeGenerated, OperationName, Result, TargetUserPrincipalName, TargetAadUserId, InitiatingUserPrincipalName, InitiatingAadUserId, InitiatingIPAddress
```
</details>

<details><summary>Nudge</summary>

The account you compromised invites an external guest. A rule exists for invites by people
who don't normally invite — so look at **everything that accounts did *before* the attack**, too.. 
</details>

<details><summary>Field</summary>

`AuditLogs_CH2`, `OperationName == "Invite external user"`, pivot on
`InitiatingUserPrincipalName`. Compare the malicious invite to that inviter's **prior 14 days**.
</details>

<details><summary>Mechanism (ADE4-01 — Gate Inversion)</summary>

Fires only when the inviter is **NOT** in the last-14-day inviter list (`!in (inviting_users)`).
A **benign invite by the same victim two days earlier** makes them an "established inviter," so
the NOT-gate flips and the malicious invite reads as normal. Use an **allowlist of approved
inviters**, not a learned baseline. → the invited guest is your Rule 3 actor.
</details>

---

## Rule 3 — [ADE101 CH2]  Bulk Changes to Privileged Account Permissions


**Goal:** the guest grants privilege — why is the "bulk privileged-role change" rule not firing??

📖 Rule: [BulkChangestoPrivilegedAccountPermissions.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/BulkChangestoPrivilegedAccountPermissions.yaml)  ·  🔎 Hunt: [Bulk Changes…kql](<../Setup/hunts/CH2/Bulk Changes to Privileged Account Permissions.kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions — full runnable hunt)</summary>

```kql
let AdminRecords = AuditLogs_CH2
| where Category =~ "RoleManagement"
| where OperationName has_any ("Add eligible member to role", "Add member to role")
| mv-apply TargetResource = TargetResources on 
  (
      where TargetResource.type =~ "User"
      | extend TargetUserPrincipalName = tostring(TargetResource.userPrincipalName),
               props = TargetResource.modifiedProperties
  )
| mv-apply Property = props on 
  (
      where Property.displayName =~ "Role.DisplayName"
      | extend RoleName = trim('"',tostring(Property.newValue))
  )
| where RoleName contains "Admin";
AdminRecords
| summarize dcount(TargetUserPrincipalName) by bin(TimeGenerated, 1h)
| where dcount_TargetUserPrincipalName > 9
| join kind=rightsemi  (
  AdminRecords
  | extend TimeWindow = bin(TimeGenerated, 1h)
) on $left.TimeGenerated == $right.TimeWindow
| extend InitiatedByUser = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), "")
| extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
| extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId)
| extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
| extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| extend TargetName = tostring(split(TargetUserPrincipalName,'@',0)[0]), TargetUPNSuffix = tostring(split(TargetUserPrincipalName,'@',1)[0])
| extend InitiatingAccountName = tostring(split(InitiatingUserPrincipalName, "@")[0]), InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalName, "@")[1])
```
</details>

<details><summary>Nudge</summary>

Role assignments to a service principal. The rule wants two things at once — a kind of
role **and** a rate. The attacker dodged **both**. Read the granted role names.
</details>

<details><summary>Field</summary>
run
```
AuditLogs_CH2()
| where OperationName == "Add member to role"
```
and, look at `RoleName`, and the count
per initiator per hour.
The rule has: `RoleName contains "Admin"` **and** `>9/hour`.
</details>

<details><summary>Mechanism (ADE2-01 + ADE3-02)</summary>

None of the roles contain **"Admin"** — `Directory Writers`, `read_insights` (custom),
`Owner` — yet all are privileged (**ADE2-01**). And only 3 grants, under 9/hour, so the bulk
gate never trips (**ADE3-02**). Fix: match privileged roles by an **explicit set**; alert on a
**single** privileged grant.
</details>

---

## Rule 4 — [ADE101 CH2] SharePointFileOperation via devices with previously unseen user agents


**Goal:** the rule is literally named "…by New User Agent" — why does a *new* UA evade it?

📖 Rule: [SharePoint_Downloads_byNewUserAgent.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/SharePoint_Downloads_byNewUserAgent.yaml)  ·  🔎 Hunt: [SharePointFileOperation…kql](<../Setup/hunts/CH2/SharePointFileOperation via devices with previously unseen user agents.kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions — full runnable hunt)</summary>

```kql
let threshold = 5;
// Define constants for SharePoint file operations
let szSharePointFileOperation = "SharePointFileOperation";
let szOperations = dynamic(["FileDownloaded", "FileUploaded"]);
// Define the historical activity for analysis
let starttime = 730d; // Define the start time for historical data (14 days ago)
let endtime = 1d;   // Define the end time for historical data (1 day ago)
// Extract the base events for analysis
let Baseevents =
  OfficeActivity_CH2
  | where TimeGenerated between (ago(starttime) .. ago(endtime))
  | where RecordType =~ szSharePointFileOperation
  | where Operation in~ (szOperations)
  | where isnotempty(UserAgent);
// Identify frequently occurring user agents
let FrequentUA = Baseevents
  | summarize FUACount = count() by UserAgent, RecordType, Operation
  | where FUACount >= threshold
  | distinct UserAgent;
// Calculate a user baseline for further analysis
let UserBaseLine = Baseevents
  | summarize Count = count() by UserId, Operation, Site_Url
  | summarize AvgCount = avg(Count) by UserId, Operation, Site_Url;
// Extract recent activity for analysis
let RecentActivity = OfficeActivity_CH2
  | where TimeGenerated > ago(730d)
  | where RecordType =~ szSharePointFileOperation
  | where Operation in~ (szOperations)
  | where isnotempty(UserAgent)
  | where UserAgent in~ (FrequentUA)
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), OfficeObjectIdCount = dcount(OfficeObjectId), OfficeObjectIdList = make_set(OfficeObjectId), UserAgentSeenCount = count() 
  by RecordType, Operation, UserAgent, UserType, UserId, ClientIP, OfficeWorkload, Site_Url;
// Analyze user behavior based on baseline and recent activity
let UserBehaviorAnalysis = UserBaseLine
  | join kind=inner (RecentActivity) on UserId, Operation, Site_Url
  | extend Deviation = abs(UserAgentSeenCount - AvgCount) / AvgCount;
// Filter and format results for specific user behavior analysis
UserBehaviorAnalysis
  | where Deviation > 25
  | extend UserIdName = tostring(split(UserId, '@')[0]), UserIdUPNSuffix = tostring(split(UserId, '@')[1])
  | project-reorder StartTime, EndTime, UserAgent, UserAgentSeenCount, UserId, ClientIP, Site_Url
  | project-away Site_Url1, UserId1, Operation1
  | order by UserAgentSeenCount desc, UserAgent asc, UserId asc, Site_Url asc
```
</details>

<details><summary>Nudge</summary>

The exfil UA appears nowhere else in the data. Now read what the rule actually *does* with the
user-agent field — not what its name says. Name and logic disagree.
</details>

<details><summary>Field</summary>

```
OfficeActivity_CH2
| `Operation == "FileDownloaded"
```
, pivot on `UserAgent`. Build the frequent
set, then read the rule's filter: `UserAgent in~ (FrequentUA)`.
</details>

<details><summary>Mechanism (ADE4-03 — Incorrect Expression)</summary>

It claims to catch *unseen* UAs, but keeps only events whose UA **is in** the frequent set
(`in~`, not `!in`). A brand-new UA (`python-requests/2.31.0`) is **dropped before the volume
check** — the rule can never fire on the thing it's named for. Fix: `!in`. *(It also only covers
`FileDownloaded`/`FileUploaded`, so `SharingSet` external-share exfil is an alternative too... ADE2-01.)*
</details>

---

## Rule 5 — Covering tracks (Defense Evasion / Anti-forensics)


**Goal:** a disposable account is created and deleted minutes apart — why no correlation?

📖 Rule: [Since fixed post my Issue raised on github:  AccountCreatedandDeletedinShortTimeframe.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/AccountCreatedandDeletedinShortTimeframe.yaml)  ·  🔎 Hunt: [Account Created and Deleted…kql](<../Setup/hunts/CH2/Account Created and Deleted in Short Timeframe.kql>)

<details><summary>▶ Workshop version — paste into Sentinel (CTF functions — full runnable hunt)</summary>

```kql
let queryfrequency = 730d;
let queryperiod = 730d;
AuditLogs_CH2
| where TimeGenerated > ago(730d)
| where OperationName =~ "Delete user"
//extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| mv-apply TargetResource = TargetResources on 
  (
      where TargetResource.type == "User"
      | extend UserPrincipalName = extract(@'([a-f0-9]{32})?(.*)', 2, tostring(TargetResource.userPrincipalName))
  )
| extend DeletedByUser = tostring(InitiatedBy.user.userPrincipalName), DeletedByIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend DeletedByApp = tostring(InitiatedBy.app.displayName)
| project Deletion_TimeGenerated = TimeGenerated, UserPrincipalName, DeletedByUser, DeletedByIPAddress, DeletedByApp, Deletion_InitiatedBy = InitiatedBy, Deletion_TargetResources = TargetResources
| join kind=inner (
    AuditLogs_CH2
    | where TimeGenerated > ago(730d)
    | where OperationName =~ "Add user"      
    | mv-apply TargetResource = TargetResources on 
      (
          where TargetResource.type == "User"
          | extend UserPrincipalName = trim(@'"',tostring(TargetResource.userPrincipalName))
      )
    | project-rename Creation_TimeGenerated = TimeGenerated
) on UserPrincipalName
| extend TimeDelta = Deletion_TimeGenerated - Creation_TimeGenerated
| where  TimeDelta between (time(0s) .. queryperiod)
| extend CreatedByUser = tostring(InitiatedBy.user.userPrincipalName), CreatedByIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend CreatedByApp = tostring(InitiatedBy.app.displayName)
| project Creation_TimeGenerated, Deletion_TimeGenerated, TimeDelta, UserPrincipalName, DeletedByUser, DeletedByIPAddress, DeletedByApp, CreatedByUser, CreatedByIPAddress, CreatedByApp, Creation_InitiatedBy = InitiatedBy, Creation_TargetResources = TargetResources, Deletion_InitiatedBy, Deletion_TargetResources
| extend timestamp = Deletion_TimeGenerated, Name = tostring(split(UserPrincipalName,'@',0)[0]), UPNSuffix = tostring(split(UserPrincipalName,'@',1)[0])
```
</details>

<details><summary>Nudge</summary>

Find the `Add user` and matching `Delete user` (8 min apart, obviously the same account).
Now read the exact `TargetUserPrincipalName` on each, character for character.
</details>

<details><summary>Field</summary>

```
AuditLogs_CH2
| OperationName in ("Add user","Delete user")
```
The rule inner-joins the two
events **on `TargetUserPrincipalName`** — but note the `extract()` on delete vs `trim()` on add.
</details>

<details><summary>Mechanism (ADE1-02 — Normalization Asymmetry)</summary>

`Add user` logs the UPN **with** a 32-hex object-GUID prefix
(`a1b2c3…tempsvc#EXT#@corp.com`); `Delete user` logs it **without**. The delete side strips a
32-hex prefix (`extract`), the add side doesn't (`trim`) — so the join keys differ and never
match. Fix: **normalize both keys the same way** (strip any leading 32-hex prefix) before joining.
</details>

---

### If you're still stuck after all three tiers

- Re-read the **scenario intro** in `Challenge_1/challenge-1-host.md` /
  `Challenge_2/challenge-2-cloud.md` 
- Check your **time picker** — Rely on the function's built-in `ago(730d)`.
- Record your own answer in `ctf-questions.md` **before** anything else. Fixes + flags drop after DEATHcon, 1st December.
- Ask in the Discord!
