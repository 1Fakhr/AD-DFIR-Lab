# Incident Report — Golden Ticket Attack Chain
## RC-SOC v1 Lab | corp.local Domain

**Classification:** Controlled Lab Exercise
**Analyst:** Fakhr Aldin Alkhatib
**Incident Window:** 2026-05-15 to 2026-05-16
**Severity:** Critical
**Frameworks:** MITRE ATT&CK, NIST SP 800-61

## Chain of Custody
Logs were exported from DC01 via `wevtutil epl`, preserving original
`.evtx` format prior to analysis. Splunk analysis was performed against
CSV exports of the same source events for retrospective cross-validation;
no log content was modified between collection and analysis.

## 1. Detection
Wazuh Rule 100001 (Level 12) fired at 22:35:09 on 2026-05-15, flagging an
RC4-encrypted Kerberos service ticket request (Event 4769) for `svc_sql`
originating from 192.168.100.99. Retrospective Splunk analysis later
confirmed this was 1 of exactly 5 RC4 requests against `svc_sql` out of
140 total 4769 events in the analysis window — all other traffic used
AES256 (0x12) against routine service accounts (DC01$, krbtgt,
WIN10-CLIENT$).

## 2. Analysis
Reconstructed chain: BloodHound enumeration identified `svc_sql` as
Kerberoastable (`hasspn=true`) → Kerberoasting captured an RC4 service
ticket → offline cracking recovered `svc_sql`'s password (gap — no DC
artifact exists for this phase, by design) → `impacket-secretsdump`
extracted the krbtgt hash via DRSUAPI replication (does not touch LSASS,
so no Sysmon Event 10 at this stage) → a Golden Ticket was forged for
`Administrator@CORP.LOCAL` with a 10-year lifetime (expires 2036-05-10 vs.
a normal ~10-hour TGT) → the forged ticket was used to access `\\DC01\HR`
(Event 5140) and read `employees_confidential.txt` (Event 4663, confirmed
via direct file read showing real record content). Wazuh Rule 100004
(Level 10) fired on this access.

See `SOC_Shift_Simulation.md` for how this chain would be triaged alert-by-alert
in a live shift, rather than reconstructed after the fact.

## 3. Evidence Validation — True Positive
Confirmed true positive. Independently corroborated across three log
sources (DC01 Security log, Wazuh alerts, retrospective Splunk analysis)
with consistent timestamps, source IP (192.168.100.99), and account names.
No conflicting evidence in the final evidence set (an earlier, lower-fidelity
Golden Ticket capture with a non-anomalous ~5-month expiry was identified
during review and excluded — see Lessons Learned).

## 4. Containment (recommended, lab-applicable)
1. Isolate 192.168.100.99 from the domain network
2. Reset krbtgt password twice, 10+ hour gap between resets
3. Reset svc_sql and all Domain Admin credentials
4. Disable RC4 in the Kerberos encryption GPO

## 5. Eradication & Recovery
- Audit all SPN-registered accounts for RC4 exposure
- Enable LSA Protection (`RunAsPPL`) on all domain controllers
- Re-baseline Wazuh after remediation to confirm Rule 100001 returns to zero

## 6. Detection Gaps (Lessons Learned)
- **Gap 1 — Offline cracking is invisible to the DC.** Mitigated only by
  removing RC4 from circulation, not by faster alerting.
- **Gap 2 — DRSUAPI-based credential extraction does not trigger
  LSASS-memory detections.** Rule 100005 (Sysmon Event 10) would have
  missed this attack's actual credential-theft step entirely during the
  live incident. LSASS telemetry was separately validated using a
  different technique (`comsvcs.dll` MiniDump) to confirm the rule itself
  works — but it did not fire during the real attack. This is a genuine,
  reportable detection gap, not a testing artifact, and is the single
  highest-priority tuning item from this incident.
- **Gap 3 — Golden Ticket forging happens off-network.** Detection is only
  possible at first ticket *use*, via anomalous lifetime (Rule 100003).
- **Evidence hygiene note:** an initial Golden Ticket capture during this
  investigation showed a non-anomalous ~5-month expiry from an earlier
  forging attempt. This was identified during evidence review, confirmed
  inconsistent with the final attack artifact (10-year expiry), and
  excluded from the final report. Logged here for transparency.

## 7. MITRE ATT&CK Coverage

| Technique | ID | Detected |
|---|---|---|
| Kerberoasting | T1558.003 | ✅ Rule 100001 |
| Golden Ticket | T1558.001 | ✅ Rule 100003 |
| Valid Accounts | T1078.002 | ✅ Rule 100004 |
| SMB Admin Shares | T1021.002 | ⚠️ Logged (Event 5140), no dedicated rule |
| LSASS Credential Dumping | T1003.001 | ❌ Missed during actual attack (DRSUAPI evasion) |
| Account Discovery (BloodHound) | T1087 | ❌ No rule |

## 8. Detection Tuning Notes
During baseline testing (alice.hr/bob.it normal activity, 2026-05-11/12),
Rule 100001 fired zero times — alice.hr's interactive Kerberos
authentication uses AES256, not RC4, confirming acceptable rule
specificity for this environment. Rule 100004 is intentionally scoped as
an informational signal requiring analyst context (legitimate HR staff do
read this file) rather than an autonomous high-severity alert; the
distinction between legitimate and attack access is resolved through the
triage workflow in `SOC_Shift_Simulation.md`, not by the rule alone.
