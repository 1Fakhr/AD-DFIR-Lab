# SOC Shift Simulation — How I'd Work This as a Live Alert

This project was built by reconstructing a finished attack. That's useful
for showing detection engineering, but it hides the actual job: triaging
an alert with no idea yet how it ends. This section works the same
incident in alert order, the way it would arrive on a Tier 1 queue,
without using knowledge of later steps to justify earlier decisions.

## Alert 1 — Rule 100001 fires: "Kerberoasting: RC4 service ticket requested for svc_sql by alice.hr"

**First 2 minutes — what I check immediately:**
- Is `alice.hr` a service account or a real person? → AD lookup: real HR
  user, standard workstation, no SPN-related job function. This is
  already odd — regular users don't normally request service tickets for
  SQL service accounts.
- What's the source IP? → `192.168.100.99`. Is that a known asset?
  → Not in the asset inventory for WIN10-CLIENT or DC01. That's the first
  real red flag, not the RC4 encryption type itself.
- Is this the first time this rule has fired? → Check rule history: zero
  fires during the prior 2 weeks of baseline. Not a noisy rule, so I treat
  this fire as meaningful rather than discounting it as a known-FP pattern.

**Severity reasoning:**
RC4 alone isn't proof of attack — some legacy applications still request
RC4 tickets. What moves this from "investigate when convenient" to
"investigate now" is the combination: unrecognized source IP + an HR
account touching a SQL service account + zero historical baseline for
this pattern. I'd escalate this from Level 12 informational triage to
active investigation within the hour, not immediately page on-call.

**What I'd rule out before escalating further:**
- Legitimate SQL Server application requesting delegation on alice.hr's
  behalf → checked: no Kerberos constrained delegation configured for any
  service alice.hr's account is permissioned against. Ruled out.
- Scheduled vulnerability scanner sweeping SPNs → checked: no scan
  schedule logged for that IP/time window. Ruled out.

**Decision at this point:** Open a case, do not escalate to management
yet. One ticket request from one account is suspicious, not confirmed.

## Alert 2 — Four more RC4 requests against the same SPN, now from `Administrator`

This is where it stops being ambiguous. The same source IP now requests
the same service ticket type four more times, switching from `alice.hr`
to `Administrator`. An account switch mid-pattern from the same source IP
is a stronger indicator than the encryption type ever was — it suggests
either credential reuse or that the requester already has more access
than a normal HR account should.

**Decision:** This is the point I'd escalate to a Tier 2/IR handoff,
*before* finding any Golden Ticket evidence. I don't need to see the rest
of the chain to justify escalating here — the account-switch pattern from
an unrecognized IP is sufficient on its own.

## Alert 3 — Rule 100004: "HR sensitive file accessed... by Administrator"

By the time this fires, the case is already open from Alert 2. The
question here isn't "is this suspicious" — it's "does this confirm
impact." Checking:
- Is `Administrator` logged on interactively anywhere right now, or is
  this a non-interactive/network logon? → Network logon, same external IP
  as the Kerberoasting alerts. Confirms it's the same actor, not a
  coincidental legitimate admin task.
- Is `employees_confidential.txt` a file Administrator normally touches?
  → No prior access history for this account against this file in the
  audit log. Confirms anomalous access, not routine admin maintenance.

**Decision:** This converts the case from "suspected credential abuse" to
"confirmed data access incident." This is the alert I'd use to justify
pulling in a manager/lead, not Alert 1 or 2 alone — sensitive data access
is the threshold most orgs use for mandatory escalation, regardless of
how clear the earlier signals were.

## What I would NOT have caught in real time

Being honest about this matters more than claiming full coverage:
- The offline hash-cracking step between Alert 1 and Alert 2 produced
  no log entry at all. In a live shift, there's a window where the case
  is open but quiet, and nothing tells the analyst what's happening during
  it. I wouldn't know a Golden Ticket was being forged during this gap —
  only that the account behavior already justified escalation.
- The LSASS credential-dumping step did not trigger Rule 100005 during
  the actual attack (DRSUAPI-based extraction doesn't touch LSASS memory).
  In a live shift, I would have had zero alert for this step. I only know
  about it now because I separately tested the rule afterward with a
  different technique. This is the gap I'd flag in a post-incident review
  as something the current ruleset misses, not something I caught.

## Escalation summary (if this were a real shift)

| Trigger | My action | Why this point, not earlier/later |
|---|---|---|
| Alert 1 (single RC4 request) | Open case, monitor | One signal, several benign explanations not yet ruled out |
| Alert 2 (pattern + account switch) | Escalate to Tier 2 / IR | Unrecognized IP + account switch is enough on its own, don't need to wait for data access |
| Alert 3 (sensitive file access) | Escalate to lead/manager | Confirmed impact crosses the mandatory-notification threshold |
| Post-incident | Flag LSASS detection gap for tuning | Real ruleset gap, found after the fact — log it, don't bury it |

## What I'd tell my lead in one sentence

"We have a confirmed credential-theft-to-data-access chain from an
external IP, contained to one HR-readable file share, with one ruleset
gap on the credential-theft step we should close before this happens
again."
