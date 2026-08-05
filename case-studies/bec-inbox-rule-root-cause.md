# Case Study: Business Email Compromise — From Inbox Rule Discovery to Reusable Root-Cause Tooling

**Role:** Security Engineer — Incident Response / Detection Engineering
**Stack:** Microsoft Defender XDR, Microsoft Sentinel, Entra ID, Microsoft Purview (Unified Audit Log), Exchange Online
**ATT&CK Mapping:** T1114.003 — Email Collection: Email Forwarding Rule · T1098 — Account Manipulation · T1556 — Modify Authentication Process

---

## Summary

Responded to a business email compromise where a malicious inbox rule was silently moving incoming replies to the Conversation History folder — a classic technique for hiding reply-chain hijacking from the account owner during payment-fraud or credential-harvesting follow-through. Beyond remediating the immediate account, the investigation was used to build a repeatable, five-vector root-cause methodology and two reusable artifacts (a parameterized investigation notebook and a Sentinel workbook) so future account-compromise cases don't start from a blank page.

## The Trigger

The account had already been suspended and its sessions revoked by the time the investigation began — standard immediate containment. The open question was root cause: how was the account compromised, and what had the attacker done with the access before containment. A malicious inbox rule was already known: it moved specific incoming messages to Conversation History, a folder most users never check, which lets an attacker intercept replies (e.g., to a fraudulent payment redirect) without the victim noticing anything missing from their inbox.

## Investigation Methodology

Rather than investigating ad hoc, the case was structured around five vectors, each with its own evidence trail:

1. **Master timeline reconstruction** — correlating sign-in events, mailbox access, and rule changes into a single chronological view to establish the compromise window
2. **Malicious OAuth consent detection** — checking for illicit consent grants that could provide persistent API-level access independent of the user's password
3. **AiTM / token replay detection** — checking for adversary-in-the-middle session token theft as the initial access vector
4. **MFA fatigue / push-bombing signal** — checking authentication logs for repeated MFA prompts consistent with push-bombing
5. **Inbox/transport rule creation as BEC follow-through** — the rule itself, plus a tenant-wide sweep for similar rules on other mailboxes in case of lateral spread

This framework doubles as a checklist for the next case, not just documentation of this one.

## Detection & Hunting Queries

Beyond the malicious rule itself, four KQL queries were built to establish scope and check for parallel compromise:

- **Tenant-wide inbox rule creation/modification**, parsing `RawEventData.Parameters` as dynamic JSON to extract `MoveToFolder`, `ForwardTo`, `RedirectTo`, and `DeleteMessage` attributes — catching both the known rule and any siblings
- **Mailbox-level forwarding changes** via `Set-Mailbox` events, since `ForwardingSmtpAddress` is a separate persistence mechanism from inbox rules and easy to miss if you only check rules
- **OAuth consent grants**, to rule out illicit consent as a parallel or alternate persistence path
- **Outbound email from the compromised mailbox**, to scope whether the account was used to send further phishing internally or to external parties before containment

One useful finding while building these: empty `RawEventData.Parameters` on older audit events typically indicates a retention/licensing gap, not a query error — worth ruling out before assuming a query bug.

## A Side Investigation: The Case of the Missing Email

During the broader investigation, a related question came up: an email showed as "Delivered" in Threat Explorer but wasn't visible in one recipient's inbox. This mattered because the same mechanism — post-delivery deletion or movement — is exactly what a compromised-account cleanup action looks like.

The troubleshooting path ruled out the usual explanations in order: delivery-verdict vs. actual delivery location, Outlook cached-mode/OST issues, and Focused Inbox — all ruled out once the user confirmed the item wasn't in OWA directly across all folders either. That pointed to the item having been moved or deleted *after* delivery, which standard inbox search doesn't surface.

The resolution was the Unified Audit Log in Purview, filtered for `SoftDelete`, `HardDelete`, `MoveToDeletedItems`, `Move`, and `MailItemsAccessed`, examining the `ClientInfoString` and `ClientProcessName` fields in the `AuditData` JSON to distinguish a manual user action from an automated/app-driven one. This step is also why the audit log — not a live `Get-InboxRule` query — is the authoritative source in BEC cases: a rule created and then deleted by an attacker to cover tracks won't show up in a live rule query, but it will be in the audit log.

## Building Reusable Tooling

Rather than treat this as a one-off, the five-vector methodology was turned into two artifacts for future account-compromise investigations:

- **A parameterized investigation notebook**, so the same five checks can be re-run against a new UPN and time window without rebuilding queries from scratch
- **A Sentinel workbook** covering all five sections plus a fleet-wide IOC hunt, for a visual walkthrough during live IR rather than reading raw KQL output

Building these surfaced a real environment-specific gotcha worth documenting: an early draft used `AADSignInEventsBeta`, a Defender XDR Advanced Hunting table, but the environment's Sentinel workspace only had the native Entra ID `SigninLogs` table — not the Defender XDR beta table. That meant rewriting every sign-in query with corrected column mappings (timestamp, account, error code, user agent, location, and device-trust fields all differ between the two schemas), and re-validating each query individually rather than trusting the full rewrite at once. A smaller schema issue also came up in the timeline query: `tostring(ActivityObjects)` needed to be replaced with the flat `ObjectName`/`ObjectType` columns, and those columns had to be explicitly added to an upstream `project` statement — `project` acts as a strict allowlist, unlike `extend`, so a column can silently disappear downstream if it's not named there.

## Outcome

- Confirmed the malicious inbox rule as the primary persistence/interception mechanism and removed it as part of remediation
- Ruled out illicit OAuth consent and forwarding-based persistence as parallel compromise paths through the four-query sweep
- Established a defensible root-cause timeline using the Unified Audit Log rather than inference from symptoms
- Converted a single incident response into two reusable artifacts (notebook + Sentinel workbook), reducing the time-to-first-query for the next account compromise investigation

## Lessons Learned

1. **A "Delivered" verdict in Threat Explorer isn't the end of the story.** It reflects delivery, not final state — post-delivery moves or deletions (including attacker cleanup) require the Unified Audit Log, not the mail-flow trace, to see.
2. **Deleted artifacts still leave a trail.** An inbox rule an attacker creates and then deletes to cover tracks won't appear in a live `Get-InboxRule` query, but will appear in the audit log — the audit log, not the current-state query, is the authoritative source in BEC cases.
3. **Don't assume schema parity between similar-sounding tables.** `AADSignInEventsBeta` and `SigninLogs` cover similar data but aren't interchangeable — column names, types (including string-typed error codes needing quoted comparisons), and nesting all differ. Validate against the actual workspace rather than the most familiar schema.
4. **`project` is a strict allowlist; `extend` isn't.** A field computed upstream can silently vanish from results if it's not also named in a later `project` — an easy, quiet bug in multi-stage KQL.
5. **Turn one-off investigations into reusable methodology.** A five-vector root-cause framework, encoded as a parameterized notebook and a workbook, means the next compromise investigation starts from a checklist and working queries instead of a blank page.

---

*Investigation and tooling built using Microsoft Sentinel, Defender XDR, and Microsoft Purview during an active incident response engagement. Account identifiers, real UPNs, and organizational details have been omitted or genericized.*
