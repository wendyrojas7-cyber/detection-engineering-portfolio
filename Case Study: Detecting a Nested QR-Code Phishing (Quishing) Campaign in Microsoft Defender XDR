# Case Study: Detecting a Nested QR-Code Phishing (Quishing) Campaign in Microsoft Defender XDR

**Role:** Security Engineer — Detection Engineering
**Stack:** Microsoft Defender XDR (Advanced Hunting / Custom Detections), Sentinel, Exchange Online
**ATT&CK Mapping:** T1566.001 — Phishing: Spearphishing Attachment

---

## Summary

Attackers ran an active phishing campaign using HR/benefits-themed lures (e.g., "Benefits Update," "Pay Increase") that delivered a malicious QR code hidden two layers deep: an outer email carrying a nested `.eml` attachment, whose body contained a PDF image with the QR code embedded inside. Because each layer of nesting strips visibility from Defender for Office 365's Safe Attachments/Safe Links detonation, the payload was effectively invisible to native QR-decoding controls. I built and iterated a custom detection rule in Defender XDR to close that blind spot, then extended it in real time as the campaign evolved.

## The Problem

Standard quishing defenses (Safe Links time-of-click protection, native QR decoding in Defender for Office 365) work by decoding a QR image and evaluating the extracted URL. That pipeline assumes the QR code is directly visible to the scanning engine. In this campaign, the attacker nested the payload inside a `.eml` attachment — an email within an email — so the QR-bearing PDF never reached the layer of inspection that decodes QR content. This is a known architectural blind spot in nested-object scanning, not a signature-evasion trick, which meant no amount of tuning existing native controls would close it. A new, purpose-built detection was needed.

## Hunt & Build Process

**Initial hypothesis:** flag external-sender emails carrying `.eml` attachments where the nested content shows no extracted URLs in `EmailUrlInfo` (a proxy for "this attachment isn't being decoded upstream"), combined with subject-line social-engineering keywords.

**First build attempt failed silently.** A query anchored on `EmailAttachmentInfo` with `FileType == "eml"` returned zero results, despite confirmed live samples in the environment. Debugging traced this to two separate issues:

1. **Schema mismatch:** Defender XDR classified the nested attachment with a *compound* `FileType` value (`eml;mime`), not a clean `eml` string — so an exact-match filter silently failed. Switching to `has` resolved it.
2. **Anchor table mattered for response actions:** Anchoring the custom detection rule on `EmailAttachmentInfo` meant the rule wizard didn't expose the Email response-action category at all. Re-anchoring the query on `EmailEvents` (joining in `EmailAttachmentInfo`) surfaced the correct action set, likely compounded by scoped RBAC permissions that excluded direct email remediation rights.

**Final rule design** (v1):
- Anchored on `EmailEvents`, joined to `EmailAttachmentInfo`
- `FileType has "eml"` (not `==`, to survive compound type values)
- `FileName has_any` against the known lure-keyword set
- Explicit `Timestamp > ago(30d)` on both sides of the join, rather than relying on the Advanced Hunting UI time picker, for portability and reproducibility
- Runs hourly; fires a High-severity alert (category: Phishing) **and** an automated Files → Block action on the SHA256 hash in the same rule

This combined an always-on alert with an automated, reactive per-variant block — reactive because the block targets a known hash after ingestion, not a pre-delivery control, but still meaningfully reduced dwell time given the person building the rule did not hold Exchange transport-rule or email-remediation permissions (those sat with a separate team).

## Campaign Evolution & Detection Iteration

Within days, the attacker pivoted delivery from `.eml` attachments to similarly-named `.pdf` attachments carrying the same lure subject lines — while native QR scanning continued to catch and quarantine a portion of the traffic, confirming the custom rule's role as a backstop rather than the primary control. The detection was updated by widening the file-type filter from `eml`-only to `FileType in ("eml", "pdf")`, keeping the filename-keyword match as the durable anchor since the subject-line lure pattern stayed constant across the pivot. The corresponding Exchange transport rule (owned by a separate team) was updated in parallel to append PDF wildcard patterns alongside the existing EML patterns, rather than replacing them — preserving detection continuity for both variants.

## Outcome

- Closed a detection gap that native Safe Links/Safe Attachments QR decoding structurally could not cover (nested-object blind spot)
- Delivered an automated response (SHA256 block) despite not holding the permissions typically required for email remediation, by choosing the correct anchor table for the rule wizard
- Detection survived a mid-campaign attacker pivot (EML → PDF) with a single filter change, because the durable IOC (filename/subject pattern) was identified and anchored on up front rather than the more brittle file-type signal
- Fed learnings back into the transport-rule layer maintained by the email security team, closing the loop between detection engineering and preventive control

## Lessons Learned

1. **Don't trust exact-match filters against vendor-classified fields without checking real sample values first.** `FileType == "eml"` vs. `FileType has "eml"` was the difference between zero results and a working rule — Defender XDR's schema uses compound values that aren't always documented.
2. **Anchor table choice isn't just a performance decision — it changes what response actions are even available in the rule wizard**, independent of RBAC. Validate this before investing time in query logic.
3. **Identify the durable IOC before the brittle one.** File type changed (EML → PDF); the filename/subject lure pattern didn't. Anchoring detection logic on what's likely to survive attacker iteration meant a one-line fix kept pace with the campaign instead of a rebuild.
4. **A custom detection doesn't need to replace native controls — its value is in covering exactly what they structurally can't see.** Framing this as a backstop (not a replacement for Safe Links/Safe Attachments) kept scope tight and avoided duplicate alerting.

---

*Detection built and iterated in Microsoft Defender XDR Advanced Hunting during an active incident response engagement. Lure keywords and campaign details are illustrative of the pattern observed; specific IOCs, hashes, and organizational identifiers have been omitted.*
