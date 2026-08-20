# Agent Note: Harvest hostnames from tshark name-service summaries

Status: implemented

English | [中文](2026-08-20-harvest-hostname-from-tshark-summaries.zh.md)

## Problem

`harvestIdentities` recorded hostname only from labeled keys (`hostname|host|nbns.name|dns.qry.name := value`). A default `pcap_filter` dump already named the workstation in tshark Info text, never as those labels: `LLMNR Standard query ANY DESKTOP-TEYQ2NR`, `NBNS Registration NB DESKTOP-TEYQ2NR<00>` / `<20>`, `BROWSER Request Announcement DESKTOP-TEYQ2NR`, and `BROWSER Host Announcement DESKTOP-TEYQ2NR`. The identity ledger therefore omitted hostname, and `case_report` `where` could only state IP and MAC. The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) already persists harvested identities; this gap is the hostname parser, not the ledger.

## Decision

`harvestIdentities` also persists `kind: hostname` from NBNS, BROWSER, SMB, and LLMNR tshark summary forms. DESKTOP-* NetBIOS names and Host Announcement names land. Workgroup and domain tokens distinguished as `Domain/Workgroup Announcement`, `Local Master Announcement`, or NBNS suffixes `<1b>`–`<1e>` are not recorded as hostname, so a token such as `EASYAS123` is omitted even when the same dump also carries `EASYAS123<00>` or a Request Announcement of that name. IP, MAC, user, and full_name harvest are unchanged. Labeled hostname keys still win first-seen order.

## Alternatives considered

**Require `-e nbns.name` or `dns.qry.name` on every `pcap_filter` call.** Rejected because the live dump already contained the hostname in default summaries. A field-only parser leaves those runs without a hostname identity.

**Harvest every NetBIOS-like token.** Rejected because workgroup and domain names such as `EASYAS123` would be recorded as hostname.

**Clone scout or Beldum harvest.** Rejected: those trees are out of scope, and this repo forbids leaking or copying that source.

**Add malware-family harvest or a new eval in the same change.** Rejected: those are separate knobs from hostname persistence.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` feeds the Easy as 123 tshark summary lines plus workgroup forms. `harvestIdentities` must yield normalized hostname `desktop-teyq2nr` and must not yield `easyas123`. Adjacent IP `10.2.28.88`, MAC `00:19:d1:b2:4d:ad`, user `brolf`, and full name `Becka Rolf` stay harvested.

## Consequences

The identity ledger can include hostname after a summary-only `pcap_filter` dump, so `where` can name the workstation. Unusual tshark phrasings outside the named NBNS, BROWSER, SMB, and LLMNR host forms are still omitted. A name that is both a workgroup token and a Host Announcement is treated as workgroup and dropped.
