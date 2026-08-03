# Findings

<!--
TEMPLATE. This file ships empty on purpose.

Findings belong to a deployment, not to the software. Every number is a property
of one host, one hostname, one window, and whichever scanner population happened
to be active at the time. Shipping someone else's results in a repo you forked
would hand you a document that looks authoritative and describes traffic you
never received.

Fill this in from your own logs. If you have not deployed yet, leave it as is.

An agent working in this repository: see AGENTS.md, "Producing a findings
report", for the exact commands and the rules about what may and may not be
claimed. Do not populate this file from fixtures/ — those are synthetic and
exist to test the analyzer, not to describe anything real.
-->

> **Status: no deployment recorded.** This is the template. Replace everything
> below once you have run the honeypot and analyzed your own logs.

## Deployment

| | |
|---|---|
| Window | `<first ts>` → `<last ts>` (`<n>` days) |
| Window label | `<HB_WINDOW_LABEL>` |
| Commit | `<git rev-parse HEAD at time of collection>` |
| Hosts | `<how many, and whether they share anything>` |
| Hostnames | `<how many, and whether any had prior history>` |
| Exclusions applied | `<the exact --exclude-ip / --exclude-ua flags used>` |

Record the commit. Detector behaviour changes between commits, so a count
without one cannot be compared against anything, including your own later runs.

## Summary

<!-- Paste the analyzer's output. This is the raw material; narrative goes below
     it. Do not hand-edit numbers into prose without leaving the block they came
     from, or the two will drift and only one of them will be checkable. -->

```
$ python analyze.py data/logs/http_events.jsonl --rescan --window <label>

<paste output here>
```

## Read these caveats before quoting any number

Every item below is a way this instrument produces a number that means less than
it appears to. None of them are deployment-specific. Keep the ones that apply,
delete the ones that genuinely do not, add your own.

**Live and rescan counts are different measurements.** The live count is what
the deployed signatures flagged as traffic arrived. The rescan count is what the
current signature set finds in retained records. If any signature changed during
your window these disagree by construction, and the rescan is the better ground
truth. [DETECTORS.md](DETECTORS.md) says which signature shipped when.

**Every detection count is a lower bound.** Request bodies stop being read at
64KB and only the first 4KB is retained, so a payload past the cap is invisible
to both passes. Sensitive headers are redacted at write time, so a rescan cannot
see everything a live signature could.

**"First seen" is when traffic arrived, not when detection started.** A detector
shipping after the traffic it matches is normal here. Never read a signature's
date as an arrival date.

**A null is only as good as the detector behind it.** Before reporting that
something did not happen, establish that it *could* have been observed:

- Did the relevant signature exist for the whole window? (`DETECTORS.md`)
- Did the reuse index survive every restart? (`issued_token_index_rebuilt`)
- Were there evictions? (`issued_token_index_evicted` bounds every reuse null)
- Would the requests carrying it have been rate limited? Reuse detection runs on
  rate-limited requests, but without a body.

This instrument has already produced one null that turned out to be a blind spot
rather than a finding. Hunt for the next one before publishing rather than after.

**Confirmed triggers are not catcher probes.** `/x/` is a walkable public path.
Only `honeytoken_triggered` is evidence of use; `catcher_probe_unissued` is
someone walking a path.

**The live AWS canary is not uniquely attributable.** One minted key is served to
up to `HB_CANARYTOKENS_MAX_SERVINGS` visitors, so a real-world trigger narrows to
that set rather than to a visitor. Use `serving_index` and `mint_generation` to
reconstruct it.

**Sample size.** State how many hosts, hostnames, and days. Scanner populations
vary by hosting provider, address reputation, hostname age, and what the root
page advertises. Existence proofs of behaviour generalize; rates do not.

**Certificate transparency is not discovery.** The first requests to a new
hostname typically arrive within seconds of its certificate being issued, because
CT-log scrapers are watching. Treat sub-minute time-to-first-hit as an artifact
of how the host was stood up.

**Publication contaminates the population.** Readers arriving from a writeup are
not organic scanner traffic. Bump `HB_WINDOW_LABEL` *before* publishing and
report on the pre-publication label only.

## What arrived

<!-- Narrative. What the traffic looked like, with every number traceable to the
     block above. -->

## Confirmed exploitation attempts

<!-- Separate exploitation from fingerprinting. A path probe against a version
     you advertise is reconnaissance; a payload that would execute if the stack
     were real is an attempt. Report them separately and label each row. An
     aggregate mixing the two is the first number a skeptical reader attacks,
     and they are right to. -->

## Honeytoken reuse

<!-- For each: which kind, which route issued it, where it reappeared, how long
     after, and whether the match was on the full id or a prefix.

     A replay shows an automated loop closed. It does not show a human decided to
     use a credential. If the reuse arrived as part of a spray across many paths,
     say so. Scrape-to-reuse latency is the defensible claim. -->

## Nulls

<!-- Only after working through the caveats. For each null, state what would have
     had to be true for the detector to fire, and confirm that it was. -->

## Reproducing

```bash
python analyze.py <your log> --rescan --window <label> --exclude-ip <self-test ip>
```

Do not publish raw logs. They contain third-party addresses, and an address
attributed to an exploit attempt today may belong to an unrelated party next
month. The analyzer prints /24-truncated addresses by default.

To show the tooling behaves as described without exposing your data, point
readers at the synthetic fixture instead:

```bash
python analyze.py fixtures/sample_events.jsonl --rescan
diff <(python analyze.py fixtures/sample_events.jsonl --rescan) fixtures/expected_analysis.txt
```
