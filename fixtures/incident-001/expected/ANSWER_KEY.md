# Answer key (do not give to the agents)

Primary hypothesis (should be supported): the dependency bump streamcache 2.3.4 -> 2.4.1
removed the default 10000-entry cap (CVE-2026-90001 / release notes); the new /export
route stores a payload under a unique key per request, so the unbounded cache grows
with every request until the 512 MiB limit is hit at ~14:07 UTC.

Competing hypotheses Phase 4 must test:
H1 GCP resource exhaustion / noisy neighbor: REFUTED. No incident on status page; the
  previous revision ran 24h flat at ~190 MiB on the same infrastructure; the second
  instance (0070c4, 13:44-13:52) also started low (~192 MiB) and grew only ~1.1 MiB/min
  (8.5 MiB over 8 min), much slower than the primary.
 H2 Traffic spike: REFUTED. Requests/sec on the primary instance stayed in a narrow 9-15 band
   throughout; memory growth is linear and matches cache entry count, not request rate changes.
 H3 Cold-start / startup-probe issue at 13:46: REAL but UNRELATED. 11.2s probe delay on
    the short-lived instance; no memory effect.
 H4 yamlforge CVE-2026-90002: REAL finding, NOT the cause. No untrusted YAML parsing in
    the failing path; heap trace shows 0.9 MiB for yamlforge.

Expected classification: CWE-770 (allocation without limits), CWE-401 (memory not
released). ATT&CK: no adversary activity is evidenced. If mapped, only as potential
impact T1499 (Endpoint Denial of Service), stated as non-malicious / accidental.
The report should say uncertainty remains about how much of the growth is the new
route versus the changed default (the diff shows both), and should not claim more.

Remediation MR: pin streamcache>=2.4.3 AND set max_entries=10000 explicitly in
app/cache.py; change /export to avoid unique-key caching (or add a TTL-bound key).
