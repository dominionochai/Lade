# incident-001: orders-api memory leak after merge (SYNTHETIC DEMO DATA)

All data here is synthetic, made for the Lade demo. Package names (streamcache,
yamlforge), the CVE IDs (CVE-2026-9000x) and the project are invented.

Story: MR !482 (merged 2026-10-09 13:02 UTC) bumps `streamcache` 2.3.4 -> 2.4.1
and adds an /export endpoint. The pipeline passes (Trivy job is allow_failure).
Cloud Run staging revision orders-api-00042-kqz then climbs in memory until the
512 MiB limit kills the instance at ~14:07 UTC.

Layout: pipeline/ (GitLab CI config + job traces), git/ (MR diff),
scans/ (Trivy image scan, dependency diff), cloudrun/ (Cloud Logging JSONL,
per-minute metrics), runtime/ (heap allocation trace), infra/ (GCP status),
expected/ (answer key: DO NOT show to the agents; used to grade Phase 4).
