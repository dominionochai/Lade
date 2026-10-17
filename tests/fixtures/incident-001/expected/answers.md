# Expected Answers (DO NOT READ)

This file holds the answer key for incident-001.
Tools must refuse to read it.

trivy_report: CVE-2026-90001, streamcache, HIGH
dependency_diff: streamcache 2.3.4 -> 2.4.1
ci_job_log: passed with warnings
git_diff: FILE app/routes/export.py
cloud_logs: Memory limit of 512 MiB exceeded
memory_metrics: slope 6.0
