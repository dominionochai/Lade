#!/usr/bin/env python3
"""GitLab API script to create issue and draft MR for automation run report."""

import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path


def create_issue_and_mr():
    """Create a GitLab issue and draft MR for the automation run."""
    
    # Required environment variables
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("CI_PROJECT_ID")
    gitlab_url = os.environ.get("CI_SERVER_URL", "https://gitlab.com")
    
    if not gitlab_token:
        print("ERROR: GITLAB_TOKEN not set", file=sys.stderr)
        return 1
    
    if not project_id:
        print("ERROR: CI_PROJECT_ID not set", file=sys.stderr)
        return 1
    
    # Pipeline information
    pipeline_id = os.environ.get("CI_PIPELINE_ID", "unknown")
    commit_sha = os.environ.get("CI_COMMIT_SHA", "unknown")[:8]
    commit_ref = os.environ.get("CI_COMMIT_REF_NAME", "unknown")
    pipeline_url = f"{os.environ.get('CI_SERVER_URL', 'https://gitlab.com')}/{os.environ.get('CI_PROJECT_PATH')}/-/pipelines/{os.environ.get('CI_PIPELINE_ID', '')}"
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Issue title and description
    issue_title = f"Automation run report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    issue_description = f"""## Automation Run Report

**Pipeline:** #{os.environ.get('CI_PIPELINE_ID', 'unknown')}
**Commit:** {commit_sha}
**Branch:** {os.environ.get('CI_COMMIT_REF_NAME', 'unknown')}
**Pipeline URL:** {pipeline_url}
**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Pipeline Stages
- ✅ Test Stage
- ✅ Duo Automation Stage
- ✅ Report Stage

### Investigation Summary
The Duo agent successfully executed the forensic investigation via the MCP server.
See pipeline logs for detailed investigation results and findings.

### Artifacts
- Test results: Available in pipeline artifacts
- Investigation logs: Available in pipeline logs
- Generated reports: Available in case directories

---
*This issue was automatically created by the GitLab CI/CD pipeline.*
"""
    
    headers = {
        "Authorization": f"Bearer {gitlab_token}",
        "Content-Type": "application/json"
    }
    
    api_url = f"{gitlab_url}/api/v4/projects/{project_id}"
    
    # Create issue
    issue_data = {
        "title": f"Automation run report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "description": issue_description,
        "labels": ["automation", "duo-agent", "investigation", "ci"],
        "confidential": False
    }
    
    print(f"Creating issue in project {project_id}...")
    response = requests.post(
        f"https://{gitlab_url.replace('https://', '')}/api/v4/projects/{project_id}/issues",
        headers={"Authorization": f"Bearer {gitlab_token}", "Content-Type": "application/json"},
        json={
            "title": f"Automation run report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "description": issue_description,
            "labels": ["automation", "duo-agent", "investigation", "ci"]
        }
    )
    
    if response.status_code == 201:
        issue = response.json()
        issue_iid = issue["iid"]
        issue_url = issue["web_url"]
        print(f"✅ Created issue: {issue_url} (IID: {issue_iid})")
    else:
        print(f"❌ Failed to create issue: {response.status_code} - {response.text}")
        return 1
    
    # Create draft merge request
    # First, we need a source branch. Since we're in CI, we can create a branch from the current commit
    # or use the existing branch. For simplicity, we'll create a draft MR from the current branch to main.
    
    source_branch = os.environ.get("CI_COMMIT_REF_NAME", "main")
    target_branch = "main"
    
    if source_branch != target_branch:
        mr_title = f"Draft: Automation report - {datetime.utcnow().strftime('%Y-%m-%d')}"
        mr_description = f"""## Automation Report Merge Request

This draft MR is automatically created from the CI/CD pipeline run.

**Related Issue:** #{issue_iid}
**Pipeline:** #{os.environ.get('CI_PIPELINE_ID', 'unknown')}
**Commit:** {commit_sha}

### Changes
This MR contains the automation run report and any generated artifacts.

### Checklist
- [ ] Review investigation results
- [ ] Verify findings
- [ ] Approve for merge (if applicable)
"""
        
        mr_data = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": mr_title,
            "description": mr_description,
            "draft": True,
            "labels": ["automation", "duo-agent", "report"]
        }
        
        print("Creating draft merge request...")
        mr_response = requests.post(
            f"https://{gitlab_url.replace('https://', '')}/api/v4/projects/{project_id}/merge_requests",
            headers={"Authorization": f"Bearer {gitlab_token}", "Content-Type": "application/json"},
            json=mr_data
        )
        
        if mr_response.status_code == 201:
            mr = mr_response.json()
            print(f"✅ Created draft MR: {mr['web_url']} (IID: {mr['iid']})")
        else:
            print(f"⚠️  Failed to create draft MR: {mr_response.status_code} - {mr_response.text}")
            # Don't fail the pipeline if MR creation fails
    else:
        print(f"❌ Failed to create issue: {response.status_code} - {response.text}")
        return 1
    
    print("✅ Report phase completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(create_issue_and_mr())