#!/usr/bin/env bash
# Duo Agent Trigger Script
# This script triggers the Duo agent to run an investigation via the MCP server.
# It can be called from GitLab CI/CD pipeline.

set -euo pipefail

# Configuration
MCP_SERVER_URL="${MCP_SERVER_URL:-http://localhost:8081}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
GITLAB_PROJECT_ID="${GITLAB_PROJECT_ID:-}"
MCP_AUTH_TOKEN="${MCP_AUTH_TOKEN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Trigger the Duo agent to run an investigation via the MCP server.

Required environment variables:
  GITLAB_TOKEN        - GitLab API token with api scope
  GITLAB_PROJECT_ID   - GitLab project ID or path (e.g., group/project)

Optional environment variables:
  MCP_SERVER_URL      - MCP server URL (default: http://localhost:8081)
  MCP_AUTH_TOKEN      - Optional auth token for MCP server

Options:
  -h, --help          Show this help
  --case-id CASE_ID   Specific case ID to investigate (optional)
  --evidence-path PATH  Evidence path to investigate (optional)
  --profile PROFILE    Investigation profile: devsecops|dfir (default: devsecops)

Examples:
  # Trigger investigation on current repository
  $0

  # Trigger with specific case ID
  $0 --case-id my-case-123

  # Trigger with evidence path
  $0 --evidence-path /path/to/evidence
EOF
}

# Parse arguments
CASE_ID=""
EVIDENCE_PATH=""
PROFILE="devsecops"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        --case-id)
            CASE_ID="$2"
            shift 2
            ;;
        --evidence-path)
            EVIDENCE_PATH="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate required environment variables
if [[ -z "$GITLAB_TOKEN" ]]; then
    log_error "GITLAB_TOKEN environment variable is required"
    exit 1
fi

if [[ -z "$GITLAB_PROJECT_ID" ]]; then
    log_error "GITLAB_PROJECT_ID environment variable is required"
    exit 1
fi

# Validate MCP server is reachable
log_info "Checking MCP server at $MCP_SERVER_URL..."
if ! curl -sf "$MCP_SERVER_URL/health" > /dev/null; then
    log_error "MCP server not reachable at $MCP_SERVER_URL"
    exit 1
fi
log_info "MCP server is healthy"

# Prepare the investigation request
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RUN_ID="ci-run-$(date +%s)-${RANDOM}"

# Build the investigation request payload
INVESTIGATION_PAYLOAD=$(cat <<EOF
{
  "run_id": "$RUN_ID",
  "timestamp": "$TIMESTAMP",
  "profile": "$PROFILE",
  "case_id": "$CASE_ID",
  "evidence_path": "$EVIDENCE_PATH",
  "gitlab": {
    "project_id": "$GITLAB_PROJECT_ID",
    "token": "$GITLAB_TOKEN"
  }
}
EOF
)

log_info "Starting investigation run: $RUN_ID"
log_info "Profile: $PROFILE"
[[ -n "$CASE_ID" ]] && log_info "Case ID: $CASE_ID"
[[ -n "$EVIDENCE_PATH" ]] && log_info "Evidence path: $EVIDENCE_PATH"

# Call the Duo agent via MCP server
# The Duo agent should be configured to listen for investigation requests
# and execute the investigation pipeline via the MCP server

# For now, we'll simulate the Duo agent call by directly invoking the Lade CLI
# In production, this would call the Duo Agent Platform API
log_info "Triggering investigation via Duo agent..."

# Build the lade investigate command
LADE_CMD="lade investigate"
if [[ -n "$EVIDENCE_PATH" ]]; then
    LADE_CMD="$LADE_CMD \"$EVIDENCE_PATH\""
else
    # Use current directory as evidence path
    LADE_CMD="$LADE_CMD \".\""
fi

if [[ -n "$CASE_ID" ]]; then
    LADE_CMD="$LADE_CMD --case-id \"$CASE_ID\""
fi

LADE_CMD="$LADE_CMD --profile $PROFILE"

log_info "Running: $LADE_CMD"

# Execute the investigation
if eval "$LADE_CMD"; then
    log_info "Investigation completed successfully"
    
    # Generate report
    if [[ -n "$CASE_ID" ]]; then
        log_info "Generating report for case $CASE_ID..."
        lade report "$CASE_ID" --db-dir /tmp/lade
    fi
    
    log_info "Investigation run completed successfully: $RUN_ID"
    exit 0
else
    log_error "Investigation failed"
    exit 1
fi