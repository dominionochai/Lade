#!/usr/bin/env bash
# Cloud Run deployment script for Lade webhook
# Usage: ./deploy.sh [project-id] [region] [service-name]

set -euo pipefail

PROJECT_ID="${1:-${GOOGLE_CLOUD_PROJECT:-}}"
REGION="${2:-europe-west1}"
SERVICE_NAME="${3:-lade-webhook}"

if [[ -z "$PROJECT_ID" ]]; then
    echo "Usage: $0 <project-id> [region] [service-name]"
    echo "  project-id: GCP project ID (or set GOOGLE_CLOUD_PROJECT)"
    echo "  region: GCP region (default: europe-west1)"
    echo "  service-name: Cloud Run service name (default: lade-webhook)"
    exit 1
fi

echo "=== Lade Webhook Cloud Run Deployment ==="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo

# Check prerequisites
for cmd in gcloud docker; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found in PATH"
        exit 1
    fi
done

# Enable required APIs
echo "Enabling required APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    --project="$PROJECT_ID"

# Create Artifact Registry repository if needed
REPO_NAME="lade-docker"
if ! gcloud artifacts repositories describe "$REPO_NAME" \
    --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
    echo "Creating Artifact Registry repository..."
    gcloud artifacts repositories create "$REPO_NAME" \
        --repository-format=docker \
        --location="$REGION" \
        --project="$PROJECT_ID"
fi

# Check/create secrets
echo "Checking secrets..."
for secret in GITLAB_WEBHOOK_SECRET ANTHROPIC_API_KEY; do
    if ! gcloud secrets describe "$secret" --project="$PROJECT_ID" &>/dev/null; then
        echo "Secret $secret not found. Creating placeholder..."
        echo "CHANGE_ME" | gcloud secrets create "$secret" \
            --data-file=- --replication-policy=automatic \
            --project="$PROJECT_ID"
        echo "WARNING: Update secret '$secret' in Secret Manager with real value!"
    fi
done

# Build and deploy using Cloud Build
echo "Building and deploying with Cloud Build..."
cat > /tmp/cloudbuild.yaml <<EOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - '\${_REGION}-docker.pkg.dev/\$PROJECT_ID/lade-docker/\${_SERVICE_NAME}:\$COMMIT_SHA'
      - '-f'
      - 'Dockerfile.cloudrun'
      - '.'
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'push'
      - '\${_REGION}-docker.pkg.dev/\$PROJECT_ID/lade-docker/\${_SERVICE_NAME}:\$COMMIT_SHA'
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: 'gcloud'
    args:
      - 'run'
      - 'deploy'
      - '\${_SERVICE_NAME}'
      - '--image'
      - '\${_REGION}-docker.pkg.dev/\$PROJECT_ID/lade-docker/\${_SERVICE_NAME}:\$COMMIT_SHA'
      - '--region'
      - '\${_REGION}'
      - '--memory'
      - '2Gi'
      - '--cpu'
      - '2'
      - '--no-cpu-throttling'
      - '--min-instances'
      - '1'
      - '--max-instances'
      - '1'
      - '--concurrency'
      - '1'
      - '--timeout'
      - '3600'
      - '--port'
      - '8080'
      - '--set-env-vars'
      - 'LADE_EVIDENCE_ROOT=/app/evidence'
      - '--set-secrets'
      - 'GITLAB_WEBHOOK_SECRET=GITLAB_WEBHOOK_SECRET:latest,ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest'
      - '--service-account'
      - '\${_SERVICE_NAME}@\$PROJECT_ID.iam.gserviceaccount.com'
      - '--project'
      - '\$PROJECT_ID'
      - '--quiet'
substitutions:
  _REGION: '$REGION'
  _SERVICE_NAME: '$SERVICE_NAME'
options:
  logging: CLOUD_LOGGING_ONLY
EOF

gcloud builds submit \
    --config=/tmp/cloudbuild.yaml \
    --substitutions=_REGION="$REGION",_SERVICE_NAME="$SERVICE_NAME" \
    --project="$PROJECT_ID"

# Get service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format='value(status.url)')

echo
echo "=== Deployment Complete ==="
echo "Service URL: $SERVICE_URL"
echo
echo "Next steps:"
echo "1. Update secrets in Secret Manager with real values:"
echo "   gcloud secrets versions add GITLAB_WEBHOOK_SECRET --data-file=- --project=$PROJECT_ID"
echo "   gcloud secrets versions add ANTHROPIC_API_KEY --data-file=- --project=$PROJECT_ID"
echo
echo "2. Register webhook in GitLab:"
echo "   URL: $SERVICE_URL/webhook/gitlab"
echo "   Secret Token: (value of GITLAB_WEBHOOK_SECRET)"
echo "   Triggers: Pipeline events, Merge request events"
echo
echo "3. Test deployment:"
echo "   curl $SERVICE_URL/healthz"
echo
echo "Note: Evidence root is /app/evidence (baked into image)."
echo "Filesystem is ephemeral - reports are published to GitLab, not persisted locally."