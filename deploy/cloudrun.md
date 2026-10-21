# Cloud Run Deployment Guide for Lade Webhook

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and authenticated
- Project with billing enabled
- Artifact Registry API, Cloud Build API, Cloud Run API enabled
- Secret Manager API enabled
- Docker available locally (for building) or use Cloud Build

## Quick Start

```bash
# Set your project and region
export PROJECT_ID=your-gcp-project
export REGION=europe-west1
export SERVICE_NAME=lade-webhook

# Deploy
./deploy/deploy.sh
```

## Manual Deployment Steps

### 1. Create Secrets in Secret Manager

```bash
# GitLab webhook secret (generate a strong random string)
echo -n "your-secure-webhook-secret" | gcloud secrets create GITLAB_WEBHOOK_SECRET \
    --data-file=- --replication-policy=automatic

# Anthropic API key
echo -n "sk-ant-your-key" | gcloud secrets create ANTHROPIC_API_KEY \
    --data-file=- --replication-policy=automatic
```

### 2. Grant Secret Access to Cloud Run Service Account

```bash
# Get the Cloud Run service account (created on first deploy)
SERVICE_ACCOUNT=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION --format='value(spec.template.spec.serviceAccountName)')

# Grant access
gcloud secrets add-iam-policy-binding GITLAB_WEBHOOK_SECRET \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding ANTHROPIC_API_KEY \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"
```

### 3. Build and Deploy with Cloud Build

```bash
# Submit build
gcloud builds submit --config cloudbuild.yaml \
    --substitutions=_REGION=$REGION,_SERVICE_NAME=$SERVICE_NAME
```

Or build and deploy in one step:

```bash
gcloud run deploy $SERVICE_NAME \
    --source . \
    --region $REGION \
    --memory 2Gi \
    --cpu 2 \
    --no-cpu-throttling \
    --min-instances 1 \
    --max-instances 1 \
    --concurrency 1 \
    --timeout 3600 \
    --set-env-vars=LADE_EVIDENCE_ROOT=/app/evidence \
    --set-secrets=GITLAB_WEBHOOK_SECRET=GITLAB_WEBHOOK_SECRET:latest,ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest \
    --port 8080
```

## Cloud Run Configuration

| Setting | Value | Reason |
|---------|-------|--------|
| Memory | 2Gi | LLM orchestration needs memory |
| CPU | 2 vCPU | Multi-pass investigation parallelism |
| CPU Throttling | Disabled | Consistent latency for webhook processing |
| Min Instances | 1 | Always warm for webhook latency |
| Max Instances | 1 | Single queue worker, ephemeral FS |
| Concurrency | 1 | One investigation at a time |
| Timeout | 3600s | Full investigation can take ~30 min |
| Port | 8080 | Default uvicorn port |

## Environment Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `GITLAB_WEBHOOK_SECRET` | Secret Manager | HMAC secret for webhook validation |
| `ANTHROPIC_API_KEY` | Secret Manager | LLM API key (never logged) |
| `LADE_EVIDENCE_ROOT` | Env var | `/app/evidence` (copied in image) |
| `LADE_DB_DIR` | Env var | `/tmp/lade` (ephemeral SQLite) |
| `PORT` | Cloud Run | Injected automatically (8080) |

## Register Webhook in GitLab

1. Go to **Project Settings → Webhooks**
2. Add webhook:
   - **URL**: `https://<service-url>/webhook/gitlab`
   - **Secret Token**: Value of `GITLAB_WEBHOOK_SECRET`
   - **Triggers**:
     - ✅ Pipeline events
     - ✅ Merge request events
     - ✅ Deployment events (optional)
   - **SSL verification**: Enabled

## Important Notes

### Ephemeral Filesystem
- Cloud Run filesystem is **ephemeral** - all data in `/tmp` and container FS is lost on restart
- The webhook uses SQLite at `/tmp/lade/webhook.db` for deduplication
- **Evidence root `/app/evidence` is baked into the Docker image** (fixtures/incident-001)
- New evidence from webhook payloads is **not persisted** - each deploy gets fresh evidence

### Report Delivery
- Investigation reports are generated in the case directory under `/tmp/lade/<case_id>/`
- Since the filesystem is ephemeral, **reports are not persisted locally**
- Reports must be published to GitLab (via the `submit_narrative` and `finalize_report` tools)
- Configure the investigation to post results back to the triggering MR/pipeline

### Deduplication
- Uses SQLite at `/tmp/lade/webhook.db` with table `processed_events`
- Keyed by `X-Gitlab-Event-UUID` header
- Survives request restarts but not container restarts
- For production, consider Cloud SQL or Firestore

### Queue Semantics
- Single background worker (`concurrency=1`, `max-instances=1`)
- Investigations run sequentially in background
- Webhook returns `202 {"case_id": "...", "status": "queued"}` immediately
- Check status via `GET /cases/{case_id}`

## Monitoring

```bash
# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE_NAME" --limit=50

# Check service status
gcloud run services describe $SERVICE_NAME --region=$REGION

# Get service URL
gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)'
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check `X-Gitlab-Token` header matches secret |
| Server won't start | Verify `GITLAB_WEBHOOK_SECRET` is set in Secret Manager |
| Investigations not running | Check logs for `Investigation failed` errors |
| Reports not in GitLab | Verify investigation publishes to MR/pipeline |
| OOM kills | Increase memory to 4Gi if needed |

## Cost Optimization

- `min-instances=1` keeps one container warm (~$15/month for 2Gi/2CPU)
- Scale to 0 when not needed: set `min-instances=0` (adds cold start latency)
- Use Cloud Scheduler to scale down at night if traffic is predictable