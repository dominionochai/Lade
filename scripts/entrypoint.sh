#!/usr/bin/env bash
set -e

LADE_HOME="/home/lade"
LADE_CONFIG="$LADE_HOME/.config"
mkdir -p "$LADE_CONFIG"

# Copy mounted credential files to a lade-accessible location so the
# non-root user can read them without modifying host file permissions.
if [ -f /tmp/gcloud-creds.json ]; then
    cp /tmp/gcloud-creds.json "$LADE_CONFIG/gcloud-creds.json"
    chown lade:lade "$LADE_CONFIG/gcloud-creds.json"
    export GOOGLE_APPLICATION_CREDENTIALS="$LADE_CONFIG/gcloud-creds.json"
fi

chown -R lade:lade "$LADE_CONFIG" 2>/dev/null || true
chown -R lade:lade "$LADE_HOME/.lade" 2>/dev/null || true
# Ensure the cases directory is writable (may be a bind mount from host)
chmod -R a+rwX "$LADE_HOME/.lade/cases" 2>/dev/null || true

exec gosu lade "$@"
