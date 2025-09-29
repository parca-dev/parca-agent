#!/usr/bin/env bash

set -euo pipefail

# Configuration
REPO="parca-dev/opentelemetry-ebpf-profiler"
BRANCH="main"

echo "Fetching latest SHA from ${REPO} on branch ${BRANCH}..."

# Get the latest commit SHA from GitHub API
LATEST_SHA=$(curl -s "https://api.github.com/repos/${REPO}/commits/${BRANCH}" | grep '"sha"' | head -1 | cut -d'"' -f4)

if [ -z "$LATEST_SHA" ]; then
    echo "Error: Failed to fetch latest SHA from GitHub API"
    exit 1
fi

# Truncate SHA to first 12 characters (Go convention for pseudo-versions)
SHORT_SHA="${LATEST_SHA:0:12}"

echo "Latest SHA: ${LATEST_SHA}"
echo "Short SHA: ${SHORT_SHA}"

# Get commit timestamp from GitHub API for pseudo-version
COMMIT_DATE=$(curl -s "https://api.github.com/repos/${REPO}/commits/${LATEST_SHA}" | python3 -c "import sys, json; data = json.load(sys.stdin); print(data['commit']['committer']['date'])")
TIMESTAMP=$(date -d "${COMMIT_DATE}" -u +%Y%m%d%H%M%S)

# Construct the new replace directive
NEW_REPLACE="replace go.opentelemetry.io/ebpf-profiler => github.com/${REPO} v0.0.0-${TIMESTAMP}-${SHORT_SHA}"

echo "New replace directive: ${NEW_REPLACE}"

# Check if go.mod exists
if [ ! -f "go.mod" ]; then
    echo "Error: go.mod not found in current directory"
    exit 1
fi

# Update the replace directive in go.mod
sed -i "s|^replace go.opentelemetry.io/ebpf-profiler.*|${NEW_REPLACE}|" go.mod

echo "Updated go.mod with new replace directive"

# Run go mod tidy to fetch the module and update go.sum
echo "Running go mod tidy..."
go mod tidy

echo "Successfully updated OpenTelemetry eBPF profiler to latest SHA: ${SHORT_SHA}"
echo "Full commit: ${LATEST_SHA}"
