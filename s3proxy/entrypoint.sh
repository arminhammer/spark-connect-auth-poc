#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# entrypoint.sh
#
# 1. If the Overture Maps data directory is empty, download a sample
#    partition from the public S3 bucket using anonymous access.
# 2. Exec into the real s3proxy startup script.
#
# The filesystem layout that jclouds expects:
#   <JCLOUDS_FILESYSTEM_BASEDIR>/<bucket>/<key>
#
# This aligns perfectly with what "aws s3 cp --recursive s3://bucket/key/ dir/"
# produces when you set dir/ = <BASEDIR>/<bucket>/<key>/.
# ---------------------------------------------------------------------------
set -euo pipefail

BUCKET="overturemaps-us-west-2"
S3_PREFIX="release/${OVERTURE_RELEASE}/theme=${OVERTURE_THEME}/type=${OVERTURE_TYPE}"
DATA_DIR="${JCLOUDS_FILESYSTEM_BASEDIR}/${BUCKET}/${S3_PREFIX}"

if [ -z "$(ls -A "${DATA_DIR}" 2>/dev/null)" ]; then
  echo "[s3proxy] No data found at ${DATA_DIR}"
  echo "[s3proxy] Downloading from s3://${BUCKET}/${S3_PREFIX}/ ..."
  mkdir -p "${DATA_DIR}"

  # Download only the first partition file to keep the demo lightweight.
  # Remove the --include filter to pull all partitions (can be several GB).
  aws s3 cp \
    --no-sign-request \
    --recursive \
    "s3://${BUCKET}/${S3_PREFIX}/" \
    "${DATA_DIR}/" \
    --exclude "*" \
    --include "part-00000-*"

  echo "[s3proxy] Download complete — $(du -sh "${DATA_DIR}" | cut -f1) on disk."
else
  echo "[s3proxy] Data already present at ${DATA_DIR} — skipping download."
fi

exec /opt/s3proxy/run-s3proxy.sh