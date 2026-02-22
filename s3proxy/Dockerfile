FROM andrewgaul/s3proxy

# Install AWS CLI so we can download Overture Maps data on first start.
# RUN apt-get update -qq && \
#     apt-get install -y --no-install-recommends awscli && \
#     rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Frontend credentials — what Spark presents when it reads from s3a://
# These are the credentials your mock STS service should return.
# ---------------------------------------------------------------------------
ENV S3PROXY_AUTHORIZATION=aws-v2-or-v4
ENV S3PROXY_IDENTITY=test-access-key-id
ENV S3PROXY_CREDENTIAL=test-secret-access-key
ENV S3PROXY_ENDPOINT=http://0.0.0.0:8080

# ---------------------------------------------------------------------------
# Backend — filesystem; each bucket is a subdirectory of BASEDIR.
# ---------------------------------------------------------------------------
ENV JCLOUDS_PROVIDER=filesystem
ENV JCLOUDS_FILESYSTEM_BASEDIR=/data

# ---------------------------------------------------------------------------
# Overture Maps dataset to download (override via docker-compose env / -e)
# ---------------------------------------------------------------------------
ENV OVERTURE_RELEASE=2026-02-18.0
ENV OVERTURE_THEME=base
ENV OVERTURE_TYPE=infrastructure

# Mount point for persisting downloaded data across restarts
VOLUME ["/data"]

# COPY entrypoint.sh /entrypoint.sh
# RUN chmod +x /entrypoint.sh

EXPOSE 8080

# Replace the base image entrypoint with our wrapper, which downloads data
# if absent, then execs the original s3proxy startup script.
# ENTRYPOINT ["/entrypoint.sh"]
