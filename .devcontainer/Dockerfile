FROM apache/sedona:1.8.1

USER root

# The Sedona JupyterLab image installs Python via conda; put it on root's PATH
ENV PATH=/opt/conda/bin:$PATH

# Install build tools and dev utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
        maven \
        git \
        curl \
        wget \
        less \
        procps \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install SBT
ARG SBT_VERSION=1.10.7
RUN curl -fL "https://github.com/sbt/sbt/releases/download/v${SBT_VERSION}/sbt-${SBT_VERSION}.tgz" \
        | tar xz -C /usr/local \
    && ln -s /usr/local/sbt/bin/sbt /usr/local/bin/sbt

# Pre-warm SBT's launcher (downloads the launcher on first run)
RUN sbt --version 2>&1 | tail -1

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
