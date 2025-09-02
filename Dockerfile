# DevSecOps toolbox image: Python + popular scanners (version-pinned)
# Build: docker build -t devsecops-toolbox:latest .

FROM python:3.13-slim

# Versions (update here when you want to bump)
ARG CHECKOV_VERSION=3.2.467
ARG CONFTEST_VERSION=0.62.0
ARG DOCKLE_VERSION=0.4.15
ARG GITLEAKS_VERSION=8.28.0
ARG GRYPE_VERSION=0.99.1
ARG HADOLINT_VERSION=2.12.0
ARG SEMGREP_VERSION=1.134.0
ARG SYFT_VERSION=1.32.0
ARG TRIVY_VERSION=0.65.0
ARG TRUFFLEHOG_VERSION=3.90.5

# Basic utilities
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq tar unzip gnupg libmagic1 file; \
    rm -rf /var/lib/apt/lists/*

# ---- Checkov (Python) ----
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"

# ---- Semgrep (Python) ----
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Helper for fetching GitHub release tarballs
SHELL ["/bin/sh", "-c"]
ENV BIN_DIR=/usr/local/bin
WORKDIR /tmp

# ---- Conftest (OPA) ----
RUN set -eux; \
    curl -sSL -o conftest.tar.gz "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"; \
    tar -xzf conftest.tar.gz conftest && mv conftest ${BIN_DIR}/conftest && chmod +x ${BIN_DIR}/conftest && rm -f conftest.tar.gz

# ---- Dockle ----
RUN set -eux; \
    curl -sSL -o dockle.tar.gz "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz"; \
    tar -xzf dockle.tar.gz dockle && mv dockle ${BIN_DIR}/dockle && chmod +x ${BIN_DIR}/dockle && rm -f dockle.tar.gz

# ---- Gitleaks ----
RUN set -eux; \
    curl -sSL -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    tar -xzf gitleaks.tar.gz gitleaks && mv gitleaks ${BIN_DIR}/gitleaks && chmod +x ${BIN_DIR}/gitleaks && rm -f gitleaks.tar.gz

# ---- Grype ----
RUN set -eux; \
    curl -sSfL "https://raw.githubusercontent.com/anchore/grype/main/install.sh" | sh -s -- -b ${BIN_DIR} "v${GRYPE_VERSION}"

# ---- Hadolint ----
RUN set -eux; \
    curl -sSL -o ${BIN_DIR}/hadolint "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64"; \
    chmod +x ${BIN_DIR}/hadolint

# ---- Syft ----
RUN set -eux; \
    curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | sh -s -- -b ${BIN_DIR} "v${SYFT_VERSION}"

# ---- Trivy ----
# NOTE: GitHub org is aquasecurity (correct for the install script). On Docker Hub it's aquasec.
RUN set -eux; \
    curl -sSfL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" | sh -s -- -b ${BIN_DIR} "v${TRIVY_VERSION}"

# ---- TruffleHog ----
RUN set -eux; \
    curl -sSL -o trufflehog.tar.gz "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"; \
    tar -xzf trufflehog.tar.gz trufflehog && mv trufflehog ${BIN_DIR}/trufflehog && chmod +x ${BIN_DIR}/trufflehog && rm -f trufflehog.tar.gz

# Light check that binaries are on PATH
RUN set -eux; \
    for c in \
      python3 pip checkov conftest dockle gitleaks grype hadolint semgrep syft trivy trufflehog \
    ; do command -v "$c" >/dev/null; done

# Copy Python application
COPY requirements.txt /app/requirements.txt
COPY src/ /app/src/
COPY examples/ /app/examples/
COPY templates/ /app/templates/

# Install Python application dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Set Python path and create entrypoint
ENV PYTHONPATH="/app"
RUN echo '#!/bin/bash\ncd /app && python -m src "$@"' > /usr/local/bin/security-scanner && \
    chmod +x /usr/local/bin/security-scanner

# Create reports directory and set working directory
RUN mkdir -p /app/reports && chmod 755 /app/reports
WORKDIR /app

# Install Docker CLI for target validation (best practice approach)
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        lsb-release; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-ce-cli; \
    rm -rf /var/lib/apt/lists/*

# Final validation check - ensure all required tools are available
RUN set -eux; \
    for c in \
      python3 pip checkov conftest dockle gitleaks grype hadolint semgrep syft trivy trufflehog \
      git docker file \
    ; do command -v "$c" >/dev/null; done

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD security-scanner --check-dependencies || exit 1

# Default command - run the security scanner
#CMD ["security-scanner", "--help"]
CMD ["bash"]
