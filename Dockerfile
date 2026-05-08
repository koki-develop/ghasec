FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS download

ARG GHASEC_VERSION
ARG TARGETARCH

RUN test -n "$GHASEC_VERSION" || (echo "ERROR: GHASEC_VERSION build arg is required" && exit 1)
RUN apk add --no-cache curl
RUN case "$TARGETARCH" in \
      amd64) ARCH="x86_64" ;; \
      arm64) ARCH="arm64" ;; \
      *) echo "ERROR: unsupported architecture: '${TARGETARCH:-<empty>}'. Supported: amd64, arm64" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/ghasec.tar.gz \
      "https://github.com/koki-develop/ghasec/releases/download/v${GHASEC_VERSION}/ghasec_Linux_${ARCH}.tar.gz" && \
    tar xz -C /usr/local/bin ghasec -f /tmp/ghasec.tar.gz && \
    rm /tmp/ghasec.tar.gz

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

COPY --from=download /usr/local/bin/ghasec /usr/local/bin/ghasec
RUN ghasec --version

WORKDIR /mnt
ENTRYPOINT ["ghasec"]
