FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/istio-diagnostics-mcp ./cmd/istio-diagnostics-mcp
# Set the kubectl version compatible with your cluster, e.g. --build-arg KUBECTL_VERSION=vX.Y.Z.
ARG KUBECTL_VERSION
ARG TARGETARCH=amd64
RUN test -n "$KUBECTL_VERSION" && \
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" -o /out/kubectl && \
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256" -o /out/kubectl.sha256 && \
    cd /out && printf '%s  kubectl\n' "$(cat kubectl.sha256)" | sha256sum --check && chmod 0755 kubectl
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/istio-diagnostics-mcp /out/kubectl /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["istio-diagnostics-mcp"]
