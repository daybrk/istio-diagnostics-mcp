FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/istio-diagnostics-mcp ./cmd/istio-diagnostics-mcp

FROM scratch
COPY --from=build /out/istio-diagnostics-mcp /istio-diagnostics-mcp
USER 65532:65532
ENTRYPOINT ["/istio-diagnostics-mcp"]
