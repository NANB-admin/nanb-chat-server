## Build stage --------------------------------------------------------
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates && update-ca-certificates

WORKDIR /src

# Cache module layer.
COPY go.mod go.sum ./
RUN go mod download

# Build. No GOARCH pin — the build runs inside this linux container and targets
# its native arch, so the SAME Dockerfile produces an amd64 binary on an Intel/
# AMD box and an arm64 binary on Graviton (t4g). The golang + distroless base
# images are multi-arch, so each pulls the matching variant automatically.
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/nanb-server ./cmd/server

## Runtime stage ------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /out/nanb-server /nanb-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY migrations /migrations

USER nonroot:nonroot
EXPOSE 8080 8081
ENTRYPOINT ["/nanb-server"]
