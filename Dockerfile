FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o manager ./cmd/manager
RUN CGO_ENABLED=0 GOOS=linux go build -a -o tsecret-inject ./cmd/inject

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /app/manager .
COPY --from=builder /app/tsecret-inject .
USER 65532:65532

ENTRYPOINT ["/manager"]
