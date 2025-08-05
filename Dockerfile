FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o krakenfs-agent ./cmd/krakenfs-agent

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/krakenfs-agent .

# Copy configuration
COPY config/krakenfs/base.yaml /etc/krakenfs/config.yaml

# Create necessary directories
RUN mkdir -p /var/lib/krakenfs/volumes

EXPOSE 6881 6882

ENTRYPOINT ["./krakenfs-agent"]
CMD ["--config", "/etc/krakenfs/config.yaml"] 