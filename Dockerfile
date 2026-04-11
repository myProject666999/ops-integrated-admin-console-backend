FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /ops-admin-backend .

FROM alpine:3.19

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /ops-admin-backend .
COPY --from=builder /app/data ./data

RUN mkdir -p /app/db

ENV ADDR=0.0.0.0:8080
ENV TZ=Asia/Shanghai

EXPOSE 8080

CMD ["./ops-admin-backend"]
