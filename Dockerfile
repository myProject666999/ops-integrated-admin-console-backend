# 使用 Windows Server Core 作为基础镜像
FROM golang:1.26-windowsservercore-ltsc2022 AS builder

WORKDIR C:/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -buildvcs=false -o ops-admin-backend.exe .

FROM mcr.microsoft.com/windows/servercore:ltsc2022

WORKDIR C:/app

COPY --from=builder C:/app/ops-admin-backend.exe .
COPY --from=builder C:/app/data ./data

RUN mkdir db

ENV ADDR=0.0.0.0:8080
ENV TZ=Asia/Shanghai

EXPOSE 8080

CMD ["ops-admin-backend.exe"]
