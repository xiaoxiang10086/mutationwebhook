FROM golang:1.19-alpine AS build-env

# 设置工作目录
WORKDIR /app

# 复制代码到镜像中
COPY . .

RUN go build -o layoctl cmd/layotto-inject/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build-env /app/layoctl .
EXPOSE 8443
ENTRYPOINT ["./layoctl", "serve"]
