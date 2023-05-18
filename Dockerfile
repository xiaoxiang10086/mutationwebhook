FROM golang:1.18-alpine AS build-env

# 设置工作目录
WORKDIR /app

# 复制代码到镜像中
COPY . .

# 编译 Mutation Webhook 服务
RUN go build -o mutation-webhook .

# 运行 Mutation Webhook 服务
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build-env /app/mutation-webhook .
EXPOSE 8443
ENTRYPOINT ["./mutation-webhook"]