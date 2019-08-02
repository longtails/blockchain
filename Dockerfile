FROM golang:latest

WORKDIR $GOPATH/src/blockchain/certdemo

#将代码复制到镜像中
COPY . ..

#编译代码
RUN go build .

EXPOSE 12345
EXPOSE 5000
ENTRYPOINT ["./certdemo"]
