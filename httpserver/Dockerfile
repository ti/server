FROM golang:1.11.2

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GO111MODULE=on

COPY . /go/src/github.com/ti/server/httpserver
WORKDIR /go/src/github.com/ti/server/httpserver
RUN go install -ldflags '-s -w'
WORKDIR /go/src/github.com/ti/server/httpserver/client
RUN go install -ldflags '-s -w'

FROM scratch
COPY --from=0 /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=0 /go/bin/httpserver /app/main
COPY --from=0 /go/bin/client /app/client
COPY --from=0 /go/src/github.com/ti/server/httpserver/www /app/www
WORKDIR /app/
CMD ["/app/main","-p", "8080", "-d", "www"]
EXPOSE 8080