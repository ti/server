FROM golang:1.13.0

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GO111MODULE=on

COPY . /go/src/github.com/ti/server/httpserver
WORKDIR /go/src/github.com/ti/server/httpserver
RUN go install -ldflags '-s -w'
WORKDIR /go/src/github.com/ti/server/httpserver/client
RUN go install -ldflags '-s -w'

FROM golang:1.13.0
RUN apt-get update
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y install traceroute \
    autoconf build-essential libcurl4-gnutls-dev libxml2-dev libssl-dev \
    automake build-base c-ares-dev libev-dev libtool libsodium-dev linux-headers mbedtls-dev pcre-dev \
    dnsutils \
    apt-utils\
    tree\
    mtr-tiny \
    iputils-ping \
    netcat-openbsd \
    wget \
    telnet \
    curl \
    bash \
    htop \
    tcpdump \
    nmap \
    iperf \
    gnupg2 \
    net-tools \
    openssh-client \
    git \
    vim \
    curl \
    wget \
    redis-server \
    mysql-server \
    postgresql \
    postgresql-contrib \
    shadowsocks-libev \
    jq \
    apt-transport-https \
    gnupg-agent \
    software-properties-common

RUN curl https://www.mongodb.org/static/pgp/server-4.2.asc -o mongodb.asc
RUN /usr/bin/apt-key add mongodb.asc
RUN /bin/rm mongodb.asc
RUN /bin/echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | /usr/bin/tee /etc/apt/sources.list.d/mongodb-org-4.2.list
RUN apt-get update
RUN apt-get install -y mongodb-org

COPY --from=0 /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=0 /go/bin/httpserver /app/main
COPY --from=0 /go/bin/client /app/client
COPY --from=0 /go/src/github.com/ti/server/httpserver/www /app/www
WORKDIR /app/
CMD ["/app/main","-p", "8080", "-d", "www"]
EXPOSE 8080
