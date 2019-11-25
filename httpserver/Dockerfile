FROM golang:1.13.4

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GO111MODULE=on

COPY ../ /go/src/github.com/ti/server/
WORKDIR /go/src/github.com/ti/server/httpserver
RUN go install -ldflags '-s -w'
WORKDIR /go/src/github.com/ti/server/httpserver/client
RUN go install -ldflags '-s -w'
WORKDIR /go/src/github.com/ti/server/etcdrest
RUN go install -ldflags '-s -w'

FROM golang:1.13.4
RUN apt-get update
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y install traceroute \
    python3-dev python3-pip \
    autoconf build-essential libcurl4-gnutls-dev libxml2-dev libssl-dev automake libev-dev libtool libsodium-dev \
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
    shadowsocks-libev \
    jq \
    apt-transport-https \
    gnupg-agent \
    software-properties-common \
    libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev

# mongo
RUN curl https://www.mongodb.org/static/pgp/server-4.2.asc -o mongodb.asc
RUN /usr/bin/apt-key add mongodb.asc
RUN /bin/rm mongodb.asc
RUN /bin/echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | /usr/bin/tee /etc/apt/sources.list.d/mongodb-org-4.2.list
RUN apt-get update
RUN apt-get install -y mongodb-org

# postgres
RUN curl https://www.postgresql.org/media/keys/ACCC4CF8.asc -o pg.asc
RUN /usr/bin/apt-key add pg.asc
RUN /bin/rm pg.asc
RUN apt-get update
RUN apt-get install -y postgresql-11 postgresql-client-11

# mysql
RUN curl https://repo.mysql.com//mysql-apt-config_0.8.13-1_all.deb -o mysql.deb
RUN dpkg -i mysql.deb
RUN /bin/rm mysql.deb
RUN apt-get update
RUN apt install -y mysql-server mysql-client

# docker
RUN curl https://download.docker.com/linux/debian/gpg -o docker.asc
RUN /usr/bin/apt-key add docker.asc
RUN /bin/rm docker.asc
RUN add-apt-repository \
       "deb [arch=amd64] https://download.docker.com/linux/debian \
       $(lsb_release -cs) \
       stable"
RUN apt-get update
RUN apt install -y docker-ce

# TensorFlow
RUN mkdir /tf/
WORKDIR /tf/
RUN pip3 install -U virtualenv
RUN pip3 install --no-cache-dir install --upgrade \
    pip \
    setuptools \
    tensorflow
RUN virtualenv --system-site-packages -p python3 ./venv

ENV GO111MODULE on
ENV GOPROXY=https://goproxy.io
COPY --from=0 /go/bin/httpserver /app/main
COPY --from=0 /go/bin/client /app/client
COPY --from=0 /go/bin/etcdrest /app/etcdrest
COPY --from=0 /go/src/github.com/ti/server/httpserver/www /app/www
WORKDIR /app/
CMD ["/app/main","-p", "8080", "-d", "www"]
EXPOSE 8080
