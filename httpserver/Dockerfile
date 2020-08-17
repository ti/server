FROM ubuntu:20.04
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GO111MODULE=on
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -yqq update && \
    apt install -y traceroute \
    python3-dev python3-pip \
    software-properties-common \
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
    jq \
    apt-transport-https \
    gnupg-agent \
    libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev && \
    apt-get autoremove -y && \
    apt-get clean -y
        
RUN apt update
RUN apt install -y traceroute \
    python3-dev python3-pip \
    software-properties-common \
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
    jq \
    apt-transport-https \
    gnupg-agent \
    libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev

# mongo
RUN curl https://www.mongodb.org/static/pgp/server-4.2.asc -o mongodb.asc
RUN /usr/bin/apt-key add mongodb.asc
RUN /bin/rm mongodb.asc
RUN /bin/echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | /usr/bin/tee /etc/apt/sources.list.d/mongodb-org-4.2.list
RUN apt update
RUN apt install -y mongodb-org

# postgres
RUN curl https://www.postgresql.org/media/keys/ACCC4CF8.asc -o pg.asc
RUN /usr/bin/apt-key add pg.asc
RUN /bin/rm pg.asc
RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" | tee  /etc/apt/sources.list.d/pgdg.list
RUN apt update
RUN apt install -y postgresql-12 postgresql-client-12

# mysql
RUN curl https://repo.mysql.com//mysql-apt-config_0.8.15-1_all.deb -o mysql.deb
RUN dpkg -i mysql.deb
RUN /bin/rm mysql.deb
RUN apt update
RUN apt install -y mysql-server mysql-client

# go
RUN curl https://dl.google.com/go/go1.15.linux-amd64.tar.gz -o go.tar.gz
RUN tar -C /usr/local -xzf go.tar.gz
RUN /bin/rm go.tar.gz
RUN mkdir -p /go/bin
ENV PATH="/go/bin:/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"


## kubenetes
RUN curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
RUN chmod +x ./kubectl
RUN mv ./kubectl /usr/local/bin/kubectl

## helm
RUN curl https://get.helm.sh/helm-v3.3.0-linux-amd64.tar.gz -o helm.tar.gz
RUN tar -xzf helm.tar.gz
RUN mv linux-amd64/helm /usr/local/bin
RUN /bin/rm helm.tar.gz

# v2ray
RUN curl -Ls https://install.direct/go.sh | bash

# shadowsocks
RUN apt install -y shadowsocks-libev

# TensorFlow
RUN mkdir /tf/
WORKDIR /tf/
RUN pip3 --no-cache-dir install -U virtualenv
RUN pip3 --no-cache-dir install --upgrade setuptools
RUN pip3 --no-cache-dir install --upgrade tensorflow
RUN virtualenv --system-site-packages -p python3 ./venv

# nodejs
RUN curl https://nodejs.org/dist/v12.18.3/node-v12.18.3-linux-x64.tar.xz -o node.tar.xz
RUN tar -xJvf node.tar.xz
RUN mv node-v12.18.3-linux-x64 /usr/local/nodejs
ENV PATH="/usr/local/nodejs/bin:${PATH}"

# java
RUN apt install -y default-jdk
RUN apt install -y maven

# kafka
RUN curl https://downloads.apache.org/kafka/2.5.0/kafka_2.12-2.5.0.tgz -o kafka.tgz
RUN tar xzf kafka.tgz
RUN mv kafka_2.12-2.5.0 /usr/local/kafka
RUN /bin/rm kafka.tgz
ENV PATH="/usr/local/kafka/bin:${PATH}"


# ffmpeg
RUN apt-get -yqq update && \
    apt-get install -yq ffmpeg && \
    apt-get autoremove -y && \
    apt-get clean -y

# clean
RUN apt-get autoremove -y && \
    apt-get clean -y
    
# tools
ENV GOPROXY=https://goproxy.io

RUN go get github.com/ti/server/etcdrest
RUN go get github.com/ti/server/httpserver
RUN go get github.com/ti/server/httpserver/client
RUN go clean --modcache
RUN mv /go/bin /app/
RUN rm -rf /go/src/
RUN rm -rf /go/pkg/
WORKDIR /app/
CMD ["/app/httpserver", "-p", "8080", "-d", "www"]
EXPOSE 8080
