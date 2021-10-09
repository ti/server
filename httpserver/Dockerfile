FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt -yqq update && \
    apt install -y traceroute \
    python3-dev python3-pip \
    software-properties-common openssh-server \
    autoconf build-essential cmake pkg-config libcurl4-gnutls-dev libxml2-dev libssl-dev automake libev-dev libtool libsodium-dev \
    dnsutils apt-utils tree nfs-common mtr-tiny iputils-ping netcat-openbsd wget zip unzip telnet curl zsh powerline fonts-powerline htop \
    tcpdump nmap iperf gnupg gnupg2 net-tools openssh-client git vim curl wget redis-server jq apt-transport-https gnupg-agent \
    libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev

# mysql
RUN apt update
RUN apt install -y mysql-server mysql-client

# java
RUN apt install -y default-jdk
RUN apt install -y maven

# ffmpeg
RUN apt-get install -yq ffmpeg

# pytorch
RUN pip3 --no-cache-dir install torch torchvision

# cqlsh
RUN pip3 --no-cache-dir install cqlsh

# shadowsocks
RUN apt install -y shadowsocks-libev

# postgres
RUN curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" | tee  /etc/apt/sources.list.d/pgdg.list
RUN apt update
RUN apt install -y postgresql-13 postgresql-client-13

## docker
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
RUN apt update
RUN apt install -y docker-ce docker-ce-cli containerd.io
RUN curl -L https://github.com/docker/compose/releases/download/1.29.2/docker-compose-Linux-x86_64 -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose

## clickhouse
RUN apt install apt-transport-https ca-certificates dirmngr
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E0C56BD4
RUN echo "deb https://repo.clickhouse.tech/deb/stable/ main/" | tee /etc/apt/sources.list.d/clickhouse.list
RUN apt update
RUN apt install -y clickhouse-server clickhouse-client

# TensorFlow
RUN pip3 --no-cache-dir install -U virtualenv
RUN pip3 --no-cache-dir install --upgrade setuptools
RUN pip3 --no-cache-dir install --upgrade tensorflow

RUN mkdir /tf/
WORKDIR /tf/
RUN virtualenv --system-site-packages -p python3 /tf/venv

WORKDIR /tmp/

# helm
RUN curl https://get.helm.sh/helm-v3.6.3-linux-amd64.tar.gz -o helm.tar.gz
RUN tar -xzf helm.tar.gz
RUN cp linux-amd64/helm /usr/local/bin/

# v2ray
RUN curl -O https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
RUN bash install-release.sh
RUN rm install-release.sh

# go
RUN curl https://dl.google.com/go/go1.17.linux-amd64.tar.gz -o go.tar.gz
RUN tar -C /usr/local -xzf go.tar.gz
RUN mkdir -p /go/bin
ENV PATH="${PATH}:/go/bin:/usr/local/go/bin"
ENV GOPATH="/go"

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GO111MODULE=on

# kubenetes
RUN curl -L "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

# nodejs
RUN curl https://nodejs.org/dist/v16.8.0/node-v16.8.0-linux-x64.tar.xz -o node.tar.xz
RUN tar -xJvf node.tar.xz
RUN mv node-v16.8.0-linux-x64 /usr/local/nodejs
ENV PATH="${PATH}:/usr/local/nodejs/bin"
RUN npm install --global yarn
RUN npm install --global typescript

# kafka
RUN curl https://downloads.apache.org/kafka/3.0.0/kafka_2.13-3.0.0.tgz -o kafka.tgz
RUN tar xzf kafka.tgz
RUN mv kafka_2.13-3.0.0 /usr/local/kafka
RUN /bin/rm -rf kafka*
ENV PATH="${PATH}:/usr/local/kafka/bin"

## openssh
RUN mkdir /var/run/sshd
RUN echo 'root:o3sNqceaCaMFE1' | chpasswd
RUN sed -i 's/#*PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
# SSH login fix. Otherwise user is kicked off after login
RUN sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' /etc/pam.d/sshd
RUN sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
RUN sed -i 's/#Port .*/Port 2022/g' /etc/ssh/sshd_config

# mongodb
RUN curl https://fastdl.mongodb.org/tools/db/mongodb-database-tools-ubuntu2004-x86_64-100.5.0.tgz -o mongodb-database-tools.tgz
RUN curl https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2004-5.0.2.tgz -o mongodb.tgz
RUN tar xzf mongodb-database-tools.tgz
RUN tar xzf mongodb.tgz
RUN mkdir -p /usr/local/mongodb/bin/
RUN mv mongodb-database-tools-ubuntu2004-x86_64-100.5.0/bin/* /usr/local/mongodb/bin/
RUN mv mongodb-linux-x86_64-ubuntu2004-5.0.2/bin/* /usr/local/mongodb/bin/
ENV PATH="${PATH}:/usr/local/mongodb/bin"

# Pulsar
RUN curl https://archive.apache.org/dist/pulsar/pulsar-2.8.0/apache-pulsar-2.8.0-bin.tar.gz -o apache-pulsar.tar.gz
RUN tar xzf apache-pulsar.tar.gz
RUN mv apache-pulsar-2.8.0 /usr/local/pulsar
ENV PATH="${PATH}:/usr/local/pulsar/bin"

# tools
ENV GOPROXY=https://goproxy.io
RUN go install github.com/ti/server/etcdrest@latest
RUN go install github.com/ti/server/httpserver@latest
RUN go install github.com/ti/server/httpserver/client@latest
RUN go clean --modcache
RUN mv /go/bin /app/
RUN rm -rf /go/bin
RUN rm -rf /go/src/
RUN rm -rf /go/pkg/

# zsh
RUN chsh -s /usr/bin/zsh
RUN echo 'alias ls="ls --color=auto"\nexport DOCKER_HOST=tcp://127.0.0.1:2375\nexport PATH=${PATH}:/go/bin:/usr/local/go/bin:/usr/local/nodejs/bin:/usr/local/kafka/bin:/usr/local/mongodb/bin:/usr/local/pulsar/bin\nexport GOPROXY=https://goproxy.io' >> /root/.zshrc
RUN echo 'alias db="docker build --network host --tag"' >> /root/.zshrc
#RUN apt -y --purge --allow-remove-essential remove bash
#RUN ln -s /usr/bin/zsh  /usr/bin/bash
#RUN rm -f /root/.bashrc
RUN rm -f /root/.zcompdump
RUN rm -rf /tmp/*
RUN rm -rf /root/.cache

# clean
RUN apt-get autoremove -y && apt-get clean -y

WORKDIR /app/
RUN mkdir -p /app/www
CMD ["/app/httpserver", "-p", "8080", "-d", "www", "-l", "true"]
EXPOSE 8080
