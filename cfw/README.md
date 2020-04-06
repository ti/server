
# Docker v2ray with traefik

Docker Compose solution: v2ray + traefik


## Usage

```
$ wget https://github.com/ti/server/raw/master/cfw/cfw.tar.gz
$ tar zxvf cfw.tar.gz 
$ cd cfw
$ # config your ssl domain and key. if you have uuid, just run 
$ # sh configure <your.domain.com> <your_uuid>
$ sh configure <your.domain.com> 
$ cd build
$ docker stack deploy -c compose.yml cfw
$ cat v2ray-client.json
$ how to stop ? docker stack rm cfw
```

```
the v2ray client config is v2ray-client.json
```

Then connect to `wss://<Host>:443/v2/ws` or `https://<Host>:443/v2/h2` and  alterId is "64"


## How to connect in client

```bash
# copy build/v2ray-client.json to the local, the run the command
docker run --restart always --name v2ray -d -v $(pwd)/v2ray-client.json:/etc/v2ray/config.json -p 127.0.0.1:10808:10808  -p 127.0.0.1:10809:10809 v2fly/v2fly-core:latest
```

* the client socket5 proxy port is 127.0.0.1:10808
* the client http proxy port is  127.0.0.1:10809

## Have trouble?

### init docker swarm
docker swarm init

```bash
sed -i 's/\"live-restore\":.*/\"live-restore\": false,/g' /etc/docker/daemon.json
systemctl restart docker
```

/etc/ssh/sshd_config

```bash
sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd
# sudo adduser ${USER} sudo 
```

### install docker on ubuntu?

```
$ sudo apt-get install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo apt-key fingerprint 0EBFCD88
$ sudo add-apt-repository  "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ sudo apt-get update
$ sudo apt-get install docker-ce docker-ce-cli containerd.io
$ sudo adduser ${USER} docker 
$ su ${USER}
```
