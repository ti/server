
# Docker v2ray with traefik

Docker Compose solution: v2ray + traefik


## Usage

```
$ wget https://github.com/ti/server/raw/master/cfw/cfw.tar.gz
$ tar zxvf cfw.tar.gz 
$ cd cfw
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

## Have trouble?

docker swarm init

```bash
sed -i 's/\"live-restore\":.*/\"live-restore\": false,/g' /etc/docker/daemon.json
systemctl restart docker
```

/etc/ssh/sshd_config

```bash
sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
```

## How to connect in client

```bash
# copy build/v2ray-client.json to the local, the run the command
docker run --restart always --name v2ray -d -v $(pwd)/v2ray-client.json:/etc/v2ray/config.json -p 127.0.0.1:10808:10808  -p 127.0.0.1:10809:10809 v2fly/v2fly-core:latest
```

* the client socket5 proxy port is 127.0.0.1:10808
* the client http proxy port is  127.0.0.1:10809
