
# Docker v2ray with traefik

Docker Compose solution: v2ray + traefik


## Usage

```
$ wget https://github.com/ti/server/raw/master/cfw/cfw.tar.gz
$ tar zxvf cfw.tar.gz 
$ cd cfw
$ sh configure <Host> 
$ cd build
$ docker stack deploy -c compose.yml cfw
$ cat v2ray-client.json
$ how to stop ? docker stack rm  cfw
```

Then connect to `https://<Host>:443` via vmess over wss with `path: "/v2ws"` alterId is "4"

## Have trouble?

# docker swarm init
# /etc/docker/daemon.json
# "live-restore": false,
# /etc/ssh/sshd_config 
# PasswordAuthentication yes
