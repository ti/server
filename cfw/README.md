
# docker-v2ray-ws-tls

Docker Compose solution: v2ray + Caddy


## Usage

```
$ ./configure <Host> 
$ docker stack deploy -c compose.yml cfw
$ cat v2ray-client.json
$ how to stop ? docker stack rm  cfw
```

Then connect to `https://<Host>:443` via vmess over wss with `path: "/v2ws"` alterId is "4"

## more info
