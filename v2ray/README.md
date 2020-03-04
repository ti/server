
# docker-v2ray-ws-tls

Docker Compose solution: v2ray + Caddy


## Usage

```
$ ./configure <Host> 
$ cd ./build
$ docker-compose up -d
```

Then connect to `https://<Host>:443` via vmess over wss with `path: "/v2ws"`.
