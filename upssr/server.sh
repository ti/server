#!/usr/bin/env bash

docker run --restart always --name ss -e PASSWORD=pass -e METHOD=aes-128-gcm -p 443:8388 -p 443:8388/udp -d shadowsocks/shadowsocks-libev

docker run --restart always --name server -p 443:8388 -p 443:8388/udp -d nanxi/server:v1.2.0 /usr/bin/ss-server -k pass -m aes-128-gcm -s 0.0.0.0 -p 8388

docker run  --restart always --name ssr  -d -p  10800:80  nanxi/ssr -s ss://AES-256-CFB:password@:80

# or use v2ray
docker run  --restart always -it -d --name v2ray -v v2ray:/etc/v2ray -p 443:8888 -p 80:6666 v2ray/official

#mkdir v2ray
# v2ray/config.json
{
  "inbound": {
    "port": 8888,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "10e6d74b-add1-4310-9e33-4fdb5bbb2591",
          "level": 1,
          "alterId": 64
        }
      ]
    },
    "streamSettings": {
       "network": "tcp"
    }
  },
  "outbound": {
    "protocol": "freedom",
    "settings": {}
  },
  "inboundDetour": [
    {
      "protocol": "shadowsocks",
      "port": 6666,
      "settings": {
        "method": "aes-128-gcm",
        "password": "pass",
        "udp": true
      }
    }
  ],
  "outboundDetour": [
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "strategy": "rules",
    "settings": {
      "rules": [
        {
          "type": "field",
          "ip": ["geoip:private"],
          "outboundTag": "blocked"
        }
      ]
    }
  }
}

