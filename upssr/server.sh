#!/usr/bin/env bash

docker run  --restart always --name ssr  -d -p  10800:80  nanxi/ssr -s ss://AES-256-CFB:password@:80
