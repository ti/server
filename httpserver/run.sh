#!/usr/bin/env bash
#docker run --rm -v $(pwd):$(pwd) -w $(pwd) nanxi/protoc:v1.0.0 --go_out=plugins=grpc:. --grpc-gateway_out=logtostderr=false:. --swagger_out=logtostderr=true:.  --rest_out=plugins=rest:.   -I. pb/*.proto

docker run -p 8080:8080 -v $PWD:/app/www nanxi/server