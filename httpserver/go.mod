module github.com/ti/server/httpserver

require (
	github.com/clbanning/mxj v1.8.3
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1
	github.com/elazarl/goproxy/ext v0.0.0-20190911111923-ecfe977594f1
	github.com/golang/protobuf v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.11.1
	github.com/sirupsen/logrus v1.2.0
	github.com/ti/noframe v1.3.1
	golang.org/x/net v0.0.0-20181220203305-927f97764cc3
	google.golang.org/genproto v0.0.0-20181202183823-bd91e49a0898
	google.golang.org/grpc v1.19.0
)

replace (
	golang.org/x/net v0.0.0-20181106065722-10aee1819953 => github.com/golang/net v0.0.0-20181106065722-10aee1819953
	google.golang.org/genproto v0.0.0-20181101192439-c830210a61df => github.com/google/go-genproto v0.0.0-20181101192439-c830210a61df
	google.golang.org/grpc v1.16.0 => github.com/grpc/grpc-go v1.16.0
)
