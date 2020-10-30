package main

import (
	"encoding/json"
	"flag"
	"github.com/sirupsen/logrus"
	pb "github.com/ti/server/httpserver/pkg/go"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net/url"
	"strings"
)

var (
	addr    = flag.String("addr", "http://127.0.0.1:8080", "grpc addr")
	reqType = flag.String("type", "info", "req type")
)

func main() {
	flag.Parse()
	var err error
	uri := &url.URL{}
	if strings.Contains(*addr, "://") {
		uri, err = url.Parse(*addr)
		if err != nil {
			panic(err)
		}
	} else {
		uri.Scheme = "http"
		uri.Host = *addr
	}
	var grpcDialOption grpc.DialOption
	if strings.HasSuffix(uri.Scheme, "s") {
		grpcDialOption = grpc.WithTransportCredentials(credentials.NewTLS(nil))
	} else {
		grpcDialOption = grpc.WithInsecure()
	}
	conn, err := grpc.Dial(uri.Host, grpcDialOption)
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewServerClient(conn)
	md := metadata.New(map[string]string{
		"authorization": "Bearer 7AUaDMwP98B39hJTH5eJPxylo",
	})
	mdCtx := metadata.NewOutgoingContext(context.Background(), md)
	r, err := c.Info(mdCtx, &pb.Request{Type: *reqType})
	if err != nil {
		status, ok := status.FromError(err)
		if ok {
			b, _ := json.Marshal(status.Err())
			logrus.Error(string(b))
		} else {
			logrus.Error(err.Error())
		}
		return
	}
	if r.Data["Request"] != nil && len(r.Data["Request"].List) > 0 {
		logrus.Info(r.Data["Request"].List[0])
		delete(r.Data, "Request")
	}
	b, _ := json.Marshal(r.Data)
	logrus.Info(string(b))
}
