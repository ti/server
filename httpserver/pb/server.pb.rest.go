// Code generated by protoc-gen-rest. DO NOT EDIT.
// source: pb/server.proto

package pb


import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	runtime "github.com/grpc-ecosystem/grpc-gateway/runtime"
	grpc "google.golang.org/grpc"
	context "golang.org/x/net/context"
)


// Server API for Server service
type serverServerClient struct {
	srv ServerServer
}

func RegisterServerServerHandlerClient(ctx context.Context, mux *runtime.ServeMux, srv ServerServer) error {
	return RegisterServerHandlerClient(ctx, mux, NewServerServerClient(srv))
}

func (h *serverServerClient) Info(ctx context.Context, in *Request, _ ...grpc.CallOption) (*Response, error) {
	return h.srv.Info(ctx, in)
}

func NewServerServerClient(srv ServerServer) ServerClient {
	return &serverServerClient{
		srv: srv,
	}
}

