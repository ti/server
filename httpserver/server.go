package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/clbanning/mxj"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/ti/noframe/grpcmux"
	pb "github.com/ti/server/httpserver/pb"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	port       = flag.Int("p", 8080, "port to listen")
	logBody    = flag.Bool("l", false, "write http body log on std out")
	cors    = flag.Bool("cors", true, "enable cors?")
	decodeBody = flag.Bool("b", true, "decode as struct")
	dir        = flag.String("d", "./", "dir to server")
	showInfo   = flag.Bool("info", false, "show info router")
	spa        = flag.Bool("spa", true, "is is a single page app?")
	cert       = flag.String("cert", "", "ssl cert")
	key        = flag.String("key", "", "ssl key")
	proxyToken        = flag.String("proxy_token", "", "ssl key")
)

func main() {
	flag.Parse()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Printf("\u001b[31m[ERROR] %s\u001b[0m\n", err)
		return
	}
	scheme := "http"
	if *cert != "" && *key != "" {
		scheme = "https"
	}
	fmt.Printf("Starting up http-server, serving \u001b[36m%s \u001b[0m \nAvailable on:\n", *dir)
	addrs, _ := net.InterfaceAddrs()
	for _, rawAddr := range addrs {
		if ipnet, ok := rawAddr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			fmt.Printf("\t\u001b[34m%s://%s:%d\u001b[0m\n", scheme, ipnet.IP.To4().String(), *port)
		}
	}
	fmt.Println("Hit CTRL-C to stop the server")

	mux := grpcmux.NewServeMux()
	service := &service{}
	pb.RegisterServerServerHandlerClient(context.TODO(), mux.ServeMux, service)
	//register all as grpc service as well
	gs := grpc.NewServer()
	pb.RegisterServerServer(gs, service)
	reflection.Register(gs)
	fs := fileServer(*dir)
	runtime.OtherErrorHandler = func(w http.ResponseWriter, r *http.Request, msg string, code int) {
		if *showInfo {
			if strings.HasPrefix(r.URL.Path, "/www/") {
				http.StripPrefix("/www/", fs).ServeHTTP(w, r)
			} else if r.URL.Path == "/" {
				http.Redirect(w, r, "/www/", http.StatusFound)
			} else {
				httpInfo(w, r)
			}
		} else {
			if strings.HasPrefix(r.URL.Path, "/_info/") {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/_info/")
				r.RequestURI = strings.TrimPrefix(r.RequestURI, "/_info/")
				httpInfo(w, r)
			} else {
				fs.ServeHTTP(w, r)
			}
		}
	}

	handler := GRPCMixHandler(mux, gs)
	http.Handle("/_proxy/", http.StripPrefix("/_proxy", http.HandlerFunc(Proxy)))
	http.Handle("/_info/", http.StripPrefix("/_info", http.HandlerFunc(httpInfo)))
	http.Handle("/", handler)
	panic(http.Serve(listener, nil))
}


func Proxy(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token := q.Get("proxy_token")
	base := q.Get("proxy_base")
	if token != *proxyToken {
		http.Error(w, "token not match", 403)
		return
	}
	proxyURI, err := url.Parse(base)
	if err != nil || proxyURI.Scheme == "" || proxyURI.Host == "" {
		http.Error(w, "base not found", 404)
		return
	}
	r.Host = proxyURI.Host
	r.URL.Scheme = proxyURI.Scheme
	r.URL.Host = proxyURI.Host
	r.URL.Path = proxyURI.Path + r.URL.Path
	delete(q, "proxy_token")
	delete(q, "proxy_base")
	r.URL.RawQuery = q.Encode()
	if r.URL.RawQuery != "" {
		r.RequestURI = r.URL.Path + "?" +  r.URL.RawQuery
	} else {
		r.RequestURI = r.URL.Path
	}
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Content-Length")
	NewReverseProxy(proxyURI).ServeHTTP(w, r)
}


var defaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   time.Second,
		KeepAlive: time.Minute,
	}).DialContext,
	MaxIdleConns:          math.MaxUint32,
	MaxIdleConnsPerHost:   math.MaxUint32,
	IdleConnTimeout:       180 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 30 * time.Second,
}

// NewReverseProxy 新建反向代理
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = defaultTransport
	return proxy
}


func fileServer(dir string) http.Handler {
	absPath, err := filepath.Abs(dir)
	if err != nil {
		panic(err)
	}
	fs := http.Dir(absPath)
	fileDir := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *spa && r.URL.Path != "/" && r.URL.Path != "" {
			var err error
			fullName := absPath + r.URL.Path
			if strings.HasSuffix(r.URL.Path, "/") {
				_, err = os.Stat(fullName)
			} else {
				_, err = os.Open(fullName)
			}
			if err != nil && os.IsNotExist(err) {
				if _, err := fs.Open("/index.html"); err == nil {
					r.URL.Path = "/"
					r.RequestURI = "/"
					if r.URL.RawQuery != "" {
						r.RequestURI += "?" + r.URL.RawQuery
					}
				}
			}
		}
		fileDir.ServeHTTP(w, r)
	})
}

type URL struct {
	Scheme   string
	Path     string
	Host     string
	RawQuery string      `json:"RawQuery,omitempty"`
	Query    interface{} `json:"Query,omitempty"`
	User     interface{} `json:"User,omitempty"`
}

type request struct {
	Time          string               `json:"time"`
	Method        string               `json:"method,omitempty"`
	RequestURI    string               `json:"request_uri,omitempty"`
	RemoteIP      string               `json:"remote_ip,omitempty"`
	Body          interface{}          `json:"body,omitempty"`
	Meta          *map[string]string   `json:"meta,omitempty"`
	RemoteAddr    string               `json:"remote_addr,omitempty"`
	Proto         string               `json:"proto,omitempty"`
	Host          string               `json:"host,omitempty"`
	URL           URL                  `json:"url,omitempty"`
	Header        http.Header          `json:"header,omitempty"`
	TLS           *tls.ConnectionState `json:"tls,omitempty"`
	ContentLength int64                `json:"content_length,omitempty"`
}

func enableCors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
	origin := r.Header.Get("Origin")
	if origin != "" {
		if uri, err := url.Parse(origin); err == nil {
			if uri.Host != r.Host {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				w.Header().Set("Vary", "Origin, Accept-Encoding")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}
	}
}

func getRequestInfo(r *http.Request) *request {
	q := r.URL.Query()
	u := URL{Scheme: r.URL.Scheme, RawQuery: r.URL.RawQuery, Path: r.URL.Path, Host: r.Host}
	if len(q) > 0 {
		u.Query = q
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if user, pass, ok := r.BasicAuth(); ok {
		u.User = struct {
			Username string
			Password string
		}{
			user, pass,
		}
	}
	req := request{Time: time.Now().Format(time.RFC3339)}
	var meta = make(map[string]string)
	req.Host = r.Host
	req.Method = r.Method
	req.URL = u
	req.Header = r.Header
	req.RequestURI = r.RequestURI
	req.TLS = r.TLS
	req.RemoteAddr = r.RemoteAddr
	req.Proto = r.Proto
	req.ContentLength = r.ContentLength
	contentType := r.Header.Get("Content-Type")

	if !strings.HasPrefix(contentType, "application/grpc") {
		if *decodeBody {
			if strings.Contains(contentType, "json") {
				var data interface{}
				dec := json.NewDecoder(r.Body)
				if err := dec.Decode(&data); err == nil {
					req.Body = data
				} else {
					meta["error"] = fmt.Sprintf("json decode error - %s", err)
				}
			} else if strings.Contains(contentType, "form") {
				r.ParseForm()
				req.Body = r.PostForm
			} else if strings.Contains(contentType, "xml") {
				b, _ := ioutil.ReadAll(r.Body)
				data, err := mxj.NewMapXml(b)
				if err == nil {
					req.Body = data
				} else {
					meta["error"] = fmt.Sprintf("xml decode error - %s", err)
				}
			} else if strings.Contains(contentType, "grpc") {
				//do noting
			} else {
				if r.Method == "GET" || r.Method == "DELETE" {
					req.Body = ""
				} else {
					if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
						req.Body = string(b)
					}
				}
			}
		} else {
			if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
				req.Body = b
			}
		}
	}
	req.RemoteIP = getIP(r).String()
	if len(meta) > 0 {
		req.Meta = &meta
	}
	return &req
}

func httpInfo(w http.ResponseWriter, r *http.Request) {
	req, ok := r.Context().Value(requestKey{}).(*request)
	if !ok {
		req = getRequestInfo(r)
	}
	resp, _ := json.MarshalIndent(req, "", "\t")
	if strings.HasSuffix(r.URL.Path, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><title>%s</title><head/><h1>%s</h1><pre>%s</pre></html>", "Request Infos", "Request Infos", string(resp))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}
}

func getIP(r *http.Request) net.IP {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		return net.ParseIP(parts[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return net.ParseIP(ip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

//GRPCMixHandler mix grpc and http in one Handler
func GRPCMixHandler(h http.Handler, grpc *grpc.Server) http.Handler {
	mix := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *cors {
			enableCors(w,r)
		}
		req := getRequestInfo(r)
		log("grpc_mix", req)
		ctx := context.WithValue(r.Context(), requestKey{}, req)
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpc.ServeHTTP(w, r.WithContext(ctx))
		} else {
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
	server := &http2.Server{}
	return h2c.NewHandler(mix, server)
}

type service struct{}

type requestKey struct{}

func (h *service) Info(ctx context.Context, in *pb.Request) (*pb.Response, error) {
	resp := &pb.Response{
		Data: make(map[string]*pb.Response_List),
	}
	defer func() {
		log("grpc", resp)
	}()
	req, ok := ctx.Value(requestKey{}).(*request)
	if ok {
		data, _ := json.Marshal(req)
		list := pb.Response_List{
			List: []string{string(data)},
		}
		resp.Data["Request"] = &list
	}
	infoType := strings.ToLower(in.Type)
	if code, ok := strToCode[infoType]; ok {
		return nil, status.New(code, infoType).Err()
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logrus.Infof("failed to extract ServerMetadata from context")
		return nil, status.New(codes.InvalidArgument, fmt.Sprintf("message %s", in.Type)).Err()
	}
	if ok {
		for k, v := range md {
			list := pb.Response_List{
				List: v,
			}
			resp.Data[k] = &list
		}
	}
	return resp, nil
}

func log(reqType string, req interface{}) {
	if !*logBody {
		return
	}
	data, _ := json.Marshal(req)
	logrus.WithField("type", reqType).Info(string(data))
}

var strToCode = map[string]codes.Code{
	"cancelled": /* [sic] */ codes.Canceled,
	"unknown":               codes.Unknown,
	"invalid_argument":      codes.InvalidArgument,
	"deadline_exceeded":     codes.DeadlineExceeded,
	"not_found":             codes.NotFound,
	"already_exists":        codes.AlreadyExists,
	"permission_denied":     codes.PermissionDenied,
	"resource_exhausted":    codes.ResourceExhausted,
	"failed_precondition":   codes.FailedPrecondition,
	"aborted":               codes.Aborted,
	"out_of_range":          codes.OutOfRange,
	"unimplemented":         codes.Unimplemented,
	"internal":              codes.Internal,
	"unavailable":           codes.Unavailable,
	"data_loss":             codes.DataLoss,
	"uauthenticated":        codes.Unauthenticated,
}
