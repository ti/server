package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

var (
	port       = flag.Int("p", 8080, "port to listen")
	decodeBody = flag.Bool("b", false, "decode as struct")
	cors       = flag.Bool("cors", true, "enable cors?")
	dir        = flag.String("d", "./", "dir to server")
	spa        = flag.Bool("spa", true, "is a single page app?")
	mode       = flag.String("mode", "file", "default router mode [file, info, proxy]")
	host       = flag.String("host", "", "the host")
	cert       = flag.String("cert", "", "ssl cert")
	key        = flag.String("key", "", "ssl key")

	udp = flag.Bool("udp", false, "udp only")
)

func main() {
	flag.Parse()
	fs := fileServer(*dir)

	http.Handle("/_info/", StripPrefix("/_info", http.HandlerFunc(httpInfo)))
	http.Handle("/_www/", StripPrefix("/_www", fs))
	switch *mode {
	case "file":
		http.Handle("/", fs)
	case "info":
		http.Handle("/", http.HandlerFunc(httpInfo))
	default:
		http.Handle("/", fs)
	}
	handler := LogHandler(http.DefaultServeMux)

	scheme := "http"
	server := "http-server"
	if *cert != "" && *key != "" {
		scheme = "https"
		if *udp {
			server = "http3-server"
		}
	}
	fmt.Printf("Starting up %s serving \u001b[36m%s \u001b[0m \nAvailable on:\n", server, *dir)
	if *host == "" {
		addrs, _ := net.InterfaceAddrs()
		for _, rawAddr := range addrs {
			if ipnet, ok := rawAddr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				fmt.Printf("\t\u001b[34m%s://%s:%d\u001b[0m\n", scheme, ipnet.IP.To4().String(), *port)
			}
		}
		ipV6, err := getIPV6()
		if err == nil {
			fmt.Printf("\t\u001b[34m%s://[%s]:%d\u001b[0m\n", scheme, ipV6, *port)
		}
	} else {
		fmt.Printf("\t\u001b[34m%s://%s:%d\u001b[0m\n", scheme, *host, *port)
	}
	fmt.Println("Hit CTRL-C to stop the server")

	addr := fmt.Sprintf(":%d", *port)
	var err error
	if scheme == "https" {
		err = ListenAndServeHTTP3(addr, *cert, *key, handler, *udp)
	} else {
		err = http.ListenAndServe(fmt.Sprintf(":%d", *port), handler)
	}
	if err != nil {
		fmt.Printf("\u001b[31m[HTTP3 ERROR] %s\u001b[0m\n", err)
	}
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

// URL the url
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
	meta := make(map[string]string)
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
	reqBody, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(reqBody))
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
		} else if strings.Contains(contentType, "grpc") {
			// do noting
		} else {
			if r.Method == "GET" || r.Method == "DELETE" {
				req.Body = ""
			} else if len(reqBody) > 0 {
				req.Body = string(reqBody)
			}
		}
	} else {
		req.Body = string(reqBody)
	}
	req.RemoteIP = getIP(r).String()
	if len(meta) > 0 {
		req.Meta = &meta
	}
	return &req
}

func httpInfo(w http.ResponseWriter, r *http.Request) {
	req := getRequestInfo(r)
	resp, _ := json.MarshalIndent(req, "", "\t")

	if strings.HasSuffix(r.URL.Path, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><head><title>%s</title><head/><h1>%s</h1>"+
			"<pre>%s</pre></html>", "Request Infos", "Request Infos", string(resp))
	} else {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
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

// StripPrefix returns a handler that serves HTTP requests
// by removing the given prefix from the request URL's Path
// and invoking the handler h. StripPrefix handles a
// request for a path that doesn't begin with prefix by
// replying with an HTTP 404 not found error.
func StripPrefix(prefix string, h http.Handler) http.Handler {
	if prefix == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := strings.TrimPrefix(r.URL.Path, prefix); len(p) < len(r.URL.Path) {
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.RequestURI = strings.TrimPrefix(r.RequestURI, prefix)
			r2.URL.Path = p
			h.ServeHTTP(w, r2)
		} else {
			http.NotFound(w, r)
		}
	})
}

func getIPV6() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("interfaces error %w", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.IPv6len != 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", fmt.Errorf("addr error %w", err)
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() == nil {
					if !(strings.HasPrefix(ipNet.IP.String(), "fe80:") || strings.HasPrefix(ipNet.IP.String(), "fc00:")) {
						return ipNet.IP.String(), nil
					}
				}
			}
		}
	}
	return "", errors.New("ip not found")
}

// ListenAndServeHTTP3 listens on the given network address for both, TLS and QUIC
func ListenAndServeHTTP3(addr, certFile, keyFile string, handler http.Handler, http3Only bool) error {
	// Load certs
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS12,
	}

	if addr == "" {
		addr = ":https"
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	if handler == nil {
		handler = http.DefaultServeMux
	}
	// Start the servers
	quicServer := &http3.Server{
		TLSConfig: config,
		Handler:   handler,
	}

	hErr := make(chan error)
	qErr := make(chan error)

	if !http3Only {
		go func() {
			hErr <- http.ListenAndServeTLS(addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				quicServer.SetQuicHeaders(w.Header())
				handler.ServeHTTP(w, r)
			}))
		}()
	}
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}

// LogHandler mix grpc and http in one Handler
func LogHandler(h http.Handler) http.Handler {
	mix := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *cors {
			enableCors(w, r)
		}
		req := getRequestInfo(r)
		data, _ := json.Marshal(req)
		log.Info().Msg(string(data))
		h.ServeHTTP(w, r)
	})
	server := &http2.Server{}
	return h2c.NewHandler(mix, server)
}
