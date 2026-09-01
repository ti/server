// Command server is a small static-file and request-inspection HTTP server.
//
// It only uses the Go standard library: HTTP/1.1, HTTP/2 over TLS and
// unencrypted HTTP/2 (h2c) are all provided by net/http.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// plainPort is always served as plain HTTP, even when -cert/-key are set.
const plainPort = 80

var (
	ports      = flag.String("p", "8080", "ports to listen, comma separated (e.g. 80,443); port 80 is always plain HTTP")
	decodeBody = flag.Bool("b", false, "decode body as struct")
	cors       = flag.Bool("cors", true, "enable cors?")
	dir        = flag.String("d", "./", "dir to serve")
	spa        = flag.Bool("spa", true, "is a single page app?")
	mode       = flag.String("mode", "file", "default router mode [file, info]")
	host       = flag.String("host", "", "the host")
	cert       = flag.String("cert", "", "ssl cert")
	key        = flag.String("key", "", "ssl key")
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func main() {
	flag.Parse()

	portList, err := parsePorts(*ports)
	if err != nil {
		logger.Error("invalid -p", slog.String("value", *ports), slog.Any("error", err))
		os.Exit(1)
	}

	root, err := os.OpenRoot(*dir)
	if err != nil {
		logger.Error("open dir", slog.String("dir", *dir), slog.Any("error", err))
		os.Exit(1)
	}
	defer root.Close()

	files := fileServer(root.FS())
	info := http.HandlerFunc(httpInfo)

	mux := http.NewServeMux()
	mux.Handle("/_info/", StripPrefix("/_info", info))
	mux.Handle("/_www/", StripPrefix("/_www", files))
	if *mode == "info" {
		mux.Handle("/", info)
	} else {
		mux.Handle("/", files)
	}

	// HTTP/1.1 + HTTP/2 (TLS) + unencrypted HTTP/2, replaces x/net/http2/h2c.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	tlsEnabled := *cert != "" && *key != ""
	handler := LogHandler(mux)

	fmt.Printf("Starting up http-server serving \u001b[36m%s \u001b[0m \nAvailable on:\n", root.Name())
	for _, port := range portList {
		for _, u := range localURLs(scheme(port, tlsEnabled), port) {
			fmt.Printf("\t\u001b[34m%s\u001b[0m\n", u)
		}
	}
	fmt.Println("Hit CTRL-C to stop the server")

	// One server per port; port 80 stays plain HTTP even with -cert/-key.
	errs := make(chan error, len(portList))
	for _, port := range portList {
		go func() {
			srv := &http.Server{
				Addr:              fmt.Sprintf(":%d", port),
				Handler:           handler,
				Protocols:         protocols,
				ReadHeaderTimeout: 10 * time.Second,
				TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
				ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
			}
			var err error
			if scheme(port, tlsEnabled) == "https" {
				err = srv.ListenAndServeTLS(*cert, *key)
			} else {
				err = srv.ListenAndServe()
			}
			errs <- fmt.Errorf("port %d: %w", port, err)
		}()
	}

	// Any listener failing is fatal.
	if err := <-errs; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

// scheme reports the protocol used for a port. Port 80 is hardcoded to plain
// HTTP so that "-p 80,443 -cert x -key y" serves 80 unencrypted and 443 over TLS.
func scheme(port int, tlsEnabled bool) string {
	if tlsEnabled && port != plainPort {
		return "https"
	}
	return "http"
}

// parsePorts parses a comma separated port list such as "80,443".
func parsePorts(s string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		port, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", field)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", port)
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("no port given")
	}
	return ports, nil
}

// fileServer serves fsys, falling back to /index.html for unknown paths when
// the -spa flag is set.
func fileServer(fsys fs.FS) http.Handler {
	handler := http.FileServerFS(fsys)
	if !*spa {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(r.URL.Path, "/")
		if name != "" && !exists(fsys, name) && exists(fsys, "index.html") {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			r.RequestURI = "/"
			if r.URL.RawQuery != "" {
				r.RequestURI += "?" + r.URL.RawQuery
			}
		}
		handler.ServeHTTP(w, r)
	})
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

// URL the url
type URL struct {
	Scheme   string
	Path     string
	Host     string
	RawQuery string `json:"RawQuery,omitempty"`
	Query    any    `json:"Query,omitempty"`
	User     any    `json:"User,omitempty"`
}

type request struct {
	Time          string               `json:"time"`
	Method        string               `json:"method,omitempty"`
	RequestURI    string               `json:"request_uri,omitempty"`
	RemoteIP      string               `json:"remote_ip,omitempty"`
	Body          any                  `json:"body,omitempty"`
	Meta          map[string]string    `json:"meta,omitempty"`
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
	if origin == "" {
		return
	}
	uri, err := url.Parse(origin)
	if err != nil || uri.Host == r.Host {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
	h.Set("Vary", "Origin, Accept-Encoding")
	h.Set("Access-Control-Max-Age", "86400")
}

func getRequestInfo(r *http.Request) *request {
	u := URL{Scheme: r.URL.Scheme, RawQuery: r.URL.RawQuery, Path: r.URL.Path, Host: r.Host}
	if q := r.URL.Query(); len(q) > 0 {
		u.Query = q
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if user, pass, ok := r.BasicAuth(); ok {
		u.User = struct {
			Username string
			Password string
		}{user, pass}
	}

	req := &request{
		Time:          time.Now().Format(time.RFC3339),
		Method:        r.Method,
		RequestURI:    r.RequestURI,
		RemoteAddr:    r.RemoteAddr,
		RemoteIP:      getIP(r),
		Proto:         r.Proto,
		Host:          r.Host,
		URL:           u,
		Header:        r.Header,
		TLS:           r.TLS,
		ContentLength: r.ContentLength,
	}

	// Read the body and put it back so the next handler can read it again.
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	contentType := r.Header.Get("Content-Type")
	switch {
	case !*decodeBody:
		req.Body = string(body)
	case strings.Contains(contentType, "json"):
		var data any
		if err := json.Unmarshal(body, &data); err == nil {
			req.Body = data
		} else {
			req.Meta = map[string]string{"error": fmt.Sprintf("json decode error - %s", err)}
		}
	case strings.Contains(contentType, "form"):
		if err := r.ParseForm(); err == nil {
			req.Body = r.PostForm
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	case strings.Contains(contentType, "grpc"):
		// binary payload, do nothing
	case r.Method == http.MethodGet || r.Method == http.MethodDelete:
		req.Body = ""
	default:
		if len(body) > 0 {
			req.Body = string(body)
		}
	}
	return req
}

func httpInfo(w http.ResponseWriter, r *http.Request) {
	resp, _ := json.MarshalIndent(getRequestInfo(r), "", "\t")

	if strings.HasSuffix(r.URL.Path, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><head><title>%s</title><head/><h1>%s</h1>"+
			"<pre>%s</pre></html>", "Request Infos", "Request Infos", resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func getIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		first, _, _ := strings.Cut(ip, ",")
		return strings.TrimSpace(first)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// StripPrefix serves HTTP requests by removing the given prefix from the
// request URL's Path and RequestURI before invoking h. Requests whose path
// does not start with prefix get a 404.
func StripPrefix(prefix string, h http.Handler) http.Handler {
	if prefix == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, prefix)
		if len(p) == len(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = p
		r2.RequestURI = strings.TrimPrefix(r.RequestURI, prefix)
		h.ServeHTTP(w, r2)
	})
}

// localURLs lists the addresses the server can be reached on.
func localURLs(scheme string, port int) []string {
	if *host != "" {
		return []string{fmt.Sprintf("%s://%s:%d", scheme, *host, port)}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{fmt.Sprintf("%s://localhost:%d", scheme, port)}
	}

	var urls []string
	var v6 string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, ip4, port))
			continue
		}
		if v6 == "" && ipNet.IP.IsGlobalUnicast() && !ipNet.IP.IsPrivate() {
			v6 = ipNet.IP.String()
		}
	}
	if v6 != "" {
		urls = append(urls, fmt.Sprintf("%s://[%s]:%d", scheme, v6, port))
	}
	if len(urls) == 0 {
		urls = append(urls, fmt.Sprintf("%s://localhost:%d", scheme, port))
	}
	return urls
}

// LogHandler logs every request as JSON via log/slog and applies CORS headers.
func LogHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *cors {
			enableCors(w, r)
		}
		logger.Info("request", slog.Any("request", getRequestInfo(r)))
		h.ServeHTTP(w, r)
	})
}
