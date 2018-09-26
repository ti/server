package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clbanning/mxj"
	"path"
	"os"
)

var (
	port       = flag.Int("p", 8080, "port to listen")
	logBody    = flag.Bool("l", true, "write http body log on std out")
	dir        = flag.String("d", "./", "dir to server")
	decodeBody = flag.Bool("b", false, "decode as struct")
	cert       = flag.String("cert", "", "ssl cert")
	key        = flag.String("key", "", "ssl key")
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
	http.Handle("/_info/", http.StripPrefix("/_info", http.HandlerFunc(httpInfo)))
	http.Handle("/", fileServer(*dir))

	if scheme == "https" {
		err = http.ServeTLS(listener, nil, *cert, *key)
	} else {
		err = http.Serve(listener, nil)
	}
	panic(err)
}

func fileServer(dir string) http.Handler {
	fs := http.Dir(dir)
	fileDir := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fs.Open(path.Clean(r.URL.Path))
		if os.IsNotExist(err) {
			r.URL.Path = "/404.html"
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

var corsSuffix = []string{"nx.run", "nanxi.li"}

var safeUrlSuffix = []string{"login", "token"}

func cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
	origin := r.Header.Get("Origin")
	if origin != "" {
		if uri, err := url.Parse(origin); err == nil {
			if uri.Host != r.Host {
				for _, v := range safeUrlSuffix {
					if strings.HasSuffix(r.URL.Path, v) {
						return
					}
				}
				for _, v := range corsSuffix {
					if strings.HasSuffix(uri.Host, v) {
						w.Header().Set("Access-Control-Allow-Credentials", "true")
						break
					}
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				w.Header().Set("Vary", "Origin, Accept-Encoding")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}
	}
}

func httpInfo(w http.ResponseWriter, r *http.Request) {
	cors(w, r)
	q := r.URL.Query()
	if re := q.Get("r"); re != "" {
		q.Del("r")
		http.Redirect(w, r, re+"?"+q.Encode(), 302)
		return
	}
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
	_, decode := r.URL.Query()["decode_body"]
	if !*decodeBody || decode {
		if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
			req.Body = string(b)
		}
	} else {
		contentType := r.Header.Get("Content-Type")
		if *decodeBody && strings.Contains(contentType, "json") {
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
		} else {
			if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
				req.Body = string(b)
			}
		}
	}
	if *logBody {
		jsonBytes, _ := json.Marshal(req)
		fmt.Println(string(jsonBytes))
	}
	req.RemoteIP = getIP(r).String()
	if len(meta) > 0 {
		req.Meta = &meta
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
