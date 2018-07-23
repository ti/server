package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"io/ioutil"
	"encoding/json"
)

var (
	port = flag.Int("p", 8080, "port to listen")
	dir  = flag.String("d", "./", "dir to server")
)

func main() {
	flag.Parse()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Printf("\u001b[31m[ERROR] %s\u001b[0m\n", err)
		return
	}
	fmt.Printf("Starting up http-server, serving \u001b[36m%s \u001b[0m \nAvailable on:\n", *dir)
	addrs, _ := net.InterfaceAddrs()
	for _, rawAddr := range addrs {
		if ipnet, ok := rawAddr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			fmt.Printf("\t\u001b[34mhttp://%s:%d\u001b[0m\n", ipnet.IP.To4().String(), *port)
		}
	}
	fmt.Println("Hit CTRL-C to stop the server")
	http.Handle("/_info/", http.HandlerFunc(httpInfo))
	http.Handle("/", http.FileServer(http.Dir(*dir)))
	panic(http.Serve(listener, nil))
}

func httpInfo(w http.ResponseWriter, r *http.Request) {
	req := make(map[string]interface{})
	type URL struct {
		Scheme   string
		RawQuery string
		Path     string
		Host     string
		Query    interface{} `json:"Query,omitempty"`
		User     interface{} `json:"User,omitempty"`
	}
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
		}{
			user, pass,
		}
	}
	req["Host"] = r.Host
	req["Method"] = r.Method
	req["URL"] = u
	req["Header"] = r.Header
	req["RequestURI"] = r.RequestURI
	if r.TLS != nil {
		req["TLS"] = r.TLS
	}
	req["RemoteAddr"] = r.RemoteAddr
	req["Proto"] = r.Proto
	if r.ContentLength > 0 {
		req["ContentLength"] = r.ContentLength
	}
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		var data interface{}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&data); err != nil {
			req["Body"] = data
		}
	} else if strings.Contains(contentType, "form") {
		r.ParseForm()
		req["Body"] = r.PostForm
	} else {
		if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
			req["Body"] = string(b)
		}
	}
	if b, _ := ioutil.ReadAll(r.Body); len(b) > 0 {
		if strings.Contains(contentType, "json") {

		}
	}
	resp, _ := json.Marshal(req)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}
