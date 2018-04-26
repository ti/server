package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
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
	panic(http.Serve(listener, http.FileServer(http.Dir(*dir))))
}
