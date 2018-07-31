package main

import (
	"net/http"
	"fmt"
	"flag"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"github.com/coreos/etcd/clientv3"
	"strconv"
	"time"
	"io/ioutil"
	"bytes"
)

var addr = flag.String("addr", ":5080", "addr to serve on")
var uri = flag.String("uri", "etcd://127.0.0.1:2379", "etcd server")
var pretty = flag.Bool("pretty", false, "pretty print the out put?")

var client *clientv3.Client

func main() {
	flag.Parse()
	var err error
	client, err = newEtcdClient(*uri)
	if err != nil {
		panic(err)
	}
	fmt.Println("Available on: " + *addr)
	http.HandleFunc("/", ectd)
	http.HandleFunc("/ip", ip)
	panic(http.ListenAndServe(*addr, nil))
}

//ip 获取当前IP地址
func ip(w http.ResponseWriter, r *http.Request) {
	index := strings.LastIndex(r.RemoteAddr, ":")
	w.Write([]byte(r.RemoteAddr[:index]))
}

func etcdPost(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Path
	if prefix == "/" {
		prefix = ""
	}
	if strings.HasPrefix(prefix, "/_") {
		prefix = prefix[2:]
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte("oauth2: cannot fetch token: " + err.Error()))
		return
	}
	isJson := false
	if len(body) > 0 && (body[0] == byte('{') || body[0] == byte('[')) {
		var data interface{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&data); err != nil {
			http.Error(w, "JSON decode error: "+err.Error(), 400)
			return
		}
		body, _ = json.Marshal(data)
		isJson = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = client.Put(ctx, prefix, string(body))
	if err != nil {
		panic("register etcd status error " + err.Error())
	}
	cancel()
	if isJson {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Write([]byte(body))
}

//all 列出etcd中的所有键值对
func ectd(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Path
	if prefix == "/" {
		prefix = ""
	}
	if strings.HasPrefix(prefix, "/_") {
		prefix = prefix[2:]
	}
	if r.Method == "DELETE" {
		resp, err := client.Delete(context.TODO(), prefix, clientv3.WithPrefix())
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(strconv.FormatInt(resp.Deleted, 16) + " items DELETED"))
		return
	}

	if r.Method == "POST" {
		etcdPost(w, r)
		return
	}

	resp, err := client.Get(context.TODO(), prefix, clientv3.WithPrefix())
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	isJson := false
	result := make(map[string]interface{})
	for _, v := range resp.Kvs {
		key := string(v.Key)
		value := string(v.Value)
		if len(v.Value) > 0 && (v.Value[0] == byte('{') || v.Value[0] == byte('[')) {
			var data interface{}
			if err := json.Unmarshal(v.Value, &data); err == nil {
				result[key] = data
				isJson = true
			} else {
				result[key] = value
			}
		} else {
			result[key] = value
		}
	}
	var ret []byte
	if len(result) > 1 {
		isJson = true
		ret = marshal(result)
	} else if len(result) == 1 {
		if isJson {
			for k, v := range result {
				if k == r.URL.Path {
					ret = marshal(v)
				} else {
					ret = marshal(result)
				}
			}
		} else {
			ret = resp.Kvs[0].Value
		}
	}
	if isJson {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Write(ret)
}

func marshal(src interface{}) (ret []byte) {
	if *pretty {
		ret, _ = json.MarshalIndent(src, "", "\t")
	} else {
		ret, _ = json.Marshal(src)
	}
	return
}

func newEtcdClient(rawurl string) (client *clientv3.Client, err error) {
	var timeout = 5 * time.Second
	var uri *url.URL
	uri, err = url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	etcdConfig := clientv3.Config{
		Endpoints:   strings.Split(uri.Host, ","),
		DialTimeout: timeout,
	}
	if u := uri.User; u != nil {
		etcdConfig.Username = u.Username()
		etcdConfig.Password, _ = u.Password()
	}
	client, err = clientv3.New(etcdConfig)
	return
}
