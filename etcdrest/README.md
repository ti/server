# ETCD Restful 

Simple ETCD Restful Viewer

```bash
go get github.com/ti/server/etcdrest
etcdrest -uri etcd://192.168.1.2:2379:192.168.1.3:2379
```


`GET` http://127.0.0.1:5080/your/path  ? get all etcd text by prefix /your/path

`POST` http://127.0.0.1:5080your/path  ? edit the text

`DELETE` http://127.0.0.1:5080/your/path  ? delete the text
