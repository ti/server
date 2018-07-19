package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"
)

var addr = flag.String("addr", ":9418", "Bind TCP Address")

func main() {
	flag.Parse()
	log.Println("Starting server at " + *addr)
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/rpc/ping.action", ping)
	mux.HandleFunc("/rpc/obtainticket.action", obtainTicket)
	log.Fatalln(http.ListenAndServe(*addr, lowUriHandler(mux)))
}

func lowUriHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.ToLower(r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Server is running!"))
}

func ping(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	salt := r.URL.Query().Get("salt")
	xmlResponse := "<PingResponse><message></message><responseCode>OK</responseCode><salt>" + salt + "</salt></PingResponse>"
	xmlSignature, _ := signature(xmlResponse)
	w.Header().Add("Content-Type", "text/xml")
	w.Write([]byte("<!-- " + xmlSignature + " -->\n" + xmlResponse))
}

func obtainTicket(w http.ResponseWriter, r *http.Request) {
	salt := r.URL.Query().Get("salt")
	username := r.URL.Query().Get("userName")
	if salt == "" || username == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	prolongationPeriod := 607875500
	xmlResponse := "<ObtainTicketResponse><message></message><prolongationPeriod>" + strconv.Itoa(prolongationPeriod) + "</prolongationPeriod><responseCode>OK</responseCode><salt>" + salt + "</salt><ticketId>1</ticketId><ticketProperties>licensee=" + username + "\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>"
	xmlSignature, _ := signature(xmlResponse)
	w.Header().Add("Content-Type", "text/xml")
	w.Write([]byte("<!-- " + xmlSignature + " -->\n" + xmlResponse))
}

var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALecq3BwAI4YJZwhJ+snnDFj3lF3DMqNPorV6y5ZKXCiCMqj8OeOmxk4YZW9aaV9
ckl/zlAOI0mpB3pDT+Xlj2sCAwEAAQJAW6/aVD05qbsZHMvZuS2Aa5FpNNj0BDlf38hOtkhDzz/h
kYb+EBYLLvldhgsD0OvRNy8yhz7EjaUqLCB0juIN4QIhAOeCQp+NXxfBmfdG/S+XbRUAdv8iHBl+
F6O2wr5fA2jzAiEAywlDfGIl6acnakPrmJE0IL8qvuO3FtsHBrpkUuOnXakCIQCqdr+XvADI/UTh
TuQepuErFayJMBSAsNe3NFsw0cUxAQIgGA5n7ZPfdBi3BdM4VeJWb87WrLlkVxPqeDSbcGrCyMkC
IFSs5JyXvFTreWt7IQjDssrKDRIPmALdNjvfETwlNJyY
-----END RSA PRIVATE KEY-----
`)

func signature(message string) (string, error) {
	pemKey, _ := pem.Decode(privateKey)
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)

	hashedMessage := md5.Sum([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.MD5, hashedMessage[:])
	if err != nil {
		return "", err
	}
	hexSignature := hex.EncodeToString(signature)
	return hexSignature, nil
}
