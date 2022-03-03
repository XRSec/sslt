package src

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

func VerifyDomainCa(caTLSConf, certTLSConf *tls.Config, host string) {
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Success!")
		if err != nil {
			return
		}
	}))
	server.TLS = certTLSConf
	server.StartTLS()
	defer server.Close()

	// <-- Upgrade dns
	tmpDomain := strings.Replace(server.URL, "https://127.0.0.1", host, -1)
	tmpIP := strings.Replace(server.URL, "https://", "", -1)

	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		color.Red(" [ Start verify ]")
		color.Green("  Address Original = %v", addr)
		if addr == tmpDomain {
			addr = tmpIP
			color.Green("  Address Modified = %v", addr)
		}
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return dialer.DialContext(ctx, network, addr)
	}
	// Upgrade DNS -->

	// set up the http.Client using our certificate signed by our CA
	http.DefaultTransport.(*http.Transport).TLSClientConfig = caTLSConf
	//time.Sleep(time.Second * 10)

	// make a request to the server
	resp, err := http.Get("https://" + tmpDomain)
	CheckErr(err)
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "Success!" {
		color.Red(" [ %v ]", body)
	} else {
		color.Red(" [ not successful! ]")
	}
}
