package rsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	. "sslt/src"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	caPEMSQL, caPrivyKeyPEMSQL, certPEMSQL, certPrivyKeyPEMSQL, host string
	caStatus, certStatus                                             bool
	CaTLSConf, CertTLSConf                                           *tls.Config
)

func caSetup(caCommonName, caOrganization, country, protocol string) (*tls.Config, string, string) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{caOrganization},
			Country:      []string{country},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// create our private and public key
	caPrivyKey, err := rsa.GenerateKey(rand.Reader, 4096)

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivyKey.PublicKey, caPrivyKey)
	CheckErr(err)

	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	CheckErr(err)

	// caPrivyKey encode
	caPrivyKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivyKey),
	})
	CheckErr(err)

	// write ca to sql & file
	// 如果存在证书则导出
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(caCommonName, caCommonName, host, protocol); caStatus == false {
		//certPEM = new(bytes.Buffer)
	} else {
		caPEMSQL, caPrivyKeyPEMSQL = CaAdd(caCommonName, caCommonName, host, protocol, ca.NotAfter.Format("2006-01-02 15:04:05"), caPEM, caPrivyKeyPEM)
	}
	caPEM = bytes.NewBuffer([]byte(caPEMSQL))
	caPrivyKeyPEM = bytes.NewBuffer([]byte(caPrivyKeyPEMSQL))

	// generate certs TLSConf
	capool := x509.NewCertPool()
	capool.AppendCertsFromPEM(caPEM.Bytes())
	caTLSConf := &tls.Config{
		RootCAs: capool,
	}
	return caTLSConf, caPEMSQL, caPrivyKeyPEMSQL
}

func certSetup(caPEMSQL, CaPrivyKeyPEMSQL, certCommonName, certOrganization, country, host, protocol string) (*tls.Config, string, string) {
	// Parsing ca configuration
	var ca, err = tls.X509KeyPair([]byte(caPEMSQL), []byte(CaPrivyKeyPEMSQL))
	CheckErr(err)
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		CheckErr(err)
	}
	var x509ca *x509.Certificate
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		CheckErr(err)
	}
	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   certCommonName,
			Organization: []string{certOrganization},
			Country:      []string{country},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0),
		//SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// IP，DNS参数
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else if strings.Contains(host, " ") {
		// string to []string
		// 判断是否存在逗号
		hostTmp := strings.Split(host, " ")
		for i := 0; i < len(hostTmp); i++ {
			if ip := net.ParseIP(hostTmp[i]); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, hostTmp[i])
				if len(hostTmp) == 1 {
					cert.Subject.CommonName = hostTmp[0]
				}
			}
		}
	} else {
		cert.DNSNames = append(cert.DNSNames, host)
		cert.Subject.CommonName = host
	}

	// create our private and public key
	certPrivyKey, err := rsa.GenerateKey(rand.Reader, 4096)
	CheckErr(err)

	// create the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, x509ca, &certPrivyKey.PublicKey, ca.PrivateKey)
	CheckErr(err)

	// pem encode
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	CheckErr(err)

	// caPrivyKey encode
	certPrivyKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivyKey),
	})
	CheckErr(err)

	// write ca to sql & file
	// 如果存在证书则导出
	if certStatus, certPEMSQL, certPrivyKeyPEMSQL = CaInquire(x509ca.Issuer.CommonName, certCommonName, host, protocol); certStatus == false {
		//certPEM = new(bytes.Buffer)
	} else {
		certPEMSQL, certPrivyKeyPEMSQL = CaAdd(x509ca.Issuer.CommonName, certCommonName, host, protocol, cert.NotAfter.Format("2006-01-02 15:04:05"), certPEM, certPrivyKeyPEM)
	}
	certPEM = bytes.NewBuffer([]byte(certPEMSQL))
	certPrivyKeyPEM = bytes.NewBuffer([]byte(certPrivyKeyPEMSQL))

	// generate certs TLSConf
	certpair, err := tls.X509KeyPair(certPEM.Bytes(), certPrivyKeyPEM.Bytes())
	CheckErr(err)
	CertTLSConf = &tls.Config{
		Certificates: []tls.Certificate{certpair},
	}
	return CertTLSConf, certPEMSQL, certPrivyKeyPEMSQL
}

func ImportQuire(tableName, commonName, host, protocol, data string, certificatePEM, certificatePrivyKeyPEM []byte) {
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(tableName, commonName, host, protocol); caStatus == true {
		CaAdd(tableName, commonName, host, protocol, data, bytes.NewBuffer(certificatePEM), bytes.NewBuffer(certificatePrivyKeyPEM))
	}
}

func ImportCert(caPEMFILE, caPrivyKeyPEMFILE string) {
	certificatePEM, err := ioutil.ReadFile(caPEMFILE)
	CheckErr(err)
	certificatePrivyKeyPEM, err := ioutil.ReadFile(caPrivyKeyPEMFILE)
	CheckErr(err)
	var ca, caErr = tls.X509KeyPair(certificatePEM, certificatePrivyKeyPEM)
	CheckErr(caErr)
	color.Red(" [ 证书文件存在! ]")
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		CheckErr(caErr)
	}
	// 根证书不需要设置域名和IP
	if ca.Leaf.IsCA == true {
		host = "root"
	} else {
		if ca.Leaf.DNSNames != nil {
			// 一个证书不至于多个域名的吧
			for i := 0; i < len(ca.Leaf.DNSNames); i++ {
				if len(ca.Leaf.DNSNames) == 1 {
					host = ca.Leaf.DNSNames[0]
				} else if i+1 < len(ca.Leaf.DNSNames) {
					host = " " + ca.Leaf.DNSNames[i] + host
				} else {
					host = ca.Leaf.DNSNames[i] + host
				}
			}
		}
		if ca.Leaf.IPAddresses != nil {
			// []string to string
			for i := 0; i < len(ca.Leaf.IPAddresses); i++ {
				if len(ca.Leaf.IPAddresses) == 1 {
					host = ca.Leaf.IPAddresses[0].String()
				} else if i+1 < len(ca.Leaf.IPAddresses) {
					host = ca.Leaf.IPAddresses[i].String() + " " + host
				} else {
					host = ca.Leaf.IPAddresses[i].String() + " " + host
				}
			}
		}
		if host == "" {
			CheckErr(errors.New("cert 没有找到IP或者域名"))
		}
	}
	ImportQuire(ca.Leaf.Issuer.CommonName, ca.Leaf.Subject.CommonName, host, "rsa", ca.Leaf.NotAfter.Format("2006-01-02 15:04:05"), certificatePEM, certificatePrivyKeyPEM)
}

func VerifyDomainCa(caTLSConf, certTLSConf *tls.Config, host string) {
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Success!")
		CheckErr(err)
	}))
	server.TLS = certTLSConf
	server.StartTLS()
	defer server.Close()

	// <-- Upgrade dns
	tmpDomain := strings.Replace(server.URL, "https://127.0.0.1", host, -1)
	tmpIP := strings.Replace(server.URL, "https://", "", -1)

	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		color.Red(" [ 开始验证证书 ]")
		color.Green("  证书域名    =  %v", addr)
		if addr == tmpDomain {
			addr = tmpIP
			color.Green("  证书测试IP  =  %v", addr)
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

func WriteCert(caPEM, caPrivyKeyPEM, caPEMFile, caPrivyKeyPEMFile string) {
	Notice(" 导出证书公钥:       ", caPEMFile)
	err := ioutil.WriteFile(caPEMFile, []byte(caPEM), 0644)
	CheckErr(err)
	Notice(" 导出证书私钥:       ", caPrivyKeyPEMFile+"\n")
	err = ioutil.WriteFile(caPrivyKeyPEMFile, []byte(caPrivyKeyPEM), 0644)
	CheckErr(err)
}

func Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol string) (*tls.Config, *tls.Config) {
	/*
		公钥
			查询证书是否存在
				生成证书 -> 匹配证书 -> 数据库存储证书 -> 验证证书 -> 写入证书
			写入证书
		私钥
			查询证书是否存在
				生成证书 -> 匹配证书 -> 数据库存储证书 -> 验证证书 -> 写入证书
			写入证书
	*/
	// Check whether a certificate exists >>
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(caCommonName, caCommonName, "root", protocol); caStatus == true {
		// GENERATE CERTIFICATE
		Notice(" 生成证书字段:      ", "「CA CommonName: "+caCommonName+"」「CA Organization: "+caCommonName+"」「Protocol: "+protocol+"」")
		CaTLSConf, caPEMSQL, caPrivyKeyPEMSQL = caSetup(caCommonName, caOrganization, country, protocol)
	} else {
		// Read and write the certificate from the database
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM([]byte(caPEMSQL))
		CaTLSConf = &tls.Config{
			RootCAs: caPool,
		}
	}
	WriteCert(caPEMSQL, caPrivyKeyPEMSQL, RootPath+"ca.pem", RootPath+"ca.key.pem")
	// GENERATE CERTIFICATE
	if certStatus, certPEMSQL, certPrivyKeyPEMSQL = CaInquire(certCommonName, certCommonName, host, protocol); certStatus == true {
		CertTLSConf, certPEMSQL, certPrivyKeyPEMSQL = certSetup(caPEMSQL, caPrivyKeyPEMSQL, certCommonName, certOrganization, country, host, protocol)
	} else {
		cert, err := tls.X509KeyPair([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL))
		CheckErr(err)
		CertTLSConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	WriteCert(certPEMSQL, certPrivyKeyPEMSQL, RootPath+"server.pem", RootPath+"server.key.pem")
	return CaTLSConf, CertTLSConf
	// << Check whether a certificate exists
}
