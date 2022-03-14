package x509

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
)

var (
	err                                                              error
	caStatus, certStatus                                             bool
	caPEMSQL, caPrivyKeyPEMSQL, certPEMSQL, certPrivyKeyPEMSQL, host string
	caTLSConf, certTLSConf                                           *tls.Config
)

func certificateTemplate(templateCommonName, templateOrganization, templateCountry, host string, notAfterYear int, isCA bool) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   templateCommonName,
			Organization: []string{templateOrganization},
			Country:      []string{templateCountry},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(notAfterYear, 0, 0),
		//SubjectKeyId: []byte{1, 2, 3, 4, 6},
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
	}

	// IP，DNS, CommonName参数
	template = domainProcessing(template, host)
	return template
}

func caSetup(caCommonName, caOrganization, country string) (string, string) {
	ca := certificateTemplate(caCommonName, caOrganization, country, "", 10, true)
	// set up our CA certificate
	// create our private and public key
	caPrivyKey, err := rsa.GenerateKey(rand.Reader, 4096)
	CheckErr(err)
	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivyKey.PublicKey, caPrivyKey)
	CheckErr(err)
	// pem encode
	var caPEM = new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	CheckErr(err)
	// caPrivyKey encode
	var caPrivyKeyPEM = new(bytes.Buffer)
	err = pem.Encode(caPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivyKey),
	})
	CheckErr(err)
	return caPEM.String(), caPrivyKeyPEM.String()
}

func certSetup(caPEMSQL, CaPrivyKeyPEMSQL, certCommonName, certOrganization, country, host string) (string, string) {
	// Parsing ca configuration
	ca, caTemplate := getCertificate([]byte(caPEMSQL), []byte(CaPrivyKeyPEMSQL))
	// set up our server certificate
	cert := certificateTemplate(certCommonName, certOrganization, country, host, 2, false)
	// create our private and public key
	certPrivyKey, err := rsa.GenerateKey(rand.Reader, 4096)
	CheckErr(err)
	// create the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caTemplate, &certPrivyKey.PublicKey, ca.PrivateKey)
	CheckErr(err)
	// pem encode
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	CheckErr(err)
	// caPrivyKey encode
	var certPrivyKeyPEM = new(bytes.Buffer)
	err = pem.Encode(certPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivyKey),
	})
	CheckErr(err)
	return certPEM.String(), certPrivyKeyPEM.String()
}

func domainProcessing(template *x509.Certificate, host string) *x509.Certificate {
	// IP，DNS, CommonName参数
	if template.IsCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		for _, v := range strings.Split(host, ",") {
			if ip := net.ParseIP(v); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, v)
			}
		}
		if len(template.DNSNames) > 0 {
			template.Subject.CommonName = template.DNSNames[0]
		}
	}
	return template
}

func domainResolution(template *x509.Certificate) string {
	var host string
	if template.IsCA == true {
		host = "root"
	} else {
		if template.DNSNames != nil {
			for _, v := range template.DNSNames {
				host += " " + v
			}
		}
		if template.IPAddresses != nil {
			// []string to string
			for _, v := range template.IPAddresses {
				host += " " + v.String()
			}
		}
	}
	if host == "" {
		CheckErr(errors.New("cert 没有找到IP或者域名"))
	}
	return host
}

func ImportQuire(tableName, commonName, host, protocol, data string, certificatePEM, certificatePrivyKeyPEM []byte) {
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(tableName, commonName, host, protocol); caStatus == true {
		CaAdd(tableName, commonName, host, protocol, data, bytes.NewBuffer(certificatePEM), bytes.NewBuffer(certificatePrivyKeyPEM))
	}
}

func ImportCert(caPEMFILE, caPrivyKeyPEMFILE string) {
	if caPEMFILE == "default" && caPrivyKeyPEMFILE == "default" {
		CheckErr(errors.New("没有设置证书内容，请检查证书内容！"))
	}
	// 从网页传过来的数据不存在文件
	certificatePEM, certificatePrivyKeyPEM := []byte(caPEMFILE), []byte(caPrivyKeyPEMFILE)

	_, template := getCertificate(certificatePEM, certificatePrivyKeyPEM)
	//Warning("证书内容有效!: ", template.Subject.CommonName)
	// 域名解析处理
	host = domainResolution(template)

	ImportQuire(template.Issuer.CommonName, template.Subject.CommonName, host, string(template.PublicKeyAlgorithm), template.NotAfter.Format("2006-01-02 15:04:05"), certificatePEM, certificatePrivyKeyPEM)
}

func getCertificate(PEM, PrivyKeyPEM []byte) (tls.Certificate, *x509.Certificate) {
	var ca, err = tls.X509KeyPair(PEM, PrivyKeyPEM)
	if err != nil {
		CheckErr(errors.New("证书内容有误，请检查证书内容！"))
	}
	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		CheckErr(errors.New("证书内容有误，请检查证书内容！"))
	}
	return ca, ca.Leaf
}

func WriteCert(caPEM, caPrivyKeyPEM, caPEMFile, caPrivyKeyPEMFile string) {
	Notice(" 导出证书公钥:       ", caPEMFile)
	err = ioutil.WriteFile(caPEMFile, []byte(caPEM), 0644)
	CheckErr(err)

	Notice(" 导出证书私钥:       ", caPrivyKeyPEMFile+"\n")
	err = ioutil.WriteFile(caPrivyKeyPEMFile, []byte(caPrivyKeyPEM), 0644)
	CheckErr(err)
}

func VerifyDomainCa(caTLSConf, certTLSConf *tls.Config, host string) {
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Success!")
		if err != nil {
			CheckErr(err)
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
		Warning("开始验证证书", "")
		Notice("证书域名:", addr)
		if addr == tmpDomain {
			addr = tmpIP
			Notice("证书测试IP:", addr)
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
		Warning("证书验证成功!", "")
	} else {
		CheckErr(errors.New("证书验证失败!"))
	}
}

func Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol string) {
	// 预处理用户输入的内容
	host = strings.Replace(host, ",", " ", -1)
	// Check whether a certificate exists >>
	// CA Generate
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(caCommonName, caCommonName, "root", protocol); caStatus == true {
		//Notice("生成证书字段:", "「CA CommonName: "+caCommonName+"」「CA Organization: "+caCommonName+"」「Protocol: "+protocol+"」")
		caPEMSQL, caPrivyKeyPEMSQL = caSetup(caCommonName, caOrganization, country)
		ImportCert(caPEMSQL, caPrivyKeyPEMSQL)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(caPEMSQL))
	caTLSConf = &tls.Config{
		RootCAs: caPool,
	}
	// SERVER Generate
	if certStatus, certPEMSQL, certPrivyKeyPEMSQL = CaInquire(certCommonName, certCommonName, host, protocol); certStatus == true {
		certPEMSQL, certPrivyKeyPEMSQL = certSetup(caPEMSQL, caPrivyKeyPEMSQL, certCommonName, certOrganization, country, host)
		ImportCert(certPEMSQL, certPrivyKeyPEMSQL)
	}
	certpair, err := tls.X509KeyPair([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL))
	CheckErr(err)
	certTLSConf = &tls.Config{
		Certificates: []tls.Certificate{certpair},
	}
	// Get Host
	_, certTemplate := getCertificate([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL))
	host = domainResolution(certTemplate)

	// where The Test Was Successful
	// Verify (ca cert)certificate is ok?
	if net.ParseIP(host) == nil {
		VerifyDomainCa(caTLSConf, certTLSConf, host)
	} else {
		// TODO 现在需要设计 验证 跟证书 和 服务证书 之间是否存在证书链接
		Notice(" 暂时没有IP证书的验证方式,请尝试上传服务器验证", "")
	}
	// << Check whether a certificate exists
}
