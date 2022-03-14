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
	var (
		caPrivyKey *rsa.PrivateKey
		caBytes    []byte
	)
	if caPrivyKey, err = rsa.GenerateKey(rand.Reader, 4096); err != nil {
		CheckErr(err)
		return "", ""
	}
	// create the CA
	if caBytes, err = x509.CreateCertificate(rand.Reader, ca, ca, &caPrivyKey.PublicKey, caPrivyKey); err != nil {
		CheckErr(err)
		return "", ""
	}

	// pem encode
	var caPEM = new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		CheckErr(err)
		return "", ""
	}

	// caPrivyKey encode
	var caPrivyKeyPEM = new(bytes.Buffer)
	if err = pem.Encode(caPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivyKey),
	}); err != nil {
		CheckErr(err)
		return "", ""
	}

	return caPEM.String(), caPrivyKeyPEM.String()
}

func certSetup(caPEMSQL, CaPrivyKeyPEMSQL, certCommonName, certOrganization, country, host string) (string, string) {
	// Parsing ca configuration
	var (
		ca           tls.Certificate
		caTemplate   *x509.Certificate
		certPrivyKey *rsa.PrivateKey
		certBytes    []byte
	)
	ca, caTemplate = getCertificate([]byte(caPEMSQL), []byte(CaPrivyKeyPEMSQL))
	// set up our server certificate
	cert := certificateTemplate(certCommonName, certOrganization, country, host, 2, false)
	// create our private and public key
	if certPrivyKey, err = rsa.GenerateKey(rand.Reader, 4096); err != nil {
		CheckErr(err)
		return "", ""
	}
	// create the CA
	if certBytes, err = x509.CreateCertificate(rand.Reader, cert, caTemplate, &certPrivyKey.PublicKey, ca.PrivateKey); err != nil {
		CheckErr(err)
		return "", ""
	}
	// pem encode
	certPEM := new(bytes.Buffer)
	if err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		CheckErr(err)
		return "", ""
	}
	// caPrivyKey encode
	var certPrivyKeyPEM = new(bytes.Buffer)
	if err = pem.Encode(certPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivyKey),
	}); err != nil {
		CheckErr(err)
		return "", ""
	}
	return certPEM.String(), certPrivyKeyPEM.String()
}

func domainProcessing(template *x509.Certificate, host string) *x509.Certificate {
	// IP，DNS, CommonName参数
	if template.IsCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		// string to []string
		for _, v := range strings.Split(host, " ") {
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

func domainResolution(template *x509.Certificate) (string, string) {
	var (
		certCommonName string
		hostTmp        []string
	)

	if template.IsCA == true {
		hostTmp = append(hostTmp, "root")
	} else {
		// []string to string
		if template.DNSNames != nil {
			for _, v := range template.DNSNames {
				hostTmp = append(hostTmp, v)
			}
		}
		if template.IPAddresses != nil {
			// []string to string
			for _, v := range template.IPAddresses {
				hostTmp = append(hostTmp, v.String())
			}
		}
		if len(template.DNSNames) > 0 {
			certCommonName = template.DNSNames[0]
		}
	}
	if len(hostTmp) == 0 {
		CheckErr(errors.New("cert 没有找到IP或者域名"))
		return "", ""
	}
	hostTmp2 := strings.Join(hostTmp, " ")
	return hostTmp2, certCommonName
}

func ImportCert(PEMSQL, PrivyKeyPEMSQL string) {
	if PEMSQL == "default" || PrivyKeyPEMSQL == "default" {
		CheckErr(errors.New("没有设置证书内容，请检查证书内容！"))
		return
	}
	// 从网页传过来的数据不存在文件
	certificatePEM, certificatePrivyKeyPEM := []byte(PEMSQL), []byte(PrivyKeyPEMSQL)
	_, template := getCertificate(certificatePEM, certificatePrivyKeyPEM)
	//Warning("证书内容有效!: ", template.Subject.CommonName)
	// 域名解析处理
	host, _ = domainResolution(template)
	//var caPEMSQLTmp, caPrivyKeyPEMSQLTmp string
	if caStatus, _, _ = CaInquire(template.Issuer.CommonName, template.Subject.CommonName, host, template.PublicKeyAlgorithm.String()); caStatus == true {
		CaAdd(template.Issuer.CommonName, template.Subject.CommonName, host, template.PublicKeyAlgorithm.String(), template.NotAfter.Format("2006-01-02 15:04:05"), string(certificatePEM), string(certificatePrivyKeyPEM))
	}
}

func getCertificate(PEM, PrivyKeyPEM []byte) (tls.Certificate, *x509.Certificate) {
	var ca, err = tls.X509KeyPair(PEM, PrivyKeyPEM)
	if err != nil {
		CheckErr(errors.New("证书内容有误，请检查证书内容！" + err.Error()))
	}
	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		CheckErr(errors.New("证书内容有误，请检查证书内容！"))
	}
	return ca, ca.Leaf
}

func WriteCert(caPEM, caPrivyKeyPEM, caPEMFile, caPrivyKeyPEMFile string) {
	Notice(" 导出证书公钥:       ", caPEMFile)
	if err = ioutil.WriteFile(caPEMFile, []byte(caPEM), 0644); err != nil {
		CheckErr(err)
		return
	}
	Notice(" 导出证书私钥:       ", caPrivyKeyPEMFile+"\n")
	if err = ioutil.WriteFile(caPrivyKeyPEMFile, []byte(caPrivyKeyPEM), 0644); err != nil {
		CheckErr(err)
		return
	}
}

func VerifyDomainCa(caTLSConf, certTLSConf *tls.Config, host string) {
	var (
		resp          *http.Response
		respBodyBytes []byte
	)
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprintln(w, "Success!"); err != nil {
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
	if resp, err = http.Get("https://" + tmpDomain); err != nil {
		CheckErr(err)
		return
	}

	if respBodyBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		CheckErr(err)
		return
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "Success!" {
		Warning("证书验证成功!", "")
	} else {
		CheckErr(errors.New("证书验证失败!"))
	}
}

func Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol string) (string, string, string, string) {
	var (
		certpair tls.Certificate
	)
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
	if certpair, err = tls.X509KeyPair([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL)); err != nil {
		CheckErr(err)
		return "", "", "", ""
	}
	certTLSConf = &tls.Config{
		Certificates: []tls.Certificate{certpair},
	}
	// Get Host
	_, certTemplate := getCertificate([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL))
	host, certCommonName = domainResolution(certTemplate)
	// where The Test Was Successful
	// Verify (ca cert)certificate is ok?
	if certCommonName != "" {
		VerifyDomainCa(caTLSConf, certTLSConf, certCommonName)
	} else {
		// TODO 现在需要设计 验证 跟证书 和 服务证书 之间是否存在证书链接
		Notice("暂时没有IP证书的验证方式,请尝试上传服务器验证", "")
	}
	// << Check whether a certificate exists
	return caPEMSQL, caPrivyKeyPEMSQL, certPEMSQL, certPrivyKeyPEMSQL
}
