package src

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/fatih/color"
	"net"
	"strings"
)

var (
	caPEMSQL, caPrivyKeyPEMSQL, certPEMSQL, certPrivyKeyPEMSQL string
	caStatus, certStatus                                       bool
	caTLSConf, certTLSConf                                     *tls.Config
)

func GetConfig(caPEMFILE, caPrivyKeyPEMFILE, caCommonName, caOrganization, certCommonName, certOrganization, country, host string) {
	color.Red(" [ Get Config! ]")
	// Get CA Config
	if caPEMFILE != "default" {
		caCommonName = ImportCert(caPEMFILE, caPrivyKeyPEMFILE)
	}
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(strings.Replace(caCommonName, " ", "_", -1), caCommonName, "root"); caStatus == true {
		caTLSConf, caPEMSQL, caPrivyKeyPEMSQL = caSetup(caCommonName, caOrganization, country)
	} else {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM([]byte(caPEMSQL))
		caTLSConf = &tls.Config{
			RootCAs: caPool,
		}
		// Export the certificate from the database
		WriteCert(caPEMSQL, caPrivyKeyPEMSQL, RootPath+"ca.pem", RootPath+"ca.key.pem")
	}
	// Get Cert Config
	if certStatus, certPEMSQL, certPrivyKeyPEMSQL = CaInquire(strings.Replace(caCommonName, " ", "_", -1), certCommonName, host); certStatus == true {
		certTLSConf = certSetup(caPEMSQL, caPrivyKeyPEMSQL, certCommonName, certOrganization, country, host)
	} else {
		cert, err := tls.X509KeyPair([]byte(certPEMSQL), []byte(certPrivyKeyPEMSQL))
		CheckErr(err)
		certTLSConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		WriteCert(certPEMSQL, certPrivyKeyPEMSQL, RootPath+"server.pem", RootPath+"server.key.pem")
	}
	// Verify (ca cert)certificate is ok?
	if net.ParseIP(host) == nil {
		VerifyDomainCa(caTLSConf, certTLSConf, host)
	} else {
		// TODO 现在需要设计 验证 跟证书 和 服务证书 之间是否存在证书链接
		color.Blue(" 暂时没有IP证书的验证方式,请尝试上传服务器验证")
	}
}
