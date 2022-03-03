package src

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"
)

func certSetup(caPEMSQL, CaPrivyKeyPEMSQL, certCommonName, certOrganization, country, host string) *tls.Config {
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
	// matching certcertPEM certPrivyKeyPEM
	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivyKeyPEM.Bytes())
	CheckErr(err)

	// generate certs TLSConf
	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// write ca to sql & file
	certPEMSQL, certPrivyKeyPEMSQL := CaAdd(strings.Replace(certCommonName, " ", "_", -1), certCommonName, host, certPEM, certPrivyKeyPEM)
	WriteCert(certPEMSQL, certPrivyKeyPEMSQL, RootPath+"server.pem", RootPath+"server.key.pem")
	return serverTLSConf
}
