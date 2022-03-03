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
	"strings"
	"time"
)

func caSetup(rc, ro, c string) (*tls.Config, string, string) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   rc,
			Organization: []string{ro},
			Country:      []string{c},
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

	// generate certs TLSConf
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	caTLSConf := &tls.Config{
		RootCAs: certpool,
	}
	CheckErr(err)

	// write ca to sql & file
	caPEMSQL, caPrivyKeyPEMSQL := CaAdd(strings.Replace(rc, " ", "_", -1), rc, "root", caPEM, caPrivyKeyPEM)
	WriteCert(caPEMSQL, caPrivyKeyPEMSQL, RootPath+"ca.pem", RootPath+"ca.key.pem")
	return caTLSConf, caPEMSQL, caPrivyKeyPEMSQL
}
