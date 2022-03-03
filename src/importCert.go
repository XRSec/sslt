package src

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/fatih/color"
	"io/ioutil"
	"strings"
)

func ImportCert(caPEMFILE, caPrivyKeyPEMFILE string) string {
	color.Red(" [ Found Cert! Import Cert! ]")
	caPEM, err := ioutil.ReadFile(caPEMFILE)
	CheckErr(err)
	caPrivyKeyPEM, err := ioutil.ReadFile(caPrivyKeyPEMFILE)
	CheckErr(err)
	var ca, caErr = tls.X509KeyPair(caPEM, caPrivyKeyPEM)
	CheckErr(caErr)
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		CheckErr(caErr)
	}
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL = CaInquire(strings.Replace(ca.Leaf.Subject.CommonName, " ", "_", -1), ca.Leaf.Subject.CommonName, "root"); caStatus == true {
		CaAdd(strings.Replace(ca.Leaf.Subject.CommonName, " ", "_", -1), ca.Leaf.Subject.CommonName, "root", bytes.NewBuffer(caPEM), bytes.NewBuffer(caPrivyKeyPEM))
	}
	return ca.Leaf.Subject.CommonName
}
