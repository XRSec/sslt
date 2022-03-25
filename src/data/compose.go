package src

import (
	"archive/zip"
	"bytes"
	"github.com/gin-gonic/gin"
	"io"
	. "sslt/src/log"
)

func Compress(compress *gin.Context, caPEM, caKeyPEM, certPEM, certKeyPEM, caCommonName, certCommonName string) {
	//tar caPEM, caKeyPEM, certPEM, certKeyPEM
	ar := zip.NewWriter(compress.Writer)
	f1, _ := ar.Create(Rename(caCommonName) + ".pem")
	if _, err = io.Copy(f1, bytes.NewBuffer([]byte(caPEM))); err != nil {
		CheckErr(err)
	}
	f2, _ := ar.Create(Rename(caCommonName) + ".key.pem")
	if _, err = io.Copy(f2, bytes.NewBuffer([]byte(caKeyPEM))); err != nil {
		CheckErr(err)
	}
	f3, _ := ar.Create(Rename(certCommonName) + ".pem")
	if _, err = io.Copy(f3, bytes.NewBuffer([]byte(certPEM))); err != nil {
		CheckErr(err)
	}
	f4, _ := ar.Create(Rename(certCommonName) + ".key.pem")
	if _, err = io.Copy(f4, bytes.NewBuffer([]byte(certKeyPEM))); err != nil {
		CheckErr(err)
	}
	if err = ar.Close(); err != nil {
		CheckErr(err)
	}
}
