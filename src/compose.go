package src

import (
	"archive/zip"
	"bytes"
	"io"

	"github.com/gin-gonic/gin"
)

func compress(compress *gin.Context, r, rk, s, sk, rc, sc string) {
	//tar r rk s sk
	ar := zip.NewWriter(compress.Writer)
	f1, _ := ar.Create(Rename(rc) + ".pem")
	if _, err = io.Copy(f1, bytes.NewBuffer([]byte(r))); err != nil {
		CheckErr(err)
	}
	f2, _ := ar.Create(Rename(rc) + ".key.pem")
	if _, err = io.Copy(f2, bytes.NewBuffer([]byte(rk))); err != nil {
		CheckErr(err)
	}
	f3, _ := ar.Create(Rename(sc) + ".pem")
	if _, err = io.Copy(f3, bytes.NewBuffer([]byte(s))); err != nil {
		CheckErr(err)
	}
	f4, _ := ar.Create(Rename(sc) + ".key.pem")
	if _, err = io.Copy(f4, bytes.NewBuffer([]byte(sk))); err != nil {
		CheckErr(err)
	}
	if err = ar.Close(); err != nil {
		CheckErr(err)
	}
}
