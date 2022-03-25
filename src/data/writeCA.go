package src

import (
	"io/ioutil"
	. "sslt/src/log"
)

var err error

func WriteCert(caPEM, caPrivyKeyPEM, caPEMFile, caPrivyKeyPEMFile string) {
	Notice("导出证书公钥:", caPEMFile)
	if err = ioutil.WriteFile(caPEMFile, []byte(caPEM), 0644); err != nil {
		CheckErr(err)
		return
	}
	Notice("导出证书私钥:", caPrivyKeyPEMFile)
	if err = ioutil.WriteFile(caPrivyKeyPEMFile, []byte(caPrivyKeyPEM), 0644); err != nil {
		CheckErr(err)
		return
	}
}
