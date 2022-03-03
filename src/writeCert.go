package src

import (
	"github.com/fatih/color"
	"io/ioutil"
)

func WriteCert(caPEM, caPrivyKeyPEM, caPEMFile, caPrivyKeyPEMFile string) {
	color.New(color.FgBlue).PrintfFunc()("  Export certs:      ")
	color.New(color.FgYellow).PrintfFunc()(" %v\n", caPEMFile)

	err := ioutil.WriteFile(caPEMFile, []byte(caPEM), 0644)
	CheckErr(err)
	color.New(color.FgBlue).PrintfFunc()("  Export certs:")
	color.New(color.FgYellow).PrintfFunc()("       %v\n", caPrivyKeyPEMFile)
	err = ioutil.WriteFile(caPrivyKeyPEMFile, []byte(caPrivyKeyPEM), 0644)
	CheckErr(err)
}
