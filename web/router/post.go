package router

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"io"
	"mime/multipart"
	"sslt/encryption/x509"
	. "sslt/src"
)

type (
	Import struct {
		caPEM      string
		caKeyPEM   string
		certPEM    string
		certKeyPEM string
	}
	New struct {
		caCommonName     string
		caOrganization   string
		certCommonName   string
		certOrganization string
		country          string
		host             string
		protocol         string
	}
)

var (
	err     error
	version string
)

/*
	确定用户是选择上传文件还是输入文件内容
*/
func PostImport(req *gin.Engine, caPEM, caKeyPEM, certPEM, certKeyPEM string) {
	req.POST("/import", func(context *gin.Context) {
		form, _ := context.MultipartForm()
		if form != nil && len(form.File) != 0 {
			form, _ = context.MultipartForm()
			for i := range form.File {
				for f := range form.File[i] {
					var file multipart.File
					if file, err = form.File[i][f].Open(); err != nil {
						CheckErr(err)
						return
					}
					buf := bytes.NewBuffer(nil)
					if _, err = io.Copy(buf, file); err != nil {
						CheckErr(err)
						return
					}
					if err = file.Close(); err != nil {
						CheckErr(err)
						return
					}
					switch i {
					case "caPEM":
						caPEM = buf.String()
					case "caKeyPEM":
						caKeyPEM = buf.String()
					case "certPEM":
						certPEM = buf.String()
					case "certKeyPEM":
						certKeyPEM = buf.String()
					}
				}
			}
		} else {
			err = context.ShouldBind(&Import{})
			if err != nil {
				context.JSON(200, gin.H{
					"Message": "导入证书报错了! 请检查参数是否正确",
				})
			} else {
				caPEM = context.DefaultPostForm("caPEM", "default")
				caKeyPEM = context.DefaultPostForm("caKeyPEM", "default")
				certPEM = context.DefaultPostForm("certPEM", "default")
				certKeyPEM = context.DefaultPostForm("certKeyPEM", "default")
			}
		}
		var message = "正在导入证书:"
		if caPEM != "" || certPEM != "" {
			if caPEM != "" && caKeyPEM != "" {
				// IMPORT CA CERTIFICATE
				message += "CA..."
				x509.ImportCert(caPEM, caKeyPEM)
			}
			if certPEM != "" && certKeyPEM != "" {
				// IMPORT CERT CERTIFICATE
				message += "SERVER..."
				x509.ImportCert(certPEM, certKeyPEM)
			}
			if (caPEM != "" && caKeyPEM == "") || (caPEM == "" && caKeyPEM != "") || (certPEM != "" && certKeyPEM == "") || (certPEM == "" && certKeyPEM != "") {
				message = "导入证书报错了! 请检查参数是否正确"
			}
		} else {
			message = "导入证书报错了! 请检查参数是否正确"
		}
		context.JSON(200, gin.H{
			"Message": message,
			"Result": gin.H{
				"Data": Errors,
			},
			"Version": version,
			"Arguments": gin.H{
				"caPEM":      caPEM,
				"caKeyPEM":   caKeyPEM,
				"certPEM":    certPEM,
				"certKeyPEM": certKeyPEM,
			},
		})
	})
}
