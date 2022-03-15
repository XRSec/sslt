package main

import "C"
import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"sslt/encryption/x509"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"

	//"sslt/encryption/sm2"
	. "sslt/src"
	. "sslt/web/router"
)

var (
	err error

	// CA Root Certificates
	caCommonName, caOrganization, caOrganizationalUnit, caSerialNumber string
	caLocality, caProvince, caStreetAddress, caPostalCode              []string
	caPEM, caPrivyKeyPEM                                               *bytes.Buffer

	// CERT Certificate
	certCommonName, certOrganization, certOrganizationalUnit, certSerialNumber string
	certLocality, certProvince, certStreetAddress, certPostalCode              []string
	certPEM, certPrivyKeyPEM                                                   *bytes.Buffer

	// General Certificate Information
	country, host, protocol string

	// System parameters
	buildTime, commitId, version, author string
	help, v                              bool

	// ErrorsData Log Storage Map
	ErrorsData map[string]string
)

func init() {
	color.Green("\033[H\033[2J -------------------------------\n")
	color.Cyan("   _____   _____  .      _______")
	color.Blue("  (       (      /     '   /   ")
	color.Red("   `--.    `--.  |         |   ")
	color.Magenta("      |       |  |         |   ")
	color.Yellow(" \\___.'  \\___.'  /---/     /   \n")
	flag.BoolVar(&help, "help", false, "Display help information")
	flag.BoolVar(&v, "v", false, "sslt version")
}

func Server(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol string) (string, string, string, string) {
	var r, rk, s, sk string
	if protocol == "RSA" {
		// Generate CA
		r, rk, s, sk = x509.Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol)
	} else if protocol == "SM2" {
		// TODO SM2
		return "", "", "", ""
	}
	return r, rk, s, sk
}

func ginServer() {
	req := gin.Default()
	ErrorsData := make(map[string]string)
	req.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Home",
		})
	})
	req.GET("/list", func(c *gin.Context) {
		//caCerts := QuireAll()
		c.JSON(200, gin.H{
			"Message": "List All Certificates",
			//caCerts:   caCerts,
		})
	})
	apiNew(req)
	apiImport(req)
	req.POST("/download", func(context *gin.Context) {
		if err = context.ShouldBind(&Import{}); err != nil {
			context.JSON(200, gin.H{
				"Message": "导入证书报错了! 请检查参数是否正确",
			})
		} else {
			caCommonName = context.DefaultPostForm("caCommonName", "GTS Root R1")
			caOrganization = context.DefaultPostForm("caOrganization", "Google Trust Services LLC")
			certCommonName = context.DefaultPostForm("certCommonName", "GTS CA 1C3")
			certOrganization = context.DefaultPostForm("certOrganization", "Google Trust Services LLC")
			country = context.DefaultPostForm("country", "US")
			host = context.DefaultPostForm("host", "localhost")
			protocol = context.DefaultPostForm("protocol", "RSA")
			apiDownload(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol, context)
		}
		ErrorsData = make(map[string]string)
	})
	req.GET("/help", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Display help information",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"req":              "ca.crt_content",
					"caKeyPEM":         "ca.key.crt_content",
					"certPEM":          "server.crt_content",
					"certKeyPEM":       "server.key.crt_content",
					"caCommonName":     "Specified Root CommonName",
					"caOrganization":   "Specified Root Organization",
					"certCommonName":   "Specified Server CommonName",
					"certOrganization": "Specified Server Organization",
					"country":          "Specified Country",
					"host":             "Specified domain name",
					"protocol":         "Specified encryption protocol",
					"help":             "Display help information",
				}}})
	})
	//gin start
	if err = req.Run(":8081"); err != nil {
		CheckErr(err)
		return
	}

	// listen and serve on 0.0.0.0:8081
}

func apiNew(req *gin.Engine) {
	req.POST("/new", func(context *gin.Context) {
		err = context.ShouldBind(&New{})
		if err != nil {
			context.JSON(200, gin.H{
				"Message": "生成证书报错了! 请检查参数是否正确",
			})
		} else {
			caCommonName = context.DefaultPostForm("caCommonName", "GTS Root R1")
			caOrganization = context.DefaultPostForm("caOrganization", "Google Trust Services LLC")
			certCommonName = context.DefaultPostForm("certCommonName", "GTS CA 1C3")
			certOrganization = context.DefaultPostForm("certOrganization", "Google Trust Services LLC")
			country = context.DefaultPostForm("country", "US")
			host = context.DefaultPostForm("host", "localhost")
			protocol = context.DefaultPostForm("protocol", "RSA")
			var message = "证书正在生成! 等待证书导出..."
			if caCommonName == "GTS Root R1" || caOrganization == "Google Trust Services LLC" || certCommonName == "GTS CA 1C3" || certOrganization == "Google Trust Services LLC" || country == "US" || host == "localhost" || protocol == "RSA" {
				message = "部分参数为默认值, 证书正在生成! 等待证书导出..."
			}
			caPEM, rk, s, sk = Server(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol)
			context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%certPEM.zip", Rename(caCommonName)))
			compress(context, caPEM, rk, s, sk, caCommonName, certCommonName)
			context.JSON(200, gin.H{
				"Message": message,
				"Result": gin.H{
					"Result": gin.H{
						"Data":         Errors,
						"CA PEM":       caPEM,
						"CA KEY PEM":   rk,
						"CERT PEM":     s,
						"CERT KEY PEM": sk,
					},
					"Version": version,
					"Arguments": gin.H{
						"caCommonName":     caCommonName,
						"caOrganization":   caOrganization,
						"certCommonName":   certCommonName,
						"certOrganization": certOrganization,
						"country":          country,
						"host":             host,
						"protocol":         protocol,
					},
				},
			})
		}
		ErrorsData = make(map[string]string)
	})
	req.GET("/new", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Generate a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"caCommonName":     "Specified Root CommonName",
					"caOrganization":   "Specified Root Organization",
					"certCommonName":   "Specified Server CommonName",
					"certOrganization": "Specified Server Organization",
					"country":          "Specified Country",
					"host":             "Specified domain name",
					"protocol":         "Specified encryption protocol",
				}}})
	})
}

func apiImport(req *gin.Engine) {
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
						rk = buf.String()
					case "certPEM":
						s = buf.String()
					case "certKeyPEM":
						sk = buf.String()
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
				rk = context.DefaultPostForm("caKeyPEM", "default")
				s = context.DefaultPostForm("certPEM", "default")
				sk = context.DefaultPostForm("certKeyPEM", "default")
			}
		}
		var message = "正在导入证书:"
		if caPEM != "" || s != "" {
			if caPEM != "" && rk != "" {
				// IMPORT CA CERTIFICATE
				message += "CA..."
				x509.ImportCert(caPEM, rk)
			}
			if s != "" && sk != "" {
				// IMPORT CERT CERTIFICATE
				message += "SERVER..."
				x509.ImportCert(s, sk)
			}
			if (caPEM != "" && rk == "") || (caPEM == "" && rk != "") || (s != "" && sk == "") || (s == "" && sk != "") {
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
				"caKeyPEM":   rk,
				"certPEM":    s,
				"certKeyPEM": sk,
			},
		})
		ErrorsData = make(map[string]string)
	})
	req.GET("/import", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Import a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"req":        "ca.crt_content",
					"caKeyPEM":   "ca.key.crt_content",
					"certPEM":    "server.crt_content",
					"certKeyPEM": "server.key.crt_content",
				}}})
	})
}

func apiDownload(rc, ro, sc, so, c, h, p string, context *gin.Context) {
	var message = "证书正在导入! 等待数据库更新..."
	if rc == "default" || ro == "default" || sc == "default" || so == "default" || c == "default" || h == "default" || p == "default" {
		message = "部分参数默认! 请检查参数是否正确"
	}
	// EXPORT CA CERTIFICATE
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL := CaInquire(rc, rc, h, p); caStatus == false {
		message = "CA证书正在导入! 等待数据库更新..."
		caPEM = bytes.NewBuffer([]byte(caPEMSQL))
		caPrivyKeyPEM = bytes.NewBuffer([]byte(caPrivyKeyPEMSQL))
		context.Writer.Header().Add("Content-Disposition", "attachment; filename=certs.zip")
		context.Data(http.StatusOK, "application/octet-stream", []byte(caPrivyKeyPEMSQL))

		context.Data(http.StatusOK, "application/octet-stream", []byte(caPEMSQL))

	} else {
		// todo 数据库没找到
		fmt.Println(caPEM, caPrivyKeyPEM)
	}
	// EXPORT CERT CERTIFICATE
	if certStatus, certPEMSQL, certPrivyKeyPEMSQL := CaInquire(sc, sc, h, p); certStatus == false {
		message = "CA证书正在导入! 等待数据库更新..."
		certPEM = bytes.NewBuffer([]byte(certPEMSQL))
		certPrivyKeyPEM = bytes.NewBuffer([]byte(certPrivyKeyPEMSQL))
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%certPEM.pem", Rename(sc)))
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%certPEM.key.pem", Rename(sc)))
	} else {
		// todo 数据库没找到
		fmt.Println(certPEM, certPrivyKeyPEM)
	}
	context.JSON(200, gin.H{
		"Message": message,
		"Result": gin.H{
			"Data":    ErrorsData,
			"Version": version,
			"Arguments": gin.H{
				"caPEM":      caPEM,
				"caKeyPEM":   caPrivyKeyPEM,
				"certPEM":    certPEM,
				"certKeyPEM": certPrivyKeyPEM,
			},
		},
	})
}

func compress(compress *gin.Context, r, rk, s, sk, rc, sc string) {
	//tar caPEM caKeyPEM certPEM certKeyPEM
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

func main() {
	color.Green(" ----------------------     \n")
	defer color.Green(" -------------------------------\n")
	flag.Parse()
	// Start by identifying the functionality the user needs >>
	if help {
		flag.Usage()
		return
	}
	// Version
	if v {
		Notice("Version:   ", version)
		Notice("BuildTime: ", buildTime)
		Notice("Author:    ", author)
		Notice("CommitId:  ", commitId)
		return
	}
	// << Start by identifying the functionality the user needs
	// ginServer
	ginServer()
}

func ginweb() {
	req := gin.Default()
	req.Group("v1").Use(GinValue())
	req.Run(":8081")
}
