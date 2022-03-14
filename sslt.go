package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"sslt/encryption/x509"
	//"sslt/encryption/sm2"
	. "sslt/src"
)

var (
	buildTime, commitId, version, author string
	help, v                              bool
	err                                  error
)

type Import struct {
	r  string
	rk string
	s  string
	sk string
}
type New struct {
	ro string
	rc string
	so string
	sc string
	c  string
	h  string
	p  string
}

func init() {
	HappyLogo()
}

func Server(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol string) {
	/*
		检测用户输入并判断
			 证书协议
				生成还是导入证书
					是否存在已有证书
	*/
	// 判断证书协议
	if protocol == "RSA" {
		// Generate CA
		x509.Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol)
	}
}

func Api() {
	req := gin.Default()
	Errors = make(map[string]string)
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
	req.POST("/new", func(context *gin.Context) {
		var rc, ro, sc, so, c, h, p string
		err := context.ShouldBind(&New{})
		if err != nil {
			context.JSON(200, gin.H{
				"Message": "生成证书报错了! 请检查参数是否正确",
			})
		} else {
			rc = context.DefaultPostForm("rc", "GTS Root R1")
			ro = context.DefaultPostForm("ro", "Google Trust Services LLC")
			sc = context.DefaultPostForm("sc", "GTS CA 1C3")
			so = context.DefaultPostForm("so", "Google Trust Services LLC")
			c = context.DefaultPostForm("c", "US")
			h = context.DefaultPostForm("h", "localhost")
			p = context.DefaultPostForm("p", "RSA")
			var message = "证书正在生成! 等待证书导出..."
			if rc == "GTS Root R1" || ro == "Google Trust Services LLC" || sc == "GTS CA 1C3" || so == "Google Trust Services LLC" || c == "US" || h == "localhost" || p == "RSA" {
				message = "部分参数为默认值, 证书正在生成! 等待证书导出..."
			}
			if p == "RSA" {
				// Generate CA Cert
				go Server(rc, ro, sc, so, c, h, p)
			}
			context.JSON(200, gin.H{
				"Message": message,
				"Result": gin.H{
					"Data":    Errors,
					"Version": version,
					"Arguments": gin.H{
						"rc": rc,
						"ro": ro,
						"sc": sc,
						"so": so,
						"c":  c,
						"h":  h,
						"p":  p,
					},
				},
			})
		}
		Errors = make(map[string]string)
	})
	req.GET("/new", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Generate a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"rc": "Specified Root CommonName",
					"ro": "Specified Root Organization",
					"sc": "Specified Server CommonName",
					"so": "Specified Server Organization",
					"c":  "Specified Country",
					"h":  "Specified domain name",
					"p":  "Specified encryption protocol",
				}}})
	})
	req.POST("/import", func(context *gin.Context) {
		var r, rk, s, sk string
		form, _ := context.MultipartForm()
		if form != nil && len(form.File) != 0 {
			form, _ = context.MultipartForm()
			for i := range form.File {
				for f := range form.File[i] {
					file, err := form.File[i][f].Open()
					CheckErr(err)
					buf := bytes.NewBuffer(nil)
					_, err = io.Copy(buf, file)
					CheckErr(err)
					err = file.Close()
					CheckErr(err)
					switch i {
					case "r":
						r = buf.String()
					case "rk":
						rk = buf.String()
					case "s":
						s = buf.String()
					case "sk":
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
				r = context.DefaultPostForm("r", "default")
				rk = context.DefaultPostForm("rk", "default")
				s = context.DefaultPostForm("s", "default")
				sk = context.DefaultPostForm("sk", "default")
			}
		}
		message := apiImport(r, rk, s, sk)
		context.JSON(200, gin.H{
			"Message": message,
			"Result": gin.H{
				"Data": ErrorS(),
			},
			"Version": version,
			"Arguments": gin.H{
				"r":  r,
				"rk": rk,
				"s":  s,
				"sk": sk,
			},
		})
		Errors = make(map[string]string)
	})
	req.GET("/import", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Import a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"req": "ca.crt_content",
					"rk":  "ca.key.crt_content",
					"s":   "server.crt_content",
					"sk":  "server.key.crt_content",
				}}})
	})
	req.POST("/download", func(context *gin.Context) {
		var rc, ro, sc, so, c, h, p string
		if err = context.ShouldBind(&Import{}); err != nil {
			context.JSON(200, gin.H{
				"Message": "导入证书报错了! 请检查参数是否正确",
			})
		} else {
			rc = context.DefaultPostForm("rc", "GTS Root R1")
			ro = context.DefaultPostForm("ro", "Google Trust Services LLC")
			sc = context.DefaultPostForm("sc", "GTS CA 1C3")
			so = context.DefaultPostForm("so", "Google Trust Services LLC")
			c = context.DefaultPostForm("c", "US")
			h = context.DefaultPostForm("h", "localhost")
			p = context.DefaultPostForm("p", "RSA")
			apiDownload(rc, ro, sc, so, c, h, p, context)
		}
		Errors = make(map[string]string)
	})
	req.GET("/help", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Display help information",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"req":  "ca.crt_content",
					"rk":   "ca.key.crt_content",
					"s":    "server.crt_content",
					"sk":   "server.key.crt_content",
					"rc":   "Specified Root CommonName",
					"ro":   "Specified Root Organization",
					"sc":   "Specified Server CommonName",
					"so":   "Specified Server Organization",
					"c":    "Specified Country",
					"h":    "Specified domain name",
					"p":    "Specified encryption protocol",
					"help": "Display help information",
				}}})
	})
	//gin start
	err := req.Run(":8081")
	CheckErr(err)
	// listen and serve on 0.0.0.0:8081
}

func apiImport(r, rk, s, sk string) string {
	//创建监听退出chan
	var message = "正在导入证书:"
	if r != "" || s != "" {
		if r != "" && rk != "" {
			// IMPORT CA CERTIFICATE
			message += "CA..."
			go x509.ImportCert(r, rk)
		}
		if s != "" && sk != "" {
			// IMPORT CERT CERTIFICATE
			message += "SERVER..."
			go x509.ImportCert(s, sk)
		}
		if (r != "" && rk == "") || (r == "" && rk != "") || (s != "" && sk == "") || (s == "" && sk != "") {
			message = "导入证书报错了! 请检查参数是否正确"
		}
	} else {
		message = "导入证书报错了! 请检查参数是否正确"
	}
	return message
}

func apiDownload(rc, ro, sc, so, c, h, p string, context *gin.Context) {
	var (
		message                                        = "证书正在导入! 等待数据库更新..."
		caPEM, caPrivyKeyPEM, certPEM, certPrivyKeyPEM *bytes.Buffer
	)
	if rc == "default" || ro == "default" || sc == "default" || so == "default" || c == "default" || h == "default" || p == "default" {
		message = "部分参数默认! 请检查参数是否正确"
	}
	// EXPORT CA CERTIFICATE
	if caStatus, caPEMSQL, caPrivyKeyPEMSQL := CaInquire(rc, rc, h, p); caStatus == false {
		message = "CA证书正在导入! 等待数据库更新..."
		caPEM = bytes.NewBuffer([]byte(caPEMSQL))
		caPrivyKeyPEM = bytes.NewBuffer([]byte(caPrivyKeyPEMSQL))
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%s.pem", Rename(rc)))
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%s.key.pem", Rename(rc)))
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
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%s.pem", Rename(sc)))
		context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%s.key.pem", Rename(sc)))
	} else {
		// todo 数据库没找到
		fmt.Println(certPEM, certPrivyKeyPEM)
	}
	context.JSON(200, gin.H{
		"Message": message,
		"Result": gin.H{
			"Data":    ErrorS(),
			"Version": version,
			"Arguments": gin.H{
				"r":  caPEM,
				"rk": caPrivyKeyPEM,
				"s":  certPEM,
				"sk": certPrivyKeyPEM,
			},
		},
	})
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
	// api
	Api()
}
