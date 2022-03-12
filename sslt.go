package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"net"
	"sslt/encryption/x509"
	//"sslt/encryption/sm2"
	. "sslt/src"
)

var (
	r, rk, rc, ro, s, sk, sc, so, c, h, p, buildTime, commitId, version, author string
	help, v                                                                     bool
	err                                                                         error
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
	if protocol == "x509" {
		// Generate CA
		var (
			CertTLSConf, CaTLSConf *tls.Config
		)
		CaTLSConf, CertTLSConf = x509.Setup(caCommonName, caOrganization, certCommonName, certOrganization, country, host, protocol)
		// where The Test Was Successful
		// Verify (ca cert)certificate is ok?
		if net.ParseIP(host) == nil {
			x509.VerifyDomainCa(CaTLSConf, CertTLSConf, host)
		} else {
			// TODO 现在需要设计 验证 跟证书 和 服务证书 之间是否存在证书链接
			Notice(" 暂时没有IP证书的验证方式,请尝试上传服务器验证", "")
		}
	}
}

func Api() {
	req := gin.Default()
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
			p = context.DefaultPostForm("p", "x509")
			var message = "证书正在生成! 等待证书导出..."
			if rc == "GTS Root R1" || ro == "Google Trust Services LLC" || sc == "GTS CA 1C3" || so == "Google Trust Services LLC" || c == "US" || h == "localhost" || p == "x509" {
				message = "部分参数为默认值, 证书正在生成! 等待证书导出..."
			}
			if p == "x509" {
				// Generate CA Cert
				Errors = make(map[string]string)
				Server(rc, ro, sc, so, c, h, p)
			}
			context.JSON(200, gin.H{
				"Message": message,
				"Result": gin.H{
					"Data":    ErrorS(),
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
		err := context.ShouldBind(&Import{})
		if err != nil {
			context.JSON(200, gin.H{
				"Message": "导入证书报错了! 请检查参数是否正确",
			})
		} else {
			r = context.DefaultPostForm("r", "default")
			rk = context.DefaultPostForm("rk", "default")
			s = context.DefaultPostForm("s", "default")
			sk = context.DefaultPostForm("sk", "default")
			var message = "证书正在导入! 等待数据库更新..."

			if r != "default" || s != "default" {
				if r != "default" && rk != "default" {
					// IMPORT CA CERTIFICATE
					message = "CA证书正在导入! 等待数据库更新..."
					//defer recoverFullName()
					Errors = make(map[string]string)
					x509.ImportCert(r, rk)
				}
				if s != "default" && sk != "default" {
					// IMPORT CERT CERTIFICATE
					message = "SERVER证书正在导入! 等待数据库更新..."
					//defer recovery()
					x509.ImportCert(s, sk)
				}
				if (r != "default" && rk == "default") || (r == "default" && rk != "default") || (s != "default" && sk == "default") || (s == "default" && sk != "default") {
					message = "导入证书报错了! 请检查参数是否正确"
				}
			} else {
				message = "导入证书报错了! 请检查参数是否正确"
			}
			context.JSON(200, gin.H{
				"Message": message,
				"Result": gin.H{
					"Data":    ErrorS(),
					"Version": version,
					"Arguments": gin.H{
						"r":  r,
						"rk": rk,
						"s":  s,
						"sk": sk,
					},
				},
			})
		}

	})
	req.POST("/download", func(context *gin.Context) {
		if err = context.ShouldBind(&Import{}); err != nil {
			context.JSON(200, gin.H{
				"Message": "导入证书报错了! 请检查参数是否正确",
			})
		} else {
			var (
				message                                        = "证书正在导入! 等待数据库更新..."
				caPEM, caPrivyKeyPEM, certPEM, certPrivyKeyPEM *bytes.Buffer
			)
			rc = context.DefaultPostForm("rc", "GTS Root R1")
			ro = context.DefaultPostForm("ro", "Google Trust Services LLC")
			sc = context.DefaultPostForm("sc", "GTS CA 1C3")
			so = context.DefaultPostForm("so", "Google Trust Services LLC")
			c = context.DefaultPostForm("c", "US")
			h = context.DefaultPostForm("h", "localhost")
			p = context.DefaultPostForm("p", "x509")
			if r != "default" || s != "default" {
				if r != "default" && rk != "default" {
					// EXPORT CA CERTIFICATE
					message = "CA证书正在导入! 等待数据库更新..."
					//defer recoverFullName()
					Errors = make(map[string]string)
					if caStatus, caPEMSQL, caPrivyKeyPEMSQL := CaInquire(rc, rc, h, p); caStatus == false {
						caPEM = bytes.NewBuffer([]byte(caPEMSQL))
						caPrivyKeyPEM = bytes.NewBuffer([]byte(caPrivyKeyPEMSQL))
					} else {
						// todo 数据库没找到
						fmt.Println(caPEM, caPrivyKeyPEM)
					}
				}
				if s != "default" && sk != "default" {
					// EXPORT CERT CERTIFICATE
					message = "CA证书正在导入! 等待数据库更新..."
					//defer recoverFullName()
					Errors = make(map[string]string)
					if certStatus, certPEMSQL, certPrivyKeyPEMSQL := CaInquire(sc, sc, h, p); certStatus == false {
						certPEM = bytes.NewBuffer([]byte(certPEMSQL))
						certPrivyKeyPEM = bytes.NewBuffer([]byte(certPrivyKeyPEMSQL))
					} else {
						// todo 数据库没找到
						fmt.Println(certPEM, certPrivyKeyPEM)
					}
				}
				if (r != "default" && rk == "default") || (r == "default" && rk != "default") || (s != "default" && sk == "default") || (s == "default" && sk != "default") {
					message = "导入证书报错了! 请检查参数是否正确"
				}
			} else {
				message = "导入证书报错了! 请检查参数是否正确"
			}
			context.JSON(200, gin.H{
				"Message": message,
				"Result": gin.H{
					"Data":    ErrorS(),
					"Version": version,
					"Arguments": gin.H{
						"r":  r,
						"rk": rk,
						"s":  s,
						"sk": sk,
					},
				},
			})
		}
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
	if err != nil {
		CheckErr(err)
		return
	} // listen and serve on 0.0.0.0:8081
	fmt.Println(r, rk, rc, ro, s, sk, sc, so, c, h, p)
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
		Notice("Verdion:   ", version)
		Notice("BuildTime: ", buildTime)
		Notice("Author:    ", author)
		Notice("CommitId:  ", commitId)
		return
	}
	// << Start by identifying the functionality the user needs
	// api
	//Api()
	QuireAll()
}
