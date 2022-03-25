package Server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
	"mime/multipart"
	"net/http"
	"reflect"
	. "sslt/src/data"
	. "sslt/src/db"
	"sslt/src/encryption/x509"
	. "sslt/src/log"
)

type (
	New struct {
		rc   string
		ro   string
		rou  string
		rsn  string
		rst  string
		rpc  string
		rlc  string
		rpr  string
		rna  string
		sc   string
		so   string
		sou  string
		ssn  string
		sst  string
		spc  string
		slc  string
		spr  string
		sna  string
		host string
		p    string
		c    string
	}
	Import struct {
		r  string
		rk string
		s  string
		sk string
	}
	Download struct {
		rc string
		sc string
		c  string
		h  string
		p  string
	}
)

/*
	CommonName [*.csdn.net / baidu.com / Vscode]
	Organization [Google Trust Services LLC / 北京xxx网络技术有限公司 / GitHub, Inc.]
	OrganizationalUnit [xxx.xxx / github.com / google.com]
	SerialNumber	[2022 / 01 68 D5 75 F1 CE 87 28 AD 95 A8 F1 1E F1 59 8B / ]
	StreetAddress [xxx street / xxx road]
	PostalCode [100000]
	Locality [Beijing / 北京]
	Province [Beijing / 北京]
	NotAfter := [20 / 10 / 2]
	#General Country [CN / 中国]
	#CERT hosts [*.csdn.net / baidu.com / Vscode / 127.0.0.1,localhost,google.com]
	#General PEM KeyPEM [ string / file]
	#CERTprotocol [RSA / SM2 / ECDSA]
*/
func GinValue() gin.HandlerFunc {
	return func(context *gin.Context) {
		// CA Certificate
		caCommonName = context.DefaultPostForm("rc", "GTS Root R1")
		caOrganization = context.DefaultPostForm("ro", "Google Trust Services LLC")
		caOrganizationalUnit = context.DefaultPostForm("rou", "")
		caSerialNumber = context.DefaultPostForm("rsn", "")
		caStreetAddress = context.DefaultPostForm("rst", "")
		caPostalCode = context.DefaultPostForm("rpc", "")
		caLocality = context.DefaultPostForm("rlc", "")
		caProvince = context.DefaultPostForm("rpr", "")
		caNotAfter = context.DefaultPostForm("rna", "")
		caPEM = context.DefaultPostForm("r", "")
		caKeyPEM = context.DefaultPostForm("rk", "")

		// CERT Certificate
		certCommonName = context.DefaultPostForm("sc", "GTS CA 1C3")
		certOrganization = context.DefaultPostForm("so", "Google Trust Services LLC")
		certOrganizationalUnit = context.DefaultPostForm("sou", "")
		certSerialNumber = context.DefaultPostForm("ssn", "")
		certStreetAddress = context.DefaultPostForm("sst", "")
		certPostalCode = context.DefaultPostForm("spc", "")
		certLocality = context.DefaultPostForm("slc", "")
		certProvince = context.DefaultPostForm("spr", "")
		certNotAfter = context.DefaultPostForm("sna", "")
		certPEM = context.DefaultPostForm("s", "")
		certKeyPEM = context.DefaultPostForm("sk", "")
		// CERT hosts protocol
		host = context.DefaultPostForm("host", "localhost")
		protocol = context.DefaultPostForm("p", "RSA")
		// General Certificate
		country = context.DefaultPostForm("c", "US")
		context.Next()
		// 把参数保存到日志中
		var newLog = make(map[string]string)
		newLog["caPEM"] = caPEM
		newLog["caKeyPEM"] = caKeyPEM
		newLog["CaCommonName"] = caCommonName
		newLog["CaOrganization"] = caOrganization
		newLog["CaOrganizationalUnit"] = caOrganizationalUnit
		newLog["CaSerialNumber"] = caSerialNumber
		newLog["CaStreetAddress"] = caStreetAddress
		newLog["CaPostalCode"] = caPostalCode
		newLog["CaLocality"] = caLocality
		newLog["CaProvince"] = caProvince
		newLog["CaNotAfter"] = caNotAfter
		newLog["CertPEM"] = certPEM
		newLog["CertKeyPEM"] = certKeyPEM
		newLog["CertCommonName"] = certCommonName
		newLog["CertOrganization"] = certOrganization
		newLog["CertOrganizationalUnit"] = certOrganizationalUnit
		newLog["CertSerialNumber"] = certSerialNumber
		newLog["CertStreetAddress"] = certStreetAddress
		newLog["CertPostalCode"] = certPostalCode
		newLog["CertLocality"] = certLocality
		newLog["CertProvince"] = certProvince
		newLog["CertNotAfter"] = certNotAfter
		newLog["Country"] = country
		newLog["Host"] = host
		newLog["Protocol"] = protocol
		newLog["Api"] = "true"
		j, _ := json.Marshal(newLog)
		logrus.Info(string(j))
	}
}

func ApiServer(api bool) {
	gin.SetMode(gin.ReleaseMode)
	get := gin.Default()
	// Get
	get.GET("/", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"Message": "Home",
		})
	})
	get.GET("/list", func(context *gin.Context) {
		//caCerts := QuireAll()
		context.JSON(200, gin.H{
			"Message": "List All Certificates",
			//caCerts:   caCerts,
		})
	})
	get.GET("/new", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"Message": "Generate a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"rc":   "Specified Root CommonName like [GTS Root R1]",
					"ro":   "Specified Root Organization like [Google Trust Services LLC]",
					"sc":   "Specified Server CommonName like [GTS CA 1C3]",
					"so":   "Specified Server Organization like [Google Trust Services LLC]",
					"c":    "Specified Country like [US]",
					"host": "Specified domain name like [localhost]",
					"p":    "Specified encryption protocol like [rsa]",
					"rou":  "Specified Root OrganizationalUnit",
					"rsn":  "Specified Root SerialNumber",
					"rst":  "Specified Root StreetAddress",
					"rpc":  "Specified Root PostalCode",
					"rlc":  "Specified Root Locality",
					"rpr":  "Specified Root Province",
					"rna":  "Specified Root NotAfter",
					"sou":  "Specified Server OrganizationalUnit",
					"ssn":  "Specified Server SerialNumber",
					"sst":  "Specified Server StreetAddress",
					"spc":  "Specified Server PostalCode",
					"slc":  "Specified Server Locality",
					"spr":  "Specified Server Province",
					"sna":  "Specified Server NotAfter",
				}}})
	})
	get.GET("/import", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"Message": "Import a new certificate",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					"r":  "ca.crt_content",
					"rk": "ca.key.crt_content",
					"s":  "server.crt_content",
					"sk": "server.key.crt_content",
				}}})
	})
	get.GET("/help", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"Message": "Display help information",
			"Arguments": gin.H{
				"-X":       "POST",
				"--header": "Authorization Bearer TOKEN",
				"--data": gin.H{
					// import file or content
					"r":  "Import CA like [ca.pem_content]",
					"s":  "Import Cert CA like [server.pem_content]",
					"rk": "Import CA Key like [ca.key.pem_content]",
					"sk": "Import Cert CA Key like [server.key.pem_content]",
					/* RSA ARGS >>> */
					"rc":   "Specified Root CommonName like [GTS Root R1]",
					"ro":   "Specified Root Organization like [Google Trust Services LLC]",
					"sc":   "Specified Server CommonName like [GTS CA 1C3]",
					"so":   "Specified Server Organization like [Google Trust Services LLC]",
					"c":    "Specified Country like [US]",
					"host": "Specified domain name like [localhost]",
					"p":    "Specified encryption protocol like [rsa]",
					// No default configuration
					"rou": "Specified Root OrganizationalUnit",
					"rsn": "Specified Root SerialNumber",
					"rst": "Specified Root StreetAddress",
					"rpc": "Specified Root PostalCode",
					"rlc": "Specified Root Locality",
					"rpr": "Specified Root Province",
					"rna": "Specified Root NotAfter",
					"sou": "Specified Server OrganizationalUnit",
					"ssn": "Specified Server SerialNumber",
					"sst": "Specified Server StreetAddress",
					"spc": "Specified Server PostalCode",
					"slc": "Specified Server Locality",
					"spr": "Specified Server Province",
					"sna": "Specified Server NotAfter",
				}}})
	})

	// Post
	get.Use(GinValue()).POST("/new", func(context *gin.Context) {
		var message = "证书正在生成!"
		// 检查用户输入
		if argsDetection(context, New{}) {
			if caCommonName == "GTS Root R1" || caOrganization == "Google Trust Services LLC" || certCommonName == "GTS CA 1C3" || certOrganization == "Google Trust Services LLC" || country == "US" || host == "localhost" || protocol == "RSA" {
				message += "部分参数为默认值! "
			}
			caPEM, caKeyPEM, certPEM, certKeyPEM = Server(api)
			context.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment;filename=%s_PEM.zip", Rename(caCommonName)))
			Compress(context, caPEM, caKeyPEM, certPEM, certKeyPEM, caCommonName, certCommonName)
			// TODO 希望能下载的同时给前端打开一个页面
			/*
				context.JSON(http.StatusOK, gin.H{
					"Message": message,
					"Status":  http.StatusOK,
					"Version": viper.Get("Version").(string),
					"Arguments": gin.H{
						"caOrganization":         caOrganization,
						"caCommonName":           caCommonName,
						"caOrganizationalUnit":   caOrganizationalUnit,
						"caSerialNumber":         caSerialNumber,
						"caStreetAddress":        caStreetAddress,
						"caPostalCode":           caPostalCode,
						"caLocality":             caLocality,
						"caProvince":             caProvince,
						"caNotAfter":             caNotAfter,
						"certOrganization":       certOrganization,
						"certCommonName":         certCommonName,
						"certOrganizationalUnit": certOrganizationalUnit,
						"certSerialNumber":       certSerialNumber,
						"certStreetAddress":      certStreetAddress,
						"certPostalCode":         certPostalCode,
						"certLocality":           certLocality,
						"certProvince":           certProvince,
						"certNotAfter":           certNotAfter,
						"country":                country,
						"host":                   host,
						"protocol":               protocol,
					},
			*/
			Notice(message, "...")
		}
	})
	// TODO 勉强能用,我不想再碰了
	get.Use(GinValue()).POST("/import", func(context *gin.Context) {
		//get.POST("/import", func(context *gin.Context) {
		var (
			message    = "证书正在导入!"
			statusCode = 200
		)
		form, _ := context.MultipartForm()
		if !argsDetection(context, Import{}) {
			return
		}
		if form != nil && len(form.File) != 0 {
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
					case "r":
						caPEM = buf.String()
					case "rk":
						caKeyPEM = buf.String()
					case "s":
						certPEM = buf.String()
					case "sk":
						certKeyPEM = buf.String()
					}
				}
			}
		} else if len(context.Request.PostForm) > 0 {
			caPEM = context.DefaultPostForm("r", "")
			caKeyPEM = context.DefaultPostForm("rk", "")
			certPEM = context.DefaultPostForm("s", "")
			certKeyPEM = context.DefaultPostForm("sk", "")
		} else {
			message = "导入证书报错了! 请检查参数是否正确"
			CheckErr(errors.New(message))
			statusCode = 400
		}
		if caPEM != "" || certPEM != "" {
			if caPEM != "" && caKeyPEM != "" {
				// IMPORT CA CERTIFICATE
				message += " | CA + ,"
				x509.ImportCert(caPEM, caKeyPEM)
			}
			if certPEM != "" && certKeyPEM != "" {
				// IMPORT CERT CERTIFICATE
				message += " SERVER + "
				x509.ImportCert(certPEM, certKeyPEM)
			}
			if (caPEM != "" && caKeyPEM == "") || (caPEM == "" && caKeyPEM != "") || (certPEM != "" && certKeyPEM == "") || (certPEM == "" && certKeyPEM != "") {
				message = "导入证书报错了! 请检查参数是否正确"
				CheckErr(errors.New(message))
				statusCode = 400
			}
		} else {
			message = "导入证书报错了! 请检查参数是否正确"
			CheckErr(errors.New(message))
			statusCode = 400
		}
		context.JSON(statusCode, gin.H{
			"Message": message,
			"Status":  statusCode,
			"Version": viper.Get("Version").(string),
			"Arguments": gin.H{
				"caPEM":      caPEM,
				"caKeyPEM":   caKeyPEM,
				"certPEM":    certPEM,
				"certKeyPEM": certKeyPEM,
			},
		})
	})
	get.Use(GinValue()).POST("/download", func(context *gin.Context) {
		// TODO 数据库查询存在错误 /NUM
		var (
			message              = "正在查询数据库!"
			caStatus, certStatus bool
			statusCode           = 200
		)
		if caCommonName == "GTS Root R1" || certCommonName == "GTS Root R1" || country == "US" || host == "localhost" || protocol == "RSA" {
			message = "部分参数默认! 请检查参数是否正确"
			CheckErr(errors.New(message))
		}
		// EXPORT CA CERTIFICATE
		if caStatus, caPEM, caKeyPEM = CaInquire(caCommonName, caCommonName, host, protocol); caStatus == false {
			message += " | 正在检验CA证书!"
			fmt.Println(caStatus)
			context.Writer.Header().Add("Content-Disposition", fmt.Sprintf(fmt.Sprintf("attachment;filename=%s_PEM.zip", Rename(caCommonName))))
		} else {
			message += " | 没有找到CA证书!"
			CheckErr(errors.New(message))
			statusCode = 400
		}
		// EXPORT CERT CERTIFICATE
		if certStatus, certPEM, certKeyPEM = CaInquire(caCommonName, certCommonName, host, protocol); certStatus == false {
			message += " | 正在检验CERT证书!"
			fmt.Println(caStatus)
			context.Writer.Header().Add("Content-Disposition", fmt.Sprintf(fmt.Sprintf("attachment;filename=%s_PEM.zip", Rename(caCommonName))))
		} else {
			message += " | 没有找到 CERT 证书!"
			CheckErr(errors.New(message))
			statusCode = 400
		}
		if statusCode == 400 {
			context.JSON(statusCode, gin.H{
				"Message": message,
				"Status":  statusCode,
				"Version": viper.Get("Version").(string),
				"Arguments": gin.H{
					"caCommonName":   caCommonName,
					"certCommonName": certCommonName,
					"country":        country,
					"host":           host,
					"protocol":       protocol,
				},
			})
		}
	})

	// gin start
	if err = get.Run(":" + viper.Get("port").(string)); err != nil {
		CheckErr(err)
		return
	}
	// listen and serve on 0.0.0.0:8081
}

func argsDetection(context *gin.Context, tmpStruct interface{}) bool {
	var (
		errorArgs = make(map[string]string)
		okArg     = true
	)
	for i := range context.Request.PostForm {
		errorArgs[i] = context.PostForm(i)
	}
	for i := range context.Request.PostForm {
		if _, ok := reflect.TypeOf(tmpStruct).FieldByName(i); !ok {
			okArg = false
			break
		}
	}
	if !okArg {
		var message = "参数错误! "
		context.JSON(http.StatusBadRequest, gin.H{
			"Message":   message,
			"Status":    http.StatusBadRequest,
			"Version":   viper.Get("Version").(string),
			"Arguments": errorArgs,
		})
		CheckErr(errors.New(message))
	}
	return okArg
}
