package router

import (
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

var (
	ErrorsData                                                                                                                                                                   map[string]string
	CaCommonName, CaOrganization, CaOrganizationalUnit, CaSerialNumber, CaStreetAddress, CaPostalCode, CaLocality, CaProvince, CaNotAfter, CaPEM, CaKeyPEM                       string
	CertCommonName, CertOrganization, CertOrganizationalUnit, CertSerialNumber, CertStreetAddress, CertPostalCode, CertLocality, CertProvince, CertNotAfter, CertPEM, CertKeyPEM string
	Host, Protocol, Country                                                                                                                                                      string
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
		ErrorsData = make(map[string]string)
		CaCommonName = context.DefaultPostForm("caCommonName", "GTS Root R1")
		CaOrganization = context.DefaultPostForm("caOrganization", "Google Trust Services LLC")
		CaOrganizationalUnit = context.DefaultPostForm("caOrganizationalUnit", "default")
		CaSerialNumber = context.DefaultPostForm("caSerialNumber", strconv.FormatInt(int64(time.Now().Year()), 10))
		CaStreetAddress = context.DefaultPostForm("caStreetAddress", "default")
		CaPostalCode = context.DefaultPostForm("caPostalCode", "100000")
		CaLocality = context.DefaultPostForm("caLocality", "default")
		CaProvince = context.DefaultPostForm("caProvince", "default")
		CaNotAfter = context.DefaultPostForm("caNotAfter", "10")
		CaPEM = context.DefaultPostForm("caPEM", "default")
		CaKeyPEM = context.DefaultPostForm("caKeyPEM", "default")

		// CERT Certificate
		CertCommonName = context.DefaultPostForm("certCommonName", "GTS Root R1")
		CertOrganization = context.DefaultPostForm("certOrganization", "Google Trust Services LLC")
		CertOrganizationalUnit = context.DefaultPostForm("certOrganizationalUnit", "default")
		CertSerialNumber = context.DefaultPostForm("certSerialNumber", strconv.FormatInt(int64(time.Now().Year()), 10))
		CertStreetAddress = context.DefaultPostForm("certStreetAddress", "default")
		CertPostalCode = context.DefaultPostForm("certPostalCode", "default")
		CertLocality = context.DefaultPostForm("certLocality", "default")
		CertProvince = context.DefaultPostForm("certProvince", "default")
		CertNotAfter = context.DefaultPostForm("certNotAfter", "2")
		CertPEM = context.DefaultPostForm("certPEM", "default")
		CertKeyPEM = context.DefaultPostForm("certKeyPEM", "default")
		// CERT hosts protocol
		Host = context.DefaultPostForm("host", "localhost")
		Protocol = context.DefaultPostForm("protocol", "RSA")

		// General Certificate
		Country = context.DefaultPostForm("country", "US")
		context.Next()
	}
}
