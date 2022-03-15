package router

import "github.com/gin-gonic/gin"

func GetHome(req *gin.Engine) {
	req.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message": "Home",
		})
	})
}

func GetNew(req *gin.Engine) {
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

func GetImport(req *gin.Engine) {
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

func GetList(req *gin.Engine) {
	req.GET("/list", func(c *gin.Context) {
		//caCerts := QuireAll()
		c.JSON(200, gin.H{
			"Message": "List All Certificates",
			//caCerts:   caCerts,
		})
	})
}

func GetHelp(req *gin.Engine) {
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
}
