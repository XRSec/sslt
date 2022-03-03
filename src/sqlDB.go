package src

import (
	"bytes"
	"github.com/fatih/color"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"os"
	"time"
)

var (
	db             *gorm.DB
	ShellFolder, _ = os.Getwd()
	RootPath       = ShellFolder + "/sslt/"
	certs          struct {
		ID            uint `gorm:"primaryKey"`
		CommonName    string
		Host          string
		CaPEM         string
		CaPrivyKeyPEM string
	}
	sqliteMaster struct {
		Type string
		Name string
	}
)

type Product struct {
	ID            uint `gorm:"primaryKey"`
	CommonName    string
	Host          string
	CaPEM         string
	CaPrivyKeyPEM string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}

func init() {
	_, err := os.Stat(RootPath)
	if err != nil {
		err = os.Mkdir(RootPath, os.ModePerm)
	}
	//color.Red("[*] Debug mode is on")
	db, err = gorm.Open(sqlite.Open("sslt/sslt.db"), &gorm.Config{
		//Logger: logger.Default.LogMode(logger.Info),
	})
	CheckErr(err)
}

func CaAdd(tableName, commonname, host string, caPEM, caPrivyKeyPEM *bytes.Buffer) (string, string) {
	// 如果存在证书则退出
	if certStatus, CaPEMSQL, CaPrivyKeyPEMSQL := CaInquire(tableName, commonname, host); certStatus == false {
		return CaPEMSQL, CaPrivyKeyPEMSQL
	}
	// 不存在则创建
	color.New(color.FgMagenta).PrintfFunc()("  Writing Cert.Sql:")
	color.New(color.FgYellow).PrintfFunc()("   [%v/%v] Start!\n", tableName, commonname)
	err := db.Table(tableName).AutoMigrate(&Product{})
	CheckErr(err)
	db.Table(tableName).Create(&Product{
		CommonName:    commonname,
		Host:          host,
		CaPEM:         caPEM.String(),
		CaPrivyKeyPEM: caPrivyKeyPEM.String(),
	})
	color.New(color.FgMagenta).PrintfFunc()("  Writing Cert.Sql:")
	color.New(color.FgYellow).PrintfFunc()("   Write Cert.Sql:   [%v]  Sqlite Succeed!\n", commonname)
	return caPEM.String(), caPrivyKeyPEM.String()
}

func CaInquire(tableName, commonname, host string) (bool, string, string) {
	// SqliteMaster Inquire tableName
	if db.Select("name").Table("sqlite_master").Where("name = ? AND type = ?", tableName, "table").Scan(&sqliteMaster); sqliteMaster.Name == tableName {
		color.New(color.FgMagenta).PrintfFunc()("  Query Table:")
		color.New(color.FgYellow).PrintfFunc()("        [%v] exist!\n", tableName)
		if db.Select("*").Table(tableName).Where("common_name = ? AND host = ?", commonname, host).Scan(&certs); certs.CommonName == commonname && certs.ID != 0 {
			// 存在证书，读取证书】

			color.New(color.FgMagenta).PrintfFunc()("  Reading Cert.Sql:")
			color.New(color.FgYellow).PrintfFunc()("   [%v] exist!\n", commonname)
			return false, certs.CaPEM, certs.CaPrivyKeyPEM
		} else {
			// No certificate exists, write to database
			return true, certs.CaPEM, certs.CaPrivyKeyPEM
		}
	} else {
		// There is no certificate in the database with the Root CommonName
		return true, certs.CaPEM, certs.CaPrivyKeyPEM
	}
}
