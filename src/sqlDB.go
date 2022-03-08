package src

import (
	"bytes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"strconv"
	"strings"
	//"gorm.io/gorm/logger"
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
		Protocol      string
		Data          string
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
	Protocol      string
	Data          string
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

func CaAdd(tableName, commonname, host, protocol, data string, caPEM, caPrivyKeyPEM *bytes.Buffer) (string, string) {
	// 如果存在证书则退出
	//if certStatus, CaPEMSQL, CaPrivyKeyPEMSQL := CaInquire(tableName, commonname, host, protocol); certStatus == false {
	//	return CaPEMSQL, CaPrivyKeyPEMSQL
	//}
	// 不存在则创建
	tableName = strings.Replace(tableName, " ", "_", -1)
	commonname = strings.Replace(commonname, " ", "_", -1)
	err := db.Table(tableName).AutoMigrate(&Product{})
	CheckErr(err)
	db.Table(tableName).Create(&Product{
		CommonName:    commonname,
		Host:          host,
		Protocol:      protocol,
		Data:          data,
		CaPEM:         caPEM.String(),
		CaPrivyKeyPEM: caPrivyKeyPEM.String(),
	})
	Notice(" 存储证书:           ", "["+commonname+"] 到数据库 表名 -> ["+tableName+"] -> 成功")
	return caPEM.String(), caPrivyKeyPEM.String()
}

func CaInquire(tableName, commonname, host, protocol string) (bool, string, string) {
	/*
		Return false if tables/certificates exist; 'generate' if not
		SqliteMaster Inquire tableName
	*/
	tableName = strings.Replace(tableName, " ", "_", -1)
	commonname = strings.Replace(commonname, " ", "_", -1)
	if db.Select("name").Table("sqlite_master").Where("name = ? AND type = ?", tableName, "table").Scan(&sqliteMaster); sqliteMaster.Name == tableName {
		Notice(" 查询数据库 表名:    ", "["+tableName+"] 存在!")
		if db.Select("*").Table(tableName).Where("common_name = ? AND host = ? AND protocol = ?", commonname, host, protocol).Scan(&certs); certs.CommonName == commonname && certs.ID != 0 {
			// A certificate exists. Read the certificate
			Notice(" 查询数据库 证书:    ", "["+commonname+"] 存在!")
			t1, _ := time.Parse("2006-01-02 15:04:05", certs.Data)
			Notice(" 证书有效期:         ", "["+strconv.FormatInt(int64(t1.Sub(time.Now()).Hours()/24), 10)+"] 天")
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
