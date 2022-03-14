package src

import (
	"bytes"
	"errors"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"strconv"
	"strings"
	//"gorm.io/gorm/logger"
	"os"
	"time"
)

var (
	err            error
	db             *gorm.DB
	ShellFolder, _ = os.Getwd()
	RootPath       = ShellFolder + "/sslt/"
	sqliteMaster   SqliteMaster
	certs          Certs
)

type Certs struct {
	ID            uint `gorm:"primaryKey"`
	CommonName    string
	Host          string
	Protocol      string
	Data          string
	CaPEM         string
	CaPrivyKeyPEM string
}

type SqliteMaster struct {
	Name string
	Type string
}

type Product struct {
	Certs     // 继承
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func init() {
	if _, err = os.Stat(RootPath); err != nil {
		if err = os.Mkdir(RootPath, os.ModePerm); err != nil {
			CheckErr(errors.New("创建目录失败"))
			return
		}
	}
	//color.Red("[*] Debug mode is on")
	if db, err = gorm.Open(sqlite.Open(RootPath+"sslt.db"), &gorm.Config{
		//Logger: logger.Default.LogMode(logger.Info),
	}); err != nil {
		CheckErr(err)
		return
	}
}

func Rename(oldname string) string {
	oldname = strings.Replace(oldname, " ", "_", -1)
	return oldname

}
func CaAdd(tableName, commonName, host, protocol, data string, caPEM, caPrivyKeyPEM *bytes.Buffer) (string, string) {
	// 如果存在证书则退出
	//if certStatus, CaPEMSQL, CaPrivyKeyPEMSQL := CaInquire(tableName, commonName, host, protocol); certStatus == false {
	//	return CaPEMSQL, CaPrivyKeyPEMSQL
	//}
	// 不存在则创建
	tableName = strings.Replace(tableName, " ", "_", -1)
	commonName = strings.Replace(commonName, " ", "_", -1)
	if err = db.Table(tableName).AutoMigrate(&Product{}); err != nil {
		CheckErr(err)
		return "", ""
	}
	db.Table(tableName).Create(&Certs{
		CommonName:    commonName,
		Host:          host,
		Protocol:      protocol,
		Data:          data,
		CaPEM:         caPEM.String(),
		CaPrivyKeyPEM: caPrivyKeyPEM.String(),
	})
	Notice("存储证书:", "["+commonName+"] 到数据库 表名 -> ["+tableName+"] -> 成功")
	return caPEM.String(), caPrivyKeyPEM.String()
}

func CaInquire(tableName, commonname, host, protocol string) (bool, string, string) {
	/*
		Return false if tables/certificates exist; 'generate' if not
		SqliteMaster Inquire tableName
	*/
	tableName = Rename(tableName)
	commonname = Rename(commonname)
	if db.Select("name").Table("sqlite_master").Where("name = ? AND type = ?", tableName, "table").Scan(&sqliteMaster); sqliteMaster.Name == tableName {
		// @NUM DATABASE TABLE NAMES CANNOT BE REPEATED
		Notice("查询数据库 表名:", "["+tableName+"] 存在!")
		var NUM int64

		if db.Select("*").Table(tableName).Where("common_name = ? AND host = ? AND protocol = ?", commonname, host, protocol).Count(&NUM).Scan(&certs); certs.CommonName == commonname && certs.ID != 0 {
			// SELECT COUNT(*) AS "NUM",* FROM 'GTS_Root_R1' WHERE common_name='GTS_CA_1C3' AND host='localhost' AND protocol='x509';
			// A certificate exists. Read the certificate and return it.
			if NUM != 0 && NUM != 1 {
				Warning("查询数据库 证书:", "["+commonname+" 异常, 存在多份存档!")
			}
			Notice("查询数据库 证书:", "["+commonname+" 存在!")
			t1, _ := time.Parse("2006-01-02 15:04:05", certs.Data)
			Notice("证书有效期:", "["+strconv.FormatInt(int64(t1.Sub(time.Now()).Hours()/24), 10)+" 天")
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

// QuireAll TODO 查询所有证书
func QuireAll() string {
	db.Select("*").Table("sqlite_master").Scan(&sqliteMaster)
	//for i := 0; i < len(sqliteMaster.Name); i++ {
	//	if len(sqliteMaster.Name) == 1 {
	//		tableNames = sqliteMaster.Name
	//	} else if i+1 < len(sqliteMaster.Name) {
	//		tableNames += " " + sqliteMaster.Name[i]
	//	} else {
	//		tableNames += sqliteMaster.Name[i]
	//	}
	//}
	fmt.Println(sqliteMaster)
	return sqliteMaster.Name
	//type:table
}
