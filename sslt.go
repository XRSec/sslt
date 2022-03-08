package main

import (
	"flag"
	"github.com/fatih/color"
	"net"
	"os"
	"sslt/encryption/rsa"
	//"sslt/encryption/sm2"
	//"github.com/gin-gonic/gin"
	. "sslt/src"
)

var (
	r, rk, ro, rc, s, sk, so, sc, c, h, p, buildTime, commitId, version, author string
	help, v                                                                     bool
)

func init() {
	happyLogo()
	//flag.StringVar(&r, "r", "default", "Import CA")
	//flag.StringVar(&rk, "rk", "default", "Import CA Key")
	//flag.StringVar(&s, "s", "default", "Import Server")
	//flag.StringVar(&sk, "sk", "default", "Import Server Key")
	flag.StringVar(&r, "r", "sslt/ca.pem", "Import CA")
	flag.StringVar(&s, "s", "sslt/server.pem", "Import Cert CA")
	flag.StringVar(&rk, "rk", "sslt/ca.key.pe", "Import CA Key")
	flag.StringVar(&sk, "sk", "sslt/server.key.pe", "Import Cert CA Key")
	flag.StringVar(&ro, "ro", "Google Trust Services LLC", "Specified Root Organization")
	flag.StringVar(&rc, "rc", "GTS Root R1", "Specified Root CommonName")
	flag.StringVar(&so, "so", "Google Trust Services LLC", "Specified Server Organization")
	flag.StringVar(&sc, "sc", "GTS CA 1C3", "Specified Server CommonName")
	flag.StringVar(&c, "c", "US", "Specified Country")
	flag.StringVar(&h, "h", "localhost", "Specified domain name")
	flag.StringVar(&p, "p", "rsa", "Specified encryption protocol")
	flag.BoolVar(&help, "help", false, "Display help information")
	flag.BoolVar(&v, "v", false, "sslt version")
}

func happyLogo() {
	color.Green("\033[H\033[2J -------------------------------\n")
	color.Cyan("   _____   _____  .      _______")
	color.Blue("  (       (      /     '   /   ")
	color.Red("   `--.    `--.  |         |   ")
	color.Magenta("      |       |  |         |   ")
	color.Yellow(" \\___.'  \\___.'  /---/     /   \n")
}

func main() {
	/*
		检测用户输入并判断
			 证书协议
				生成还是导入证书
					是否存在已有证书
	*/
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

	if p == "rsa" {
		// Import CA
		if r != "default" || s != "default" {
			if r != "default" && rk != "default" {
				// IMPORT CA CERTIFICATE
				rsa.ImportCert(r, rk)
			}
			if s != "default" && sk != "default" {
				// IMPORT CERT CERTIFICATE
				rsa.ImportCert(s, sk)
			}
			if (r != "default" && rk == "default") || (r == "default" && rk != "default") || (s != "default" && sk == "default") || (s == "default" && sk != "default") {
				Notice(" 没有找到证书文件(公钥或私钥缺失): ", "「CA: "+r+"」「CA KEY: "+rk+"」「CERT: "+s+"」「CERT KEY: "+sk+"」")
			}
			os.Exit(0)
		} else {
			// Generate CA
			CaTLSConf, CertTLSConf := rsa.Setup(rc, ro, sc, so, c, h, p)
			// wherr The Test Was Successful
			// Verify (ca cert)certificate is ok?
			if net.ParseIP(h) == nil {
				rsa.VerifyDomainCa(CaTLSConf, CertTLSConf, h)
			} else {
				// TODO 现在需要设计 验证 跟证书 和 服务证书 之间是否存在证书链接
				color.Blue(" 暂时没有IP证书的验证方式,请尝试上传服务器验证")
			}
		}
	}
	// << Start by identifying the functionality the user needs
}
