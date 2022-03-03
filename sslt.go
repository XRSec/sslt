package main

import (
	"flag"
	"github.com/fatih/color"
	"os"
	. "sslt/src"
)

var (
	r, rk, ro, rc, so, sc, c, h, buildTime, commitId, versions, author string
	help, version                                                      bool
)

func init() {
	happyLogo()
	//flag.StringVar(&r, "r", "sslt/ca.pem", "Import Root_CA")
	flag.StringVar(&r, "r", "default", "Import Root_CA")
	flag.StringVar(&ro, "ro", "Google Trust Services LLC", "Specified Root Organization")
	flag.StringVar(&rc, "rc", "GTS Root R1", "Specified Root CommonName")
	//flag.StringVar(&rk, "rk", "sslt/ca.key.pem", "Import Root_CA Key")
	flag.StringVar(&rk, "rk", "default", "Import Root_CA Key")
	flag.StringVar(&so, "so", "Google Trust Services LLC", "Specified Server Organization")
	flag.StringVar(&sc, "sc", "GTS CA 1C3", "Specified Server CommonName")
	flag.StringVar(&c, "c", "US", "Specified Country")
	flag.StringVar(&h, "h", "baidu.com", "Specified domain name")
	flag.BoolVar(&help, "help", false, "Display help information")
	flag.BoolVar(&version, "v", false, "sslt version")
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
	color.Green(" ----------------------     \n")
	defer color.Green(" -------------------------------\n")
	flag.Parse()
	if help {
		flag.Usage()
		os.Exit(0)
	}
	if version {
		color.Green(" Verdion: %v BuildTime: %v", versions, buildTime)
		color.Green(" Author: %v CommitId: %v", author, commitId)
		os.Exit(0)
	}
	// get our ca and server certificate
	GetConfig(r, rk, rc, ro, sc, so, c, h)
}
