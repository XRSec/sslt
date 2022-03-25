package main

import (
	"flag"
	"github.com/fatih/color"
	"github.com/spf13/viper"
	. "sslt/src/Server"
	. "sslt/src/log"
)

var (
	buildTime, commitId, versionData, author, port string
	help, version, api                             bool
)

func init() {
	HappyLogo()
	flag.BoolVar(&help, "h", false, "Display help information")
	flag.BoolVar(&help, "help", false, "Display help information")
	flag.BoolVar(&version, "v", false, "sslt version")
	flag.BoolVar(&api, "api", false, "sslt Api Model")
	flag.StringVar(&port, "port", "8081", "sslt Api Port")
	viper.SetDefault("Version", versionData)
	viper.SetDefault("BuildTime", buildTime)
	viper.SetDefault("Author", author)
	viper.SetDefault("CommitId", commitId)
}

func main() {
	color.Green(" ----------------------     \n")
	defer color.Green(" -------------------------------\n")
	flag.Parse()
	if help {
		flag.Usage()
		return
	}
	// Version
	if version {
		Notice("Version:", versionData)
		Notice("BuildTime:", buildTime)
		Notice("Author:", author)
		Notice("CommitId:", commitId)
		return
	}
	// TODO Debug
	api = true
	if api {
		viper.SetDefault("port", port)
		ApiServer(api)
	} else {
		Server(api)
	}
}
