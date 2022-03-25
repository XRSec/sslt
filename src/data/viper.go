package src

import (
	"github.com/spf13/viper"
	"os"
)

func init() {
	shellFolder, _ := os.Getwd()
	rootPath := shellFolder + "/sslt/"
	viper.SetDefault("rootPath", rootPath)
	viper.SetDefault("logPath", rootPath+"logs/")
}
