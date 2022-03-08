package src

import (
	"github.com/fatih/color"
	"os"
	"path"
	"runtime"
	"time"
)

//var (
//	notice  = color.New(color.FgBlue).PrintfFunc()
//	warning = color.New(color.FgYellow).PrintfFunc()
//	errors  = color.New(color.FgRed).PrintfFunc()
//	succee  = color.New(color.FgGreen).PrintfFunc()
//)

func CheckErr(err error) {
	if err != nil {
		pc, file, line, _ := runtime.Caller(1)
		color.New(color.FgRed).PrintfFunc()(" [sslt] ")
		color.New(color.FgMagenta).PrintfFunc()("%v ", time.Now().Format("15:04:05"))
		color.New(color.FgGreen).PrintfFunc()("%v:%v:%v", path.Base(file), runtime.FuncForPC(pc).Name(), line)
		color.Yellow(" %v", err)
		os.Exit(0)
	}
}
func Notice(noticeTXT, resultTXT string) {
	color.New(color.FgBlue).PrintfFunc()(" %v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()("%v\n", resultTXT)
}
