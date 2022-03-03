package src

import (
	"github.com/fatih/color"
	"os"
	"path"
	"runtime"
	"time"
)

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
