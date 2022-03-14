package src

import (
	"github.com/fatih/color"
	"path"
	"runtime"
	"strconv"
	"time"
)

var (
	Errors map[string]string
	//	notice  = color.New(color.FgBlue).PrintfFunc()
	//	warning = color.New(color.FgYellow).PrintfFunc()
	//	errors  = color.New(color.FgRed).PrintfFunc()
	//	succee  = color.New(color.FgGreen).PrintfFunc()
)

func HappyLogo() {
	color.Green("\033[H\033[2J -------------------------------\n")
	color.Cyan("   _____   _____  .      _______")
	color.Blue("  (       (      /     '   /   ")
	color.Red("   `--.    `--.  |         |   ")
	color.Magenta("      |       |  |         |   ")
	color.Yellow(" \\___.'  \\___.'  /---/     /   \n")
}

func CheckErr(err error) {
	if err != nil {
		pc, file, line, _ := runtime.Caller(1)
		color.New(color.FgRed).PrintfFunc()(" [sslt ")
		color.New(color.FgMagenta).PrintfFunc()("%v:", time.Now().Format("15:04:05.00000"))
		color.New(color.FgGreen).PrintfFunc()("%v] %v:%v:", path.Ext(runtime.FuncForPC(pc).Name())[1:], path.Base(file), line)
		color.Yellow(" %v", err)
		Errors["sslt "+time.Now().Format("15:04:05.00000")+" "+path.Ext(runtime.FuncForPC(pc).Name())[1:]+" "+path.Base(file)+":"+strconv.Itoa(line)] = err.Error()
		runtime.Goexit()
	}
}

// ErrorS 返回所有的错误信息
func ErrorS() map[string]string {
	return Errors
}

func Notice(noticeTXT, resultTXT string) {
	color.New(color.FgBlue).PrintfFunc()(" %v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()("%v\n", resultTXT)
	Errors[noticeTXT] = resultTXT
}

func Error(noticeTXT, resultTXT string) {
	color.New(color.FgYellow).PrintfFunc()(" %v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()("%v\n", resultTXT)
	Errors[noticeTXT] = resultTXT
}

func Warning(noticeTXT, resultTXT string) {
	color.New(color.FgRed).PrintfFunc()(" %v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()("%v\n", resultTXT)
	Errors[noticeTXT] = resultTXT
}
