package src

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path"
	"runtime"
	"strconv"
	"time"
)

type MyFormatter struct{}

func init() {
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&MyFormatter{})
}

func HappyLogo() {
	color.Green("\033[H\033[2J -------------------------------\n")
	color.Cyan("   _____   _____  .      _______")
	color.Blue("  (       (      /     '   /   ")
	color.Red("   `--.    `--.  |         |   ")
	color.Magenta("      |       |  |         |   ")
	color.Yellow(" \\___.'  \\___.'  /---/     /   \n")
}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	// 创建日志文件夹
	if _, err := os.Stat(viper.Get("logPath").(string)); err != nil {
		if err = os.MkdirAll(viper.Get("logPath").(string), os.ModePerm); err != nil {
			fmt.Println("创建日志目录失败")
			return nil, err
		}
	}
	b = &bytes.Buffer{}
	pc, file, line, _ := runtime.Caller(8)
	newLog := make(map[string]interface{})
	result := make(map[string]interface{})
	if err := json.Unmarshal([]byte(entry.Message), &result); err != nil {
		newLog["Result"] = entry.Message
	} else {
		newLog["Result"] = result
	}
	newLog["File"] = path.Ext(runtime.FuncForPC(pc).Name())[1:]
	newLog["Function"] = path.Base(file) + ":" + strconv.Itoa(line)
	newLog["Level"] = entry.Level.String()
	newLog["Time"] = entry.Time.Format("2006-01-02 15:04:05.00000")
	j, _ := json.Marshal(newLog)
	b.WriteString(string(j) + "\n")

	// 切割日志和清理过期日志
	logrus.SetOutput(&lumberjack.Logger{
		Filename:   viper.Get("logPath").(string) + "sslt.log", //日志文件位置
		MaxSize:    50,                                         // 单文件最大容量,单位是MB
		MaxBackups: 1,                                          // 最大保留过期文件个数
		MaxAge:     365,                                        // 保留过期文件的最大时间间隔,单位是天
		Compress:   true,                                       // 是否需要压缩滚动日志, 使用的 gzip 压缩
	})
	return b.Bytes(), nil
}

func CheckErr(err error) {
	if err != nil {
		pc, file, line, _ := runtime.Caller(1)
		color.New(color.FgRed).PrintfFunc()(" [sslt] ")
		color.New(color.FgMagenta).PrintfFunc()("%v:", time.Now().Format("15:04:05.00000"))
		color.New(color.FgGreen).PrintfFunc()("%v %v:%v:", path.Ext(runtime.FuncForPC(pc).Name())[1:], path.Base(file), line)
		color.Yellow(" %v", err)
		logrus.Warning(err)
	}
	return
}

func Notice(noticeTXT, resultTXT string) {
	color.New(color.FgBlue).PrintfFunc()(" %-12v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()(" %v\n", resultTXT)
	logrus.Info(noticeTXT + resultTXT)
}

func Error(noticeTXT, resultTXT string) {
	color.New(color.FgYellow).PrintfFunc()(" %-12v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()(" %v\n", resultTXT)
	logrus.Error(noticeTXT + resultTXT)
}

func Warning(noticeTXT, resultTXT string) {
	color.New(color.FgRed).PrintfFunc()(" %-12v", noticeTXT)
	color.New(color.FgGreen).PrintfFunc()(" %v\n", resultTXT)
	logrus.Warning(noticeTXT + resultTXT)
}
