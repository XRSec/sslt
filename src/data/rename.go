package src

import "strings"

func Rename(oldname string) string {
	oldname = strings.Replace(oldname, " ", "_", -1)
	return oldname
}
