package main

import (
	"flag"
	"fmt"
	"os"

	"alertcorr/internal/scenario"
)

func main() {
	dir := flag.String("data", "data", "持久化目录（规则/原始告警/事件/抑制关系分别保存）")
	flag.Parse()
	report, err := scenario.Run(*dir)
	fmt.Print(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
