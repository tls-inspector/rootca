package main

import (
	"fmt"
	"log"
	"os"
)

var isGithubAction = os.Getenv("GITHUB_ACTIONS") == "true"

func logNotice(format string, v ...any) {
	if !isGithubAction {
		log.Printf("%s", fmt.Sprintf(format, v...))
		return
	}

	fmt.Printf("::notice ::%s\n", fmt.Sprintf(format, v...))
}

func logWarning(format string, v ...any) {
	if !isGithubAction {
		log.Printf("%s", fmt.Sprintf(format, v...))
		return
	}

	fmt.Printf("::warning ::%s\n", fmt.Sprintf(format, v...))
}

func logError(format string, v ...any) {
	if !isGithubAction {
		log.Printf("%s", fmt.Sprintf(format, v...))
		return
	}

	fmt.Printf("::error ::%s\n", fmt.Sprintf(format, v...))
}

func logFatal(format string, v ...any) {
	logError(format, v...)
	os.Exit(1)
}
