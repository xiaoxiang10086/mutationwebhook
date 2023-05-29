package main

import (
	"fmt"
	"github.com/xiaoxiang10086/mutationwebhook/internal/cmd"
	"os"
)

func main() {
	if err := cmd.GetRootCommand().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
