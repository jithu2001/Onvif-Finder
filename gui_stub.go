// +build !gui

package main

import (
	"fmt"
	"os"
)

func startGUI() {
	fmt.Println("Native GUI is not available in this build.")
	fmt.Println("Use 'desktop' command instead for cross-platform desktop app.")
	fmt.Println("Or compile with: go build -tags gui")
	os.Exit(1)
}
