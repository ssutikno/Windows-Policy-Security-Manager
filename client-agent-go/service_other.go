//go:build !windows
// +build !windows

package main

import (
	"log"
)

func startService() {
	log.Println("Running in development/console mode...")
	stopChan := make(chan struct{})
	go runAgent(stopChan)
	waitForConsoleSignal(stopChan)
}
