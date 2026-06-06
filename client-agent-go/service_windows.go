//go:build windows
// +build windows

package main

import (
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

type wwpoService struct {
	stopChan chan struct{}
}

func (s *wwpoService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Start the background agent
	go runAgent(s.stopChan)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(s.stopChan)
				// Wait briefly for goroutine to wind down
				time.Sleep(500 * time.Millisecond)
				changes <- svc.Status{State: svc.Stopped}
				return
			default:
				log.Printf("[SERVICE] Unexpected control request: %d", c.Cmd)
			}
		}
	}
}

func startService() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to check if running as Windows Service: %v", err)
	}
	if isService {
		log.Println("Initializing as Windows Service...")
		err = svc.Run("WWPOAgent", &wwpoService{stopChan: make(chan struct{})})
		if err != nil {
			log.Fatalf("Windows Service execution failed: %v", err)
		}
	} else {
		// Run as normal console app
		stopChan := make(chan struct{})
		go runAgent(stopChan)
		waitForConsoleSignal(stopChan)
	}
}
