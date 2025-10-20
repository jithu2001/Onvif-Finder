package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func startDesktopApp() {
	// Find available port
	port := findAvailablePort()
	if port == "" {
		log.Fatal("Could not find available port")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start web server in background
	serverReady := make(chan bool)
	go func() {
		logger.Info("Starting desktop app on port %s", port)

		// Signal when server is ready
		go func() {
			time.Sleep(500 * time.Millisecond)
			serverReady <- true
		}()

		if err := startWebUI(ctx, port); err != nil {
			logger.Error("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	<-serverReady

	// Open browser
	url := fmt.Sprintf("http://localhost:%s", port)
	if err := openBrowser(url); err != nil {
		logger.Error("Could not open browser: %v", err)
		fmt.Printf("\nPlease open your browser and navigate to: %s\n", url)
	}

	fmt.Printf("\n📹 ONVIF Camera Discovery Desktop App\n")
	fmt.Printf("   Running on: %s\n", url)
	fmt.Printf("   Press Ctrl+C to quit\n\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	cancel()
	time.Sleep(500 * time.Millisecond)
}

func findAvailablePort() string {
	// Try ports 8080-8090
	for port := 8080; port <= 8090; port++ {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			listener.Close()
			return fmt.Sprintf("%d", port)
		}
	}
	return ""
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		// Try common Linux browsers
		browsers := []string{"xdg-open", "sensible-browser", "firefox", "chromium", "google-chrome"}
		for _, browser := range browsers {
			if _, err := exec.LookPath(browser); err == nil {
				cmd = exec.Command(browser, url)
				break
			}
		}
		if cmd == nil {
			return fmt.Errorf("no suitable browser found")
		}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}
