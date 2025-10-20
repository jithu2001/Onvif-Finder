package main

import (
	"context"
)

// ============================================================================
// APPLICATION CONSTANTS
// ============================================================================

const (
	Version        = "1.0.0"
	DefaultTimeout = 5 // seconds
)

// ============================================================================
// APPLICATION ENTRY POINT
// ============================================================================

func main() {
	// Launch GUI application
	startGUI()
}

// ============================================================================
// API FUNCTIONS FOR GUI
// ============================================================================

// discoverCamerasForAPI is a wrapper for GUI to discover cameras
func discoverCamerasForAPI(ctx context.Context, timeoutSec int) ([]Camera, error) {
	return DiscoverCameras(ctx, timeoutSec)
}

// getStreamsFromService is a wrapper for GUI to get streams
func getStreamsFromService(ctx context.Context, serviceURL, username, password string) ([]StreamConfig, error) {
	return GetStreams(ctx, serviceURL, username, password)
}
