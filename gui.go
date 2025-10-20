package main

import (
	"context"
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ============================================================================
// GUI APPLICATION
// ============================================================================

// CameraCard represents a camera with its credentials and streams
type CameraCard struct {
	Camera   Camera
	Username string
	Password string
	Streams  []StreamConfig
}

// startGUI initializes and starts the Fyne GUI application
func startGUI() {
	myApp := app.NewWithID("com.onvif.discovery")
	myApp.Settings().SetTheme(&customTheme{})

	mainWindow := myApp.NewWindow("ONVIF Camera Discovery")
	mainWindow.Resize(fyne.NewSize(1000, 700))

	// Create UI
	content := createMainUI(mainWindow)
	mainWindow.SetContent(content)
	mainWindow.ShowAndRun()
}

// ============================================================================
// UI CREATION
// ============================================================================

// createMainUI creates the main user interface
func createMainUI(window fyne.Window) *fyne.Container {
	// State
	cameras := []CameraCard{}
	statusText := binding.NewString()
	statusText.Set("Ready to scan for cameras")

	// UI Components
	timeoutEntry := createTimeoutInput()
	statusLabel := createStatusLabel(statusText)
	camerasList := container.NewVBox()
	scrollContainer := container.NewVScroll(camerasList)
	scrollContainer.SetMinSize(fyne.NewSize(950, 550))

	// Scan button
	scanButton := createScanButton(&cameras, camerasList, statusText, timeoutEntry, window)

	// Layout
	controls := createControlsSection(timeoutEntry, scanButton)
	header := createHeaderSection(controls, statusLabel)

	return container.NewBorder(header, nil, nil, nil, scrollContainer)
}

// createHeaderSection creates the header with controls and status
func createHeaderSection(controls, statusLabel fyne.CanvasObject) *fyne.Container {
	return container.NewVBox(
		widget.NewLabelWithStyle("📹 ONVIF Camera Discovery", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		controls,
		statusLabel,
		widget.NewSeparator(),
	)
}

// createControlsSection creates the scan controls section
func createControlsSection(timeoutEntry *widget.Entry, scanButton *widget.Button) *fyne.Container {
	return container.NewBorder(
		nil,
		nil,
		widget.NewLabel("Scan Timeout:"),
		scanButton,
		timeoutEntry,
	)
}

// createTimeoutInput creates the timeout input field
func createTimeoutInput() *widget.Entry {
	entry := widget.NewEntry()
	entry.SetText("5")
	entry.SetPlaceHolder("Timeout in seconds")
	return entry
}

// createStatusLabel creates the status label
func createStatusLabel(statusText binding.String) *widget.Label {
	label := widget.NewLabelWithData(statusText)
	label.Wrapping = fyne.TextWrapWord
	return label
}

// createScanButton creates the scan button with its handler
func createScanButton(cameras *[]CameraCard, camerasList *fyne.Container, statusText binding.String, timeoutEntry *widget.Entry, window fyne.Window) *widget.Button {
	scanButton := widget.NewButtonWithIcon("Scan for Cameras", theme.SearchIcon(), nil)

	scanButton.OnTapped = func() {
		handleScanAction(cameras, camerasList, statusText, timeoutEntry, scanButton, window)
	}

	return scanButton
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

// handleScanAction handles the scan button click
func handleScanAction(cameras *[]CameraCard, camerasList *fyne.Container, statusText binding.String, timeoutEntry *widget.Entry, scanButton *widget.Button, window fyne.Window) {
	scanButton.Disable()
	statusText.Set("🔍 Scanning network for ONVIF cameras...")
	camerasList.Objects = nil
	*cameras = []CameraCard{}

	go func() {
		defer scanButton.Enable()

		// Get timeout
		timeout := DefaultTimeout
		fmt.Sscanf(timeoutEntry.Text, "%d", &timeout)
		if timeout < 1 {
			timeout = DefaultTimeout
		}

		// Discover cameras
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+2)*time.Second)
		defer cancel()

		discoveredCameras, err := discoverCamerasForAPI(ctx, timeout)
		if err != nil {
			statusText.Set("❌ Error: " + err.Error())
			return
		}

		if len(discoveredCameras) == 0 {
			statusText.Set("⚠️ No cameras found. Ensure cameras are on same subnet and multicast is enabled.")
			return
		}

		// Convert to camera cards
		for _, cam := range discoveredCameras {
			*cameras = append(*cameras, CameraCard{
				Camera:   cam,
				Username: "admin",
				Password: "",
			})
		}

		statusText.Set(fmt.Sprintf("✅ Found %d camera(s)", len(*cameras)))
		renderCameras(camerasList, *cameras, window)
	}()
}

// ============================================================================
// CAMERA RENDERING
// ============================================================================

// renderCameras renders all discovered cameras
func renderCameras(container *fyne.Container, cameras []CameraCard, window fyne.Window) {
	container.Objects = nil

	for i := range cameras {
		card := createCameraCard(&cameras[i], window)
		container.Add(card)
	}

	container.Refresh()
}

// createCameraCard creates a card for a single camera
func createCameraCard(camCard *CameraCard, window fyne.Window) *fyne.Container {
	// Camera information
	ipLabel := widget.NewLabelWithStyle(camCard.Camera.IP, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	urlLabel := widget.NewLabel(camCard.Camera.ServiceURL)
	urlLabel.Wrapping = fyne.TextWrapBreak

	// Credentials inputs
	usernameEntry := createUsernameEntry(camCard)
	passwordEntry := createPasswordEntry(camCard)
	credentialsForm := container.NewGridWithColumns(2, usernameEntry, passwordEntry)

	// Streams display
	streamsContainer := container.NewVBox()
	streamsContainer.Hide()

	// Get streams button
	getStreamsBtn := createGetStreamsButton(camCard, streamsContainer, window)

	// Camera card layout
	return container.NewPadded(
		container.NewVBox(
			container.NewHBox(
				widget.NewIcon(theme.MediaVideoIcon()),
				container.NewVBox(ipLabel, urlLabel),
			),
			widget.NewSeparator(),
			credentialsForm,
			getStreamsBtn,
			streamsContainer,
			widget.NewSeparator(),
		),
	)
}

// createUsernameEntry creates the username input
func createUsernameEntry(camCard *CameraCard) *widget.Entry {
	entry := widget.NewEntry()
	entry.SetText(camCard.Username)
	entry.SetPlaceHolder("Username")
	entry.OnChanged = func(value string) {
		camCard.Username = value
	}
	return entry
}

// createPasswordEntry creates the password input
func createPasswordEntry(camCard *CameraCard) *widget.Entry {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("Password")
	entry.OnChanged = func(value string) {
		camCard.Password = value
	}
	return entry
}

// createGetStreamsButton creates the button to retrieve streams
func createGetStreamsButton(camCard *CameraCard, streamsContainer *fyne.Container, window fyne.Window) *widget.Button {
	btn := widget.NewButton("Get RTSP Streams", nil)
	btn.Importance = widget.HighImportance

	btn.OnTapped = func() {
		handleGetStreams(camCard, streamsContainer, btn, window)
	}

	return btn
}

// handleGetStreams handles the get streams button click
func handleGetStreams(camCard *CameraCard, streamsContainer *fyne.Container, btn *widget.Button, window fyne.Window) {
	btn.Disable()
	btn.SetText("Loading...")
	streamsContainer.Objects = nil
	streamsContainer.Hide()

	go func() {
		defer func() {
			btn.SetText("Get RTSP Streams")
			btn.Enable()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(DefaultHTTPTimeout+5)*time.Second)
		defer cancel()

		streams, err := getStreamsFromService(ctx, camCard.Camera.ServiceURL, camCard.Username, camCard.Password)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to get streams: %v", err), window)
			return
		}

		camCard.Streams = streams

		// Render streams
		for _, stream := range streams {
			streamCard := createStreamCard(stream, window)
			streamsContainer.Add(streamCard)
		}

		if len(streams) > 0 {
			streamsContainer.Show()
		} else {
			dialog.ShowInformation("No Streams", "No streams found for this camera", window)
		}

		streamsContainer.Refresh()
	}()
}

// ============================================================================
// STREAM RENDERING
// ============================================================================

// createStreamCard creates a card displaying stream information
func createStreamCard(stream StreamConfig, window fyne.Window) *fyne.Container {
	// Stream name
	nameLabel := widget.NewLabelWithStyle(stream.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Stream details
	detailsText := fmt.Sprintf("📐 %dx%d  |  🎞️ %d fps  |  💾 %d kbps  |  🎬 %s",
		stream.Width, stream.Height, stream.FPS, stream.Bitrate/1000, stream.Encoding)
	detailsLabel := widget.NewLabel(detailsText)

	// RTSP URL with copy button
	urlEntry := widget.NewEntry()
	urlEntry.SetText(stream.RTSPURL)
	urlEntry.Disable()

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(stream.RTSPURL)
		dialog.ShowInformation("Copied", "RTSP URL copied to clipboard", window)
	})

	urlContainer := container.NewBorder(nil, nil, nil, copyBtn, urlEntry)

	return container.NewVBox(
		nameLabel,
		detailsLabel,
		widget.NewLabel("RTSP URL:"),
		urlContainer,
	)
}

// ============================================================================
// CUSTOM THEME
// ============================================================================

// customTheme provides a custom color theme
type customTheme struct{}

func (m customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return &color.RGBA{R: 102, G: 126, B: 234, A: 255}
	case theme.ColorNameButton:
		return &color.RGBA{R: 118, G: 75, B: 162, A: 255}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (m customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (m customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (m customTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
