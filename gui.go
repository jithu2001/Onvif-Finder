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

type CameraCard struct {
	Camera   Camera
	Username string
	Password string
	Streams  []StreamConfig
}

func startGUI() {
	myApp := app.NewWithID("com.onvif.discovery")
	myApp.Settings().SetTheme(&customTheme{})

	mainWindow := myApp.NewWindow("ONVIF Camera Discovery")
	mainWindow.Resize(fyne.NewSize(1000, 700))

	// State
	cameras := []CameraCard{}
	statusText := binding.NewString()
	statusText.Set("Ready to scan for cameras")

	// UI Components
	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText("5")
	timeoutEntry.SetPlaceHolder("Timeout in seconds")

	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.Wrapping = fyne.TextWrapWord

	scanButton := widget.NewButtonWithIcon("Scan for Cameras", theme.SearchIcon(), nil)

	camerasList := container.NewVBox()
	scrollContainer := container.NewVScroll(camerasList)
	scrollContainer.SetMinSize(fyne.NewSize(950, 550))

	// Scan button handler
	scanButton.OnTapped = func() {
		scanButton.Disable()
		statusText.Set("🔍 Scanning network for ONVIF cameras...")
		camerasList.Objects = nil
		cameras = []CameraCard{}

		go func() {
			timeout := 5
			fmt.Sscanf(timeoutEntry.Text, "%d", &timeout)
			if timeout < 1 {
				timeout = 5
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+2)*time.Second)
			defer cancel()

			discoveredCameras, err := discoverCamerasForAPI(ctx, timeout)

			if err != nil {
				statusText.Set("❌ Error: " + err.Error())
				scanButton.Enable()
				return
			}

			if len(discoveredCameras) == 0 {
				statusText.Set("⚠️ No cameras found. Ensure cameras are on same subnet and multicast is enabled.")
				scanButton.Enable()
				return
			}

			// Convert to camera cards
			for _, cam := range discoveredCameras {
				cameras = append(cameras, CameraCard{
					Camera:   cam,
					Username: "admin",
					Password: "",
				})
			}

			statusText.Set(fmt.Sprintf("✅ Found %d camera(s)", len(cameras)))

			// Update UI
			renderCameras(camerasList, cameras, mainWindow)
			scanButton.Enable()
		}()
	}

	// Top controls
	controlsBox := container.NewBorder(
		nil,
		nil,
		widget.NewLabel("Scan Timeout:"),
		scanButton,
		timeoutEntry,
	)

	// Main layout
	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("📹 ONVIF Camera Discovery", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			controlsBox,
			statusLabel,
			widget.NewSeparator(),
		),
		nil,
		nil,
		nil,
		scrollContainer,
	)

	mainWindow.SetContent(content)
	mainWindow.ShowAndRun()
}

func renderCameras(container *fyne.Container, cameras []CameraCard, window fyne.Window) {
	container.Objects = nil

	for i := range cameras {
		card := createCameraCard(&cameras[i], window)
		container.Add(card)
	}

	container.Refresh()
}

func createCameraCard(camCard *CameraCard, window fyne.Window) *fyne.Container {
	// Camera info
	ipLabel := widget.NewLabelWithStyle(camCard.Camera.IP, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	urlLabel := widget.NewLabel(camCard.Camera.ServiceURL)
	urlLabel.Wrapping = fyne.TextWrapBreak

	// Credentials
	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(camCard.Username)
	usernameEntry.SetPlaceHolder("Username")
	usernameEntry.OnChanged = func(value string) {
		camCard.Username = value
	}

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")
	passwordEntry.OnChanged = func(value string) {
		camCard.Password = value
	}

	// Streams display
	streamsContainer := container.NewVBox()
	streamsContainer.Hide()

	// Get streams button
	getStreamsBtn := widget.NewButton("Get RTSP Streams", nil)
	getStreamsBtn.Importance = widget.HighImportance

	getStreamsBtn.OnTapped = func() {
		getStreamsBtn.Disable()
		getStreamsBtn.SetText("Loading...")
		streamsContainer.Objects = nil
		streamsContainer.Hide()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(DefaultHTTPTimeout+5)*time.Second)
			defer cancel()

			streams, err := getStreamsFromService(ctx, camCard.Camera.ServiceURL, camCard.Username, camCard.Password)

			if err != nil {
				dialog.ShowError(fmt.Errorf("Failed to get streams: %v", err), window)
				getStreamsBtn.SetText("Get RTSP Streams")
				getStreamsBtn.Enable()
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

			getStreamsBtn.SetText("Get RTSP Streams")
			getStreamsBtn.Enable()
			streamsContainer.Refresh()
		}()
	}

	credentialsForm := container.NewGridWithColumns(2,
		usernameEntry,
		passwordEntry,
	)

	card := container.NewVBox(
		container.NewHBox(
			widget.NewIcon(theme.MediaVideoIcon()),
			container.NewVBox(
				ipLabel,
				urlLabel,
			),
		),
		widget.NewSeparator(),
		credentialsForm,
		getStreamsBtn,
		streamsContainer,
		widget.NewSeparator(),
	)

	return container.NewPadded(card)
}

func createStreamCard(stream StreamConfig, window fyne.Window) *fyne.Container {
	nameLabel := widget.NewLabelWithStyle(stream.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	detailsText := fmt.Sprintf("📐 %dx%d  |  🎞️ %d fps  |  💾 %d kbps  |  🎬 %s",
		stream.Width, stream.Height, stream.FPS, stream.Bitrate/1000, stream.Encoding)
	detailsLabel := widget.NewLabel(detailsText)

	urlEntry := widget.NewEntry()
	urlEntry.SetText(stream.RTSPURL)
	urlEntry.Disable()

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(stream.RTSPURL)
		dialog.ShowInformation("Copied", "RTSP URL copied to clipboard", window)
	})

	urlContainer := container.NewBorder(
		nil,
		nil,
		nil,
		copyBtn,
		urlEntry,
	)

	return container.NewVBox(
		nameLabel,
		detailsLabel,
		widget.NewLabel("RTSP URL:"),
		urlContainer,
	)
}

// Custom theme
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
