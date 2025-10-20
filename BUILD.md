# Building ONVIF Camera Discovery

This is a pure native GUI application built with Fyne. No web browser, no terminal window.

## ✅ Pre-built (macOS)

The `ONVIF Camera Discovery.app` is ready to use on macOS:
- Just double-click to launch
- Native macOS application
- No terminal window

## 🔨 Building from Source

### macOS

```bash
# Install Go 1.21+ from https://golang.org/dl/
# Clone the repository
cd onvif-discover

# Build
go build -ldflags="-s -w" -o "ONVIF Camera Discovery"

# Create app bundle
mkdir -p "ONVIF Camera Discovery.app/Contents/MacOS"
mkdir -p "ONVIF Camera Discovery.app/Contents/Resources"
cp "ONVIF Camera Discovery" "ONVIF Camera Discovery.app/Contents/MacOS/"
# Copy Info.plist (already in the bundle)

# Run
open "ONVIF Camera Discovery.app"
```

### Windows

```bash
# Install Go 1.21+ from https://golang.org/dl/
# Install gcc (MinGW-w64 recommended)

# Clone the repository
cd onvif-discover

# Build (hides console window)
go build -ldflags="-s -w -H=windowsgui" -o "ONVIF Camera Discovery.exe"

# Run
"ONVIF Camera Discovery.exe"
```

**Note:** Windows build must be done on Windows due to CGO requirements.

### Linux

```bash
# Install Go 1.21+
# Install development packages
sudo apt-get install gcc libgl1-mesa-dev xorg-dev  # Ubuntu/Debian
# OR
sudo dnf install gcc mesa-libGL-devel libXcursor-devel libXrandr-devel libXinerama-devel libXi-devel  # Fedora

# Clone the repository
cd onvif-discover

# Build
go build -ldflags="-s -w" -o "ONVIF Camera Discovery"

# Run
./ONVIF\ Camera\ Discovery
```

## 📦 Dependencies

- Go 1.21 or later
- Fyne v2.7.0 (automatically installed via `go mod download`)
- C compiler (gcc):
  - macOS: Xcode Command Line Tools
  - Windows: MinGW-w64
  - Linux: gcc + OpenGL/X11 development libraries

## 🎯 Features

All platforms get:
- ✅ Native GUI (no browser)
- ✅ No terminal/console window
- ✅ Camera discovery via ONVIF WS-Discovery
- ✅ RTSP stream retrieval with credentials
- ✅ Beautiful native interface
- ✅ Copy-to-clipboard for RTSP URLs

## 🚀 Quick Start

After building:

1. Launch the application
2. Click "Scan for Cameras"
3. Enter credentials for each camera
4. Click "Get RTSP Streams"
5. Copy RTSP URLs

## 📝 Project Structure

```
onvif-discover/
├── main.go              # Core ONVIF logic + entry point
├── gui.go               # Fyne GUI implementation
├── go.mod               # Go dependencies
├── go.sum               # Dependency checksums
├── BUILD.md             # This file
└── ONVIF Camera Discovery.app/  # macOS bundle (pre-built)
```

## 🔧 Troubleshooting

### macOS: "App can't be opened"
```bash
xattr -cr "ONVIF Camera Discovery.app"
```

### Windows: Console window appears
Make sure you used `-H=windowsgui` flag during build.

### Linux: Missing libraries
Install OpenGL and X11 development packages for your distribution.

## 📄 License

MIT License
