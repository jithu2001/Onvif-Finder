# ONVIF Camera Discovery Tool

A production-ready cross-platform application for discovering ONVIF IP cameras and retrieving RTSP stream URLs.

## Features

- 🔍 **WS-Discovery** - Automatic camera detection via multicast
- 🔐 **ONVIF Authentication** - Secure WS-Security authentication
- 📹 **Stream Details** - Resolution, FPS, bitrate, encoding info
- 🖥️ **Multiple Interfaces** - CLI, Web UI, and Desktop app
- 🌍 **Cross-Platform** - Windows, macOS, and Linux support

## Download & Installation

### Pre-built Binaries

**Windows:**
```bash
onvif-discover.exe desktop
```

**macOS:**
```bash
./onvif-discover-macos desktop
# Or native GUI version:
./onvif-discover-macos-gui gui
```

**Linux:**
```bash
./onvif-discover-linux desktop
```

## Usage

### 1. Desktop App (Recommended)

Automatically opens your browser with a beautiful UI:

```bash
# Windows
onvif-discover.exe desktop

# macOS/Linux
./onvif-discover-macos desktop
./onvif-discover-linux desktop
```

### 2. Native GUI (macOS only)

Native desktop application using Fyne:

```bash
./onvif-discover-macos-gui gui
```

### 3. Web UI

Start web server manually:

```bash
onvif-discover ui --port 8080
# Then open http://localhost:8080
```

### 4. Command Line Interface

**Discover cameras:**
```bash
onvif-discover discover --timeout 10
```

**Get streams from specific camera:**
```bash
onvif-discover get-streams http://192.168.1.150/onvif/device_service admin password123
```

## How It Works

### Step 1: Discovery
- Sends WS-Discovery multicast probe to `239.255.255.250:3702`
- Cameras respond with their IP and ONVIF service URL
- No credentials needed for discovery

### Step 2: Authentication
- Uses ONVIF service URL from discovery
- Authenticates with WS-Security (SHA1 digest)
- Retrieves media profiles and stream URIs

### Step 3: Stream Details
- Resolution (width x height)
- Frame rate (FPS)
- Bitrate (kbps)
- Encoding (H264, H265, etc.)
- Clean RTSP URLs (credentials removed)

## Screenshots

### Desktop App
![Desktop App](screenshot.png)

The UI provides:
- Camera scanning with configurable timeout
- Camera cards showing IP and service URL
- Credential input per camera
- One-click RTSP stream retrieval
- Copy-to-clipboard for RTSP URLs

## Requirements

- Cameras must be on the same subnet (WS-Discovery is link-local)
- Multicast must be enabled on cameras
- Firewall must allow UDP traffic on port 3702

## Troubleshooting

**No cameras found:**
1. Ensure cameras are on the same subnet
2. Enable "Multicast Discovery" in camera settings
3. Check firewall allows multicast (239.255.255.250:3702)
4. Try increasing timeout to 15-30 seconds

**Authentication failed:**
1. Verify username/password are correct
2. Check camera supports ONVIF profile
3. Enable ONVIF in camera settings

## Environment Variables

```bash
VERBOSE=1   # Enable verbose logging
DEBUG=1     # Enable debug mode
```

## Building from Source

```bash
# Clone repository
git clone <repo-url>
cd onvif-discover

# Install dependencies
go mod download

# Build for your platform
go build -o onvif-discover

# Build for all platforms
GOOS=windows GOARCH=amd64 go build -o onvif-discover.exe
GOOS=linux GOARCH=amd64 go build -o onvif-discover-linux
GOOS=darwin GOARCH=amd64 go build -o onvif-discover-macos

# Build macOS native GUI
go build -tags gui -o onvif-discover-macos-gui
```

## Architecture

- **Go** - Backend and CLI
- **ONVIF/SOAP** - Camera communication
- **WS-Discovery** - Camera detection protocol
- **HTML/CSS/JS** - Web UI (embedded)
- **Fyne** - Native GUI framework (optional)

## Version

v1.0.0

## License

MIT License
