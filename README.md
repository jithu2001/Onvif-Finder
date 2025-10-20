# ONVIF Camera Discovery

A native cross-platform desktop application for discovering ONVIF IP cameras and retrieving RTSP stream URLs.

**Pure native GUI - No web browser, no terminal window.**

## ✨ Features

- 🖥️ **Native Desktop App** - Pure GUI application (Fyne framework)
- 🔍 **Auto Discovery** - WS-Discovery multicast protocol
- 🔐 **Secure Authentication** - WS-Security with SHA1 digest
- 📹 **Complete Stream Info** - Resolution, FPS, bitrate, encoding
- 📋 **Copy to Clipboard** - One-click RTSP URL copying
- 🎨 **Beautiful UI** - Modern native interface
- 🌍 **Cross-Platform** - Windows, macOS, and Linux

## 🚀 Quick Start

### macOS (Ready to Use!)

Simply double-click:
```
ONVIF Camera Discovery.app
```

No installation needed! The app is already built and packaged.

### Windows & Linux

See [BUILD.md](BUILD.md) for build instructions on your platform.

## 📸 Usage

1. **Launch** the app (double-click on macOS)
2. **Scan** - Set timeout and click "Scan for Cameras"
3. **Authenticate** - Enter username/password for each camera
4. **Get Streams** - Click "Get RTSP Streams"
5. **Copy** - Click copy icon to copy RTSP URL to clipboard

## 🎯 How It Works

### Discovery Phase
- Sends WS-Discovery probe to multicast address `239.255.255.250:3702`
- Cameras respond with their IP and ONVIF service URL
- No credentials required for discovery
- Shows all cameras on the same subnet

### Stream Retrieval
- Authenticates with WS-Security (SHA1 password digest)
- Calls ONVIF `GetProfiles` to list media profiles
- Calls ONVIF `GetStreamUri` for each profile
- Parses and displays:
  - Resolution (e.g., 1920x1080)
  - Frame rate (e.g., 25 fps)
  - Bitrate (e.g., 4096 kbps)
  - Encoding (H264, H265, MJPEG)
  - Clean RTSP URL (credentials removed)

## 📋 Requirements

### For End Users
- macOS 10.13+ (High Sierra or later)
- Windows 7, 8, 10, 11 (64-bit)
- Linux (most distributions with X11)

### Network Requirements
- Cameras must be on same subnet
- Multicast must be enabled on cameras
- Firewall must allow UDP port 3702

## 🔧 Troubleshooting

### No cameras found?

1. **Check subnet** - Cameras must be on same network
2. **Enable multicast** - In camera settings, enable "ONVIF" or "Multicast Discovery"
3. **Firewall** - Allow UDP traffic on port 3702
4. **Increase timeout** - Try 15-30 seconds for larger networks

### Authentication failed?

1. **Verify credentials** - Double-check username/password
2. **Check ONVIF support** - Camera must support ONVIF profile S or higher
3. **Enable ONVIF** - Some cameras require ONVIF to be explicitly enabled

### macOS: "App can't be opened"?

```bash
xattr -cr "ONVIF Camera Discovery.app"
```

## 🏗️ Technical Details

**Built with:**
- Go 1.21+
- Fyne v2.7.0 (native UI framework)
- Pure Go ONVIF implementation
- No external dependencies for end users

**Protocols:**
- WS-Discovery (SOAP over UDP multicast)
- ONVIF Device Management
- ONVIF Media Service
- WS-Security authentication

**Binary Size:**
- macOS: ~30 MB (includes all frameworks)
- Windows: ~25-30 MB
- Linux: ~30 MB

## 📝 Version

**v1.0.0** - Native GUI Release

## 🔨 Building

See [BUILD.md](BUILD.md) for detailed build instructions for each platform.

## 📄 License

MIT License

---

**Made with ❤️ for IP camera enthusiasts**
