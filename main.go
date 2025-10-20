package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	Version            = "1.0.0"
	DefaultTimeout     = 5
	DefaultHTTPTimeout = 10
	MaxRetries         = 3
	RetryDelay         = 1 * time.Second
)

// StreamConfig represents a single RTSP stream configuration
type StreamConfig struct {
	Name     string `json:"name"`
	RTSPURL  string `json:"rtsp_url"`
	Height   int    `json:"height"`
	Width    int    `json:"width"`
	FPS      int    `json:"fps"`
	Bitrate  int    `json:"bitrate"`
	Encoding string `json:"encoding"`
}

// Camera represents a discovered ONVIF camera
type Camera struct {
	IP         string `json:"ip"`
	ServiceURL string `json:"service_url"`
}

// ONVIF XML structures
type MediaProfile struct {
	Token                     string                    `xml:"token,attr"`
	Name                      string                    `xml:"Name"`
	VideoEncoderConfiguration VideoEncoderConfiguration `xml:"VideoEncoderConfiguration"`
}

type VideoEncoderConfiguration struct {
	Encoding    string          `xml:"Encoding"`
	Resolution  VideoResolution `xml:"Resolution"`
	RateControl RateControl     `xml:"RateControl"`
}

type VideoResolution struct {
	Width  int `xml:"Width"`
	Height int `xml:"Height"`
}

type RateControl struct {
	FrameRateLimit int `xml:"FrameRateLimit"`
	BitrateLimit   int `xml:"BitrateLimit"`
}

type GetProfilesResponse struct {
	XMLName  xml.Name       `xml:"GetProfilesResponse"`
	Profiles []MediaProfile `xml:"Profiles"`
}

type GetStreamUriResponse struct {
	XMLName  xml.Name `xml:"GetStreamUriResponse"`
	MediaUri struct {
		URI string `xml:"Uri"`
	} `xml:"MediaUri"`
}

type ONVIFEnvelope struct {
	XMLName xml.Name  `xml:"Envelope"`
	Body    ONVIFBody `xml:"Body"`
}

type ONVIFBody struct {
	GetProfilesResponse  GetProfilesResponse  `xml:"GetProfilesResponse"`
	GetStreamUriResponse GetStreamUriResponse `xml:"GetStreamUriResponse"`
}

// Logger wraps standard logger with levels
type Logger struct {
	verbose bool
}

func NewLogger(verbose bool) *Logger {
	return &Logger{verbose: verbose}
}

func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}

var logger *Logger

func main() {
	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, cleaning up...")
		cancel()
		os.Exit(0)
	}()

	// Initialize logger
	verbose := os.Getenv("VERBOSE") == "1" || os.Getenv("DEBUG") == "1"
	logger = NewLogger(verbose)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "discover":
		timeout := DefaultTimeout
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--timeout" && i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &timeout)
				i++
			}
		}
		if err := discoverCameras(ctx, timeout); err != nil {
			logger.Error("Discovery failed: %v", err)
			os.Exit(1)
		}

	case "get-streams":
		if len(os.Args) != 5 {
			logger.Error("Invalid arguments for get-streams")
			fmt.Println("Usage: onvif-discover get-streams <service_url> <username> <password>")
			os.Exit(1)
		}
		serviceURL := os.Args[2]
		username := os.Args[3]
		password := os.Args[4]
		if err := getStreams(ctx, serviceURL, username, password); err != nil {
			logger.Error("Failed to get streams: %v", err)
			os.Exit(1)
		}

	case "version", "--version", "-v":
		fmt.Printf("ONVIF Discovery Tool v%s\n", Version)
		os.Exit(0)

	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)

	case "desktop", "app":
		startDesktopApp()

	case "gui":
		startGUI()

	case "ui":
		port := "8080"
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--port" && i+1 < len(os.Args) {
				port = os.Args[i+1]
				i++
			}
		}
		if err := startWebUI(ctx, port); err != nil {
			logger.Error("Failed to start web UI: %v", err)
			os.Exit(1)
		}

	default:
		logger.Error("Unknown command: %s", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("ONVIF Camera Discovery Tool v%s\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  discover [--timeout seconds]             Discover cameras via WS-Discovery (CLI)")
	fmt.Println("  get-streams <url> <user> <pass>         Get streams from camera (CLI)")
	fmt.Println("  desktop                                  Start desktop app (auto-opens browser)")
	fmt.Println("  gui                                      Start native GUI app (Fyne - macOS only)")
	fmt.Println("  ui [--port port]                        Start web UI server (default port: 8080)")
	fmt.Println("  version                                  Show version")
	fmt.Println("  help                                     Show this help")
	fmt.Println("\nExamples:")
	fmt.Println("  onvif-discover discover --timeout 10")
	fmt.Println("  onvif-discover get-streams http://192.168.1.150/onvif/device_service admin password")
	fmt.Println("  onvif-discover desktop           # Recommended for desktop use")
	fmt.Println("  onvif-discover gui               # macOS native app")
	fmt.Println("  onvif-discover ui --port 3000    # Web server only")
	fmt.Println("\nEnvironment Variables:")
	fmt.Println("  VERBOSE=1                               Enable verbose logging")
	fmt.Println("  DEBUG=1                                 Enable debug mode")
}

func discoverCameras(ctx context.Context, timeoutSec int) error {
	logger.Info("Starting ONVIF WS-Discovery (timeout: %ds)", timeoutSec)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	conn.SetReadDeadline(deadline)

	multicastAddr := &net.UDPAddr{
		IP:   net.IPv4(239, 255, 255, 250),
		Port: 3702,
	}

	probeMessage := createWSDiscoveryProbe()
	sentBytes, err := conn.WriteToUDP([]byte(probeMessage), multicastAddr)
	if err != nil {
		return fmt.Errorf("failed to send probe: %w", err)
	}

	logger.Debug("Sent %d bytes to %s", sentBytes, multicastAddr.String())
	logger.Info("Probe sent, listening for responses...")

	discoveredCameras := make(map[string]*Camera)
	buffer := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			logger.Debug("Read error: %v", err)
			break
		}

		response := string(buffer[:n])
		logger.Debug("Received %d bytes from %s", n, addr.IP.String())

		camera, err := parseWSDiscoveryResponse(response, addr.IP.String())
		if err != nil {
			logger.Debug("Failed to parse response from %s: %v", addr.IP.String(), err)
			continue
		}

		if camera != nil {
			if _, exists := discoveredCameras[camera.IP]; !exists {
				discoveredCameras[camera.IP] = camera
				logger.Info("✓ Found: %s (%s)", camera.IP, camera.ServiceURL)
			}
		}
	}

	cameras := make([]Camera, 0, len(discoveredCameras))
	for _, cam := range discoveredCameras {
		cameras = append(cameras, *cam)
	}

	logger.Info("\n========== DISCOVERED %d CAMERA(S) ==========", len(cameras))

	if len(cameras) == 0 {
		fmt.Println("\nNo cameras found. Troubleshooting:")
		fmt.Println("  - Ensure cameras are on the same subnet (WS-Discovery is link-local)")
		fmt.Println("  - Enable 'Multicast Discovery' on cameras")
		fmt.Println("  - Check firewall allows multicast traffic (239.255.255.250:3702)")
		fmt.Println("  - Try increasing timeout: --timeout 15")
		return nil
	}

	jsonData, err := json.MarshalIndent(cameras, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

func getStreams(ctx context.Context, serviceURL, username, password string) error {
	logger.Info("Getting streams from %s", serviceURL)

	// Validate service URL
	if !strings.HasPrefix(serviceURL, "http://") && !strings.HasPrefix(serviceURL, "https://") {
		return errors.New("invalid service URL: must start with http:// or https://")
	}

	streams, err := getStreamsFromService(ctx, serviceURL, username, password)
	if err != nil {
		return fmt.Errorf("failed to get streams: %w", err)
	}

	if len(streams) == 0 {
		return errors.New("no valid streams found")
	}

	logger.Info("Successfully retrieved %d stream(s)", len(streams))

	jsonData, err := json.MarshalIndent(streams, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

func getStreamsFromService(ctx context.Context, serviceURL, username, password string) ([]StreamConfig, error) {
	profiles, err := getMediaProfiles(ctx, serviceURL, username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get media profiles: %w", err)
	}

	logger.Debug("Retrieved %d profile(s)", len(profiles))

	var streams []StreamConfig
	for i, profile := range profiles {
		logger.Debug("Processing profile %d: %s (token: %s)", i+1, profile.Name, profile.Token)

		rtspURL, err := getStreamURI(ctx, serviceURL, profile.Token, username, password)
		if err != nil {
			logger.Debug("Failed to get stream URI for profile %s: %v", profile.Token, err)
			continue
		}

		// Clean URL
		rtspURL = strings.ReplaceAll(rtspURL, "&amp;", "&")
		rtspURL = removeCredentialsFromURL(rtspURL)

		// Determine stream name
		streamName := determineStreamName(profile.Name, i)

		encoding := profile.VideoEncoderConfiguration.Encoding
		if encoding == "" {
			encoding = "H264"
		}

		stream := StreamConfig{
			Name:     streamName,
			RTSPURL:  rtspURL,
			Height:   profile.VideoEncoderConfiguration.Resolution.Height,
			Width:    profile.VideoEncoderConfiguration.Resolution.Width,
			FPS:      profile.VideoEncoderConfiguration.RateControl.FrameRateLimit,
			Bitrate:  profile.VideoEncoderConfiguration.RateControl.BitrateLimit,
			Encoding: encoding,
		}

		// Only add valid streams
		if stream.Height > 0 && stream.Width > 0 {
			streams = append(streams, stream)
			logger.Debug("Added stream: %s (%dx%d @ %d fps)", stream.Name, stream.Width, stream.Height, stream.FPS)
		} else {
			logger.Debug("Skipped invalid stream: %s (resolution: %dx%d)", profile.Name, stream.Width, stream.Height)
		}
	}

	return streams, nil
}

func determineStreamName(profileName string, index int) string {
	profileLower := strings.ToLower(profileName)

	if strings.Contains(profileLower, "main") || index == 0 {
		return "mainStream"
	}
	if strings.Contains(profileLower, "sub") || index == 1 {
		return "subStream"
	}
	return fmt.Sprintf("stream%d", index+1)
}

func createWSDiscoveryProbe() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>uuid:` + generateUUID() + `</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>tds:Device</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>`
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		logger.Error("Failed to generate UUID: %v", err)
		return "00000000-0000-0000-0000-000000000000"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func parseWSDiscoveryResponse(response, ip string) (*Camera, error) {
	if !strings.Contains(response, "NetworkVideoTransmitter") &&
		!strings.Contains(response, "onvif") &&
		!strings.Contains(response, "ONVIF") &&
		!strings.Contains(response, "tds:Device") {
		return nil, errors.New("not an ONVIF device")
	}

	serviceURL, err := extractServiceURL(response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract service URL: %w", err)
	}

	return &Camera{
		IP:         ip,
		ServiceURL: serviceURL,
	}, nil
}

func extractServiceURL(response string) (string, error) {
	var serviceURL string

	if strings.Contains(response, "<wsa:XAddrs>") || strings.Contains(response, "<d:XAddrs>") {
		start := strings.Index(response, "<wsa:XAddrs>")
		if start == -1 {
			start = strings.Index(response, "<d:XAddrs>")
		}

		if start != -1 {
			tagEnd := strings.Index(response[start:], ">")
			end := strings.Index(response[start:], "</")
			if tagEnd != -1 && end != -1 {
				urlPart := response[start+tagEnd+1 : start+end]
				urls := strings.Fields(urlPart)
				if len(urls) > 0 {
					serviceURL = strings.TrimSpace(urls[0])
				}
			}
		}
	}

	if serviceURL == "" {
		return "", errors.New("no XAddrs found in response")
	}

	return serviceURL, nil
}

func getMediaProfiles(ctx context.Context, serviceURL, username, password string) ([]MediaProfile, error) {
	mediaServiceURL := buildMediaServiceURL(serviceURL)

	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Body>
		<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>`

	resp, err := sendONVIFRequestWithAuth(ctx, mediaServiceURL, soapRequest, username, password)
	if err != nil {
		return nil, err
	}

	var envelope ONVIFEnvelope
	if err := xml.Unmarshal(resp, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse GetProfiles response: %w", err)
	}

	return envelope.Body.GetProfilesResponse.Profiles, nil
}

func getStreamURI(ctx context.Context, serviceURL, profileToken, username, password string) (string, error) {
	mediaServiceURL := buildMediaServiceURL(serviceURL)

	soapRequest := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Body>
		<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
			<StreamSetup>
				<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
				<Transport xmlns="http://www.onvif.org/ver10/schema">
					<Protocol>RTSP</Protocol>
				</Transport>
			</StreamSetup>
			<ProfileToken>%s</ProfileToken>
		</GetStreamUri>
	</s:Body>
</s:Envelope>`, profileToken)

	resp, err := sendONVIFRequestWithAuth(ctx, mediaServiceURL, soapRequest, username, password)
	if err != nil {
		return "", err
	}

	var envelope ONVIFEnvelope
	if err := xml.Unmarshal(resp, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse GetStreamUri response: %w", err)
	}

	return envelope.Body.GetStreamUriResponse.MediaUri.URI, nil
}

func buildMediaServiceURL(serviceURL string) string {
	mediaServiceURL := strings.Replace(serviceURL, "/onvif/device_service", "/onvif/Media", -1)
	if mediaServiceURL == serviceURL {
		mediaServiceURL = strings.Replace(serviceURL, "/onvif/device", "/onvif/Media", -1)
	}
	return mediaServiceURL
}

func sendONVIFRequestWithAuth(ctx context.Context, serviceURL, soapBody, username, password string) ([]byte, error) {
	soapWithAuth := addWSSecurityHeader(soapBody, username, password)

	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		logger.Debug("Attempt %d/%d: Sending ONVIF request to %s", attempt, MaxRetries, serviceURL)

		client := &http.Client{
			Timeout: time.Duration(DefaultHTTPTimeout) * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, "POST", serviceURL, strings.NewReader(soapWithAuth))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < MaxRetries {
				logger.Debug("Request failed, retrying in %v: %v", RetryDelay, err)
				time.Sleep(RetryDelay)
				continue
			}
			return nil, fmt.Errorf("request failed after %d attempts: %w", MaxRetries, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			logger.Debug("HTTP error %d: %s", resp.StatusCode, string(body))
			return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		logger.Debug("Successfully received %d bytes", len(body))
		return body, nil
	}

	return nil, lastErr
}

func addWSSecurityHeader(soapBody, username, password string) string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	created := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	hash := sha1.New()
	hash.Write(nonce)
	hash.Write([]byte(created))
	hash.Write([]byte(password))
	passwordDigest := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	securityHeader := fmt.Sprintf(`
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			<UsernameToken>
				<Username>%s</Username>
				<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%s</Password>
				<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</Nonce>
				<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%s</Created>
			</UsernameToken>
		</Security>
	</s:Header>`, username, passwordDigest, nonceB64, created)

	bodyIndex := strings.Index(soapBody, "<s:Body")
	if bodyIndex == -1 {
		bodyIndex = strings.Index(soapBody, "<Body")
	}

	if bodyIndex != -1 {
		return soapBody[:bodyIndex] + securityHeader + soapBody[bodyIndex:]
	}

	return soapBody
}

func removeCredentialsFromURL(rtspURL string) string {
	if !strings.HasPrefix(rtspURL, "rtsp://") {
		return rtspURL
	}

	lastAtIndex := strings.LastIndex(rtspURL, "@")
	if lastAtIndex == -1 {
		return rtspURL
	}

	return "rtsp://" + rtspURL[lastAtIndex+1:]
}

// Web UI Server
func startWebUI(ctx context.Context, port string) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/discover", handleDiscoverAPI)
	mux.HandleFunc("/api/streams", handleStreamsAPI)

	// Serve UI
	mux.HandleFunc("/", handleIndex)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	logger.Info("Starting web UI on http://localhost:%s", port)
	fmt.Printf("\n🌐 ONVIF Camera Discovery UI\n")
	fmt.Printf("   Open in browser: http://localhost:%s\n\n", port)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func handleDiscoverAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Timeout int `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Timeout == 0 {
		req.Timeout = DefaultTimeout
	}

	// Capture discovered cameras
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout+2)*time.Second)
	defer cancel()

	cameras, err := discoverCamerasForAPI(ctx, req.Timeout)
	if err != nil {
		logger.Error("Discovery failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"cameras": cameras,
		"count":   len(cameras),
	})
}

func handleStreamsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServiceURL string `json:"service_url"`
		Username   string `json:"username"`
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.ServiceURL == "" {
		http.Error(w, "service_url is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(DefaultHTTPTimeout+5)*time.Second)
	defer cancel()

	streams, err := getStreamsFromService(ctx, req.ServiceURL, req.Username, req.Password)
	if err != nil {
		logger.Error("Failed to get streams: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"streams": streams,
		"count":   len(streams),
	})
}

func discoverCamerasForAPI(ctx context.Context, timeoutSec int) ([]Camera, error) {
	logger.Info("Starting ONVIF WS-Discovery (timeout: %ds)", timeoutSec)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	conn.SetReadDeadline(deadline)

	multicastAddr := &net.UDPAddr{
		IP:   net.IPv4(239, 255, 255, 250),
		Port: 3702,
	}

	probeMessage := createWSDiscoveryProbe()
	_, err = conn.WriteToUDP([]byte(probeMessage), multicastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send probe: %w", err)
	}

	logger.Debug("Probe sent, listening for responses...")

	discoveredCameras := make(map[string]*Camera)
	buffer := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			break
		default:
		}

		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}

		response := string(buffer[:n])
		logger.Debug("Received %d bytes from %s", n, addr.IP.String())

		camera, err := parseWSDiscoveryResponse(response, addr.IP.String())
		if err != nil {
			logger.Debug("Failed to parse response from %s: %v", addr.IP.String(), err)
			continue
		}

		if camera != nil {
			if _, exists := discoveredCameras[camera.IP]; !exists {
				discoveredCameras[camera.IP] = camera
				logger.Info("✓ Found: %s (%s)", camera.IP, camera.ServiceURL)
			}
		}
	}

	cameras := make([]Camera, 0, len(discoveredCameras))
	for _, cam := range discoveredCameras {
		cameras = append(cameras, *cam)
	}

	return cameras, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(getHTMLContent()))
}

func getHTMLContent() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ONVIF Camera Discovery</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
        }

        .scan-section {
            display: flex;
            gap: 15px;
            align-items: flex-end;
            margin-bottom: 20px;
        }

        .form-group {
            flex: 1;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        input[type="number"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }

        input[type="number"]:focus {
            outline: none;
            border-color: #667eea;
        }

        button {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        button:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }

        .status {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }

        .status.info {
            background: #e3f2fd;
            color: #1976d2;
            border-left: 4px solid #1976d2;
        }

        .status.success {
            background: #e8f5e9;
            color: #388e3c;
            border-left: 4px solid #388e3c;
        }

        .status.error {
            background: #ffebee;
            color: #c62828;
            border-left: 4px solid #c62828;
        }

        .cameras-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .camera-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border: 2px solid #e0e0e0;
            transition: all 0.3s;
        }

        .camera-card:hover {
            border-color: #667eea;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .camera-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e0e0e0;
        }

        .camera-icon {
            width: 40px;
            height: 40px;
            background: #667eea;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.2em;
        }

        .camera-info {
            flex: 1;
        }

        .camera-ip {
            font-size: 1.1em;
            font-weight: 700;
            color: #333;
        }

        .camera-url {
            font-size: 0.85em;
            color: #666;
            word-break: break-all;
            margin-top: 5px;
        }

        .credentials-form {
            display: grid;
            gap: 12px;
            margin-bottom: 15px;
        }

        .credentials-form input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 0.95em;
        }

        .credentials-form input:focus {
            outline: none;
            border-color: #667eea;
        }

        .get-streams-btn {
            width: 100%;
            padding: 10px;
            background: #764ba2;
            margin-bottom: 10px;
        }

        .get-streams-btn:hover {
            background: #653a8e;
        }

        .streams-list {
            margin-top: 15px;
            display: none;
        }

        .stream-item {
            background: white;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }

        .stream-name {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 5px;
        }

        .stream-details {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
        }

        .stream-url {
            background: #f5f5f5;
            padding: 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8em;
            word-break: break-all;
            margin-top: 8px;
        }

        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }

        .empty-state svg {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📹 ONVIF Camera Discovery</h1>
            <p>Scan your network for ONVIF cameras and retrieve RTSP stream details</p>
        </div>

        <div class="card">
            <div class="scan-section">
                <div class="form-group">
                    <label for="timeout">Scan Timeout (seconds)</label>
                    <input type="number" id="timeout" value="5" min="1" max="30">
                </div>
                <button id="scanBtn" onclick="scanCameras()">
                    <span id="scanBtnText">Scan for Cameras</span>
                </button>
            </div>

            <div id="status" class="status"></div>

            <div id="camerasContainer"></div>
        </div>
    </div>

    <script>
        let cameras = [];

        function showStatus(message, type = 'info') {
            const statusEl = document.getElementById('status');
            statusEl.textContent = message;
            statusEl.className = 'status ' + type;
            statusEl.style.display = 'block';
        }

        function hideStatus() {
            document.getElementById('status').style.display = 'none';
        }

        async function scanCameras() {
            const timeout = parseInt(document.getElementById('timeout').value);
            const scanBtn = document.getElementById('scanBtn');
            const scanBtnText = document.getElementById('scanBtnText');

            scanBtn.disabled = true;
            scanBtnText.innerHTML = '<span class="spinner"></span> Scanning...';
            showStatus('Scanning network for ONVIF cameras...', 'info');

            document.getElementById('camerasContainer').innerHTML = '';

            try {
                const response = await fetch('/api/discover', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ timeout })
                });

                const data = await response.json();

                if (data.success) {
                    cameras = data.cameras || [];
                    showStatus('Found ' + cameras.length + ' camera(s)', 'success');
                    renderCameras();
                } else {
                    showStatus('Discovery failed', 'error');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
            } finally {
                scanBtn.disabled = false;
                scanBtnText.textContent = 'Scan for Cameras';
            }
        }

        function renderCameras() {
            const container = document.getElementById('camerasContainer');

            if (cameras.length === 0) {
                container.innerHTML = '<div class="empty-state">' +
                    '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
                    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" ' +
                    'd="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/>' +
                    '</svg>' +
                    '<h3>No cameras found</h3>' +
                    '<p>Try increasing the timeout or ensure cameras are on the same network</p>' +
                    '</div>';
                return;
            }

            let html = '<div class="cameras-grid">';
            cameras.forEach((camera, index) => {
                html += '<div class="camera-card" id="camera-' + index + '">' +
                    '<div class="camera-header">' +
                    '<div class="camera-icon">📹</div>' +
                    '<div class="camera-info">' +
                    '<div class="camera-ip">' + camera.ip + '</div>' +
                    '<div class="camera-url">' + camera.service_url + '</div>' +
                    '</div></div>' +
                    '<div class="credentials-form">' +
                    '<input type="text" id="username-' + index + '" placeholder="Username (e.g., admin)" value="admin">' +
                    '<input type="password" id="password-' + index + '" placeholder="Password">' +
                    '</div>' +
                    '<button class="get-streams-btn" onclick="getStreams(' + index + ')">' +
                    '<span id="stream-btn-' + index + '">Get RTSP Streams</span>' +
                    '</button>' +
                    '<div id="streams-' + index + '" class="streams-list"></div>' +
                    '</div>';
            });
            html += '</div>';
            container.innerHTML = html;
        }

        async function getStreams(index) {
            const camera = cameras[index];
            const username = document.getElementById('username-' + index).value;
            const password = document.getElementById('password-' + index).value;
            const btnEl = document.getElementById('stream-btn-' + index);
            const streamsEl = document.getElementById('streams-' + index);

            btnEl.innerHTML = '<span class="spinner"></span> Loading...';
            streamsEl.style.display = 'none';

            try {
                const response = await fetch('/api/streams', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        service_url: camera.service_url,
                        username,
                        password
                    })
                });

                const data = await response.json();

                if (data.success && data.streams) {
                    renderStreams(index, data.streams);
                } else {
                    streamsEl.innerHTML = '<div class="stream-item" style="border-left-color: #c62828; color: #c62828;">Failed to retrieve streams. Check credentials.</div>';
                    streamsEl.style.display = 'block';
                }
            } catch (error) {
                streamsEl.innerHTML = '<div class="stream-item" style="border-left-color: #c62828; color: #c62828;">Error: ' + error.message + '</div>';
                streamsEl.style.display = 'block';
            } finally {
                btnEl.textContent = 'Get RTSP Streams';
            }
        }

        function renderStreams(cameraIndex, streams) {
            const streamsEl = document.getElementById('streams-' + cameraIndex);

            if (streams.length === 0) {
                streamsEl.innerHTML = '<div class="stream-item">No streams available</div>';
            } else {
                let html = '';
                streams.forEach(stream => {
                    html += '<div class="stream-item">' +
                        '<div class="stream-name">' + stream.name + '</div>' +
                        '<div class="stream-details">' +
                        '📐 ' + stream.width + 'x' + stream.height + ' | ' +
                        '🎞️ ' + stream.fps + ' fps | ' +
                        '💾 ' + (stream.bitrate / 1000).toFixed(0) + ' kbps | ' +
                        '🎬 ' + stream.encoding +
                        '</div>' +
                        '<div class="stream-url">' +
                        '<strong>RTSP URL:</strong><br>' +
                        stream.rtsp_url +
                        '</div>' +
                        '</div>';
                });
                streamsEl.innerHTML = html;
            }

            streamsEl.style.display = 'block';
        }

        // Auto-scan on load if desired
        // window.addEventListener('load', () => setTimeout(scanCameras, 500));
    </script>
</body>
</html>`
}
