package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// ONVIF PROTOCOL IMPLEMENTATION
// ============================================================================

// Constants for ONVIF operations
const (
	ONVIFMulticastAddress = "239.255.255.250"
	ONVIFMulticastPort    = 3702
	DefaultHTTPTimeout    = 10
	MaxRetries            = 3
	RetryDelay            = 1 * time.Second
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Camera represents a discovered ONVIF camera
type Camera struct {
	IP         string `json:"ip"`
	ServiceURL string `json:"service_url"`
}

// StreamConfig represents RTSP stream configuration
type StreamConfig struct {
	Name     string `json:"name"`
	RTSPURL  string `json:"rtsp_url"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	FPS      int    `json:"fps"`
	Bitrate  int    `json:"bitrate"`
	Encoding string `json:"encoding"`
}

// MediaProfile represents an ONVIF media profile
type MediaProfile struct {
	Token                     string                    `xml:"token,attr"`
	Name                      string                    `xml:"Name"`
	VideoEncoderConfiguration VideoEncoderConfiguration `xml:"VideoEncoderConfiguration"`
}

// VideoEncoderConfiguration contains video encoding settings
type VideoEncoderConfiguration struct {
	Encoding    string          `xml:"Encoding"`
	Resolution  VideoResolution `xml:"Resolution"`
	RateControl RateControl     `xml:"RateControl"`
}

// VideoResolution contains video dimensions
type VideoResolution struct {
	Width  int `xml:"Width"`
	Height int `xml:"Height"`
}

// RateControl contains frame rate and bitrate settings
type RateControl struct {
	FrameRateLimit int `xml:"FrameRateLimit"`
	BitrateLimit   int `xml:"BitrateLimit"`
}

// ONVIF SOAP response structures
type ONVIFEnvelope struct {
	XMLName xml.Name  `xml:"Envelope"`
	Body    ONVIFBody `xml:"Body"`
}

type ONVIFBody struct {
	GetProfilesResponse  GetProfilesResponse  `xml:"GetProfilesResponse"`
	GetStreamUriResponse GetStreamUriResponse `xml:"GetStreamUriResponse"`
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

// ============================================================================
// WS-DISCOVERY (CAMERA DISCOVERY)
// ============================================================================

// DiscoverCameras discovers ONVIF cameras on the network using WS-Discovery
func DiscoverCameras(ctx context.Context, timeoutSec int) ([]Camera, error) {
	logger.Info("Starting WS-Discovery (timeout: %ds)", timeoutSec)

	// Create UDP socket for multicast
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	conn.SetReadDeadline(deadline)

	// Multicast address for WS-Discovery
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(ONVIFMulticastAddress),
		Port: ONVIFMulticastPort,
	}

	// Send WS-Discovery probe
	probeMessage := createWSDiscoveryProbe()
	_, err = conn.WriteToUDP([]byte(probeMessage), multicastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send probe: %w", err)
	}

	logger.Debug("Probe sent to %s:%d", ONVIFMulticastAddress, ONVIFMulticastPort)

	// Collect responses
	discoveredCameras := make(map[string]*Camera)
	buffer := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return collectCameras(discoveredCameras), ctx.Err()
		default:
		}

		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}

		// Parse response
		response := string(buffer[:n])
		camera, err := parseWSDiscoveryResponse(response, addr.IP.String())
		if err != nil {
			logger.Debug("Invalid response from %s: %v", addr.IP.String(), err)
			continue
		}

		// Add unique camera
		if _, exists := discoveredCameras[camera.IP]; !exists {
			discoveredCameras[camera.IP] = camera
			logger.Info("✓ Discovered: %s (%s)", camera.IP, camera.ServiceURL)
		}
	}

	return collectCameras(discoveredCameras), nil
}

// collectCameras converts map to slice
func collectCameras(cameraMap map[string]*Camera) []Camera {
	cameras := make([]Camera, 0, len(cameraMap))
	for _, cam := range cameraMap {
		cameras = append(cameras, *cam)
	}
	return cameras
}

// createWSDiscoveryProbe creates a WS-Discovery probe message
func createWSDiscoveryProbe() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>uuid:%s</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>tds:Device</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>`, generateUUID())
}

// parseWSDiscoveryResponse parses WS-Discovery response and extracts camera info
func parseWSDiscoveryResponse(response, ip string) (*Camera, error) {
	// Validate it's an ONVIF device
	if !isONVIFDevice(response) {
		return nil, errors.New("not an ONVIF device")
	}

	// Extract service URL
	serviceURL, err := extractServiceURL(response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract service URL: %w", err)
	}

	return &Camera{
		IP:         ip,
		ServiceURL: serviceURL,
	}, nil
}

// isONVIFDevice checks if response is from an ONVIF device
func isONVIFDevice(response string) bool {
	keywords := []string{"NetworkVideoTransmitter", "onvif", "ONVIF", "tds:Device"}
	for _, keyword := range keywords {
		if strings.Contains(response, keyword) {
			return true
		}
	}
	return false
}

// extractServiceURL extracts the service URL from WS-Discovery response
func extractServiceURL(response string) (string, error) {
	// Look for XAddrs tag
	tags := []string{"<wsa:XAddrs>", "<d:XAddrs>"}
	for _, tag := range tags {
		if idx := strings.Index(response, tag); idx != -1 {
			tagEnd := strings.Index(response[idx:], ">")
			endTag := strings.Index(response[idx:], "</")
			if tagEnd != -1 && endTag != -1 {
				urlPart := response[idx+tagEnd+1 : idx+endTag]
				urls := strings.Fields(urlPart)
				if len(urls) > 0 {
					return strings.TrimSpace(urls[0]), nil
				}
			}
		}
	}

	return "", errors.New("no service URL found in response")
}

// ============================================================================
// ONVIF MEDIA OPERATIONS
// ============================================================================

// GetStreams retrieves all RTSP streams from a camera
func GetStreams(ctx context.Context, serviceURL, username, password string) ([]StreamConfig, error) {
	// Validate input
	if serviceURL == "" {
		return nil, errors.New("service URL is required")
	}

	// Get media profiles
	profiles, err := getMediaProfiles(ctx, serviceURL, username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get media profiles: %w", err)
	}

	logger.Debug("Retrieved %d profile(s)", len(profiles))

	// Get stream URI for each profile
	streams := make([]StreamConfig, 0, len(profiles))
	for i, profile := range profiles {
		stream, err := getStreamFromProfile(ctx, serviceURL, profile, username, password, i)
		if err != nil {
			logger.Debug("Skipped profile %s: %v", profile.Token, err)
			continue
		}

		if stream != nil {
			streams = append(streams, *stream)
		}
	}

	return streams, nil
}

// getStreamFromProfile retrieves stream configuration from a profile
func getStreamFromProfile(ctx context.Context, serviceURL string, profile MediaProfile, username, password string, index int) (*StreamConfig, error) {
	logger.Debug("Processing profile: %s (token: %s)", profile.Name, profile.Token)

	// Get RTSP URL
	rtspURL, err := getStreamURI(ctx, serviceURL, profile.Token, username, password)
	if err != nil {
		return nil, err
	}

	// Clean URL
	rtspURL = strings.ReplaceAll(rtspURL, "&amp;", "&")
	rtspURL = removeCredentials(rtspURL)

	// Get stream name
	streamName := determineStreamName(profile.Name, index)

	// Get encoding (default to H264)
	encoding := profile.VideoEncoderConfiguration.Encoding
	if encoding == "" {
		encoding = "H264"
	}

	// Create stream configuration
	stream := &StreamConfig{
		Name:     streamName,
		RTSPURL:  rtspURL,
		Width:    profile.VideoEncoderConfiguration.Resolution.Width,
		Height:   profile.VideoEncoderConfiguration.Resolution.Height,
		FPS:      profile.VideoEncoderConfiguration.RateControl.FrameRateLimit,
		Bitrate:  profile.VideoEncoderConfiguration.RateControl.BitrateLimit,
		Encoding: encoding,
	}

	// Validate resolution
	if stream.Width <= 0 || stream.Height <= 0 {
		return nil, fmt.Errorf("invalid resolution: %dx%d", stream.Width, stream.Height)
	}

	logger.Debug("Added stream: %s (%dx%d @ %d fps)", stream.Name, stream.Width, stream.Height, stream.FPS)
	return stream, nil
}

// getMediaProfiles retrieves media profiles from camera
func getMediaProfiles(ctx context.Context, serviceURL, username, password string) ([]MediaProfile, error) {
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Body>
		<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>`

	resp, err := sendONVIFRequest(ctx, serviceURL, soapRequest, username, password)
	if err != nil {
		return nil, err
	}

	var envelope ONVIFEnvelope
	if err := xml.Unmarshal(resp, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return envelope.Body.GetProfilesResponse.Profiles, nil
}

// getStreamURI retrieves RTSP stream URI for a profile
func getStreamURI(ctx context.Context, serviceURL, profileToken, username, password string) (string, error) {
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

	resp, err := sendONVIFRequest(ctx, serviceURL, soapRequest, username, password)
	if err != nil {
		return "", err
	}

	var envelope ONVIFEnvelope
	if err := xml.Unmarshal(resp, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return envelope.Body.GetStreamUriResponse.MediaUri.URI, nil
}

// ============================================================================
// ONVIF SOAP COMMUNICATION
// ============================================================================

// sendONVIFRequest sends an authenticated ONVIF SOAP request
func sendONVIFRequest(ctx context.Context, serviceURL, soapBody, username, password string) ([]byte, error) {
	// Add WS-Security authentication
	authenticatedSOAP := addWSSecurityHeader(soapBody, username, password)

	// Retry logic
	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		logger.Debug("Attempt %d/%d: Sending request to %s", attempt, MaxRetries, serviceURL)

		// Send HTTP request
		resp, err := sendHTTPRequest(ctx, serviceURL, authenticatedSOAP)
		if err != nil {
			lastErr = err
			if attempt < MaxRetries {
				logger.Debug("Retrying in %v: %v", RetryDelay, err)
				time.Sleep(RetryDelay)
				continue
			}
			return nil, fmt.Errorf("request failed after %d attempts: %w", MaxRetries, err)
		}

		return resp, nil
	}

	return nil, lastErr
}

// sendHTTPRequest sends HTTP POST request
func sendHTTPRequest(ctx context.Context, url, body string) ([]byte, error) {
	client := &http.Client{
		Timeout: time.Duration(DefaultHTTPTimeout) * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	logger.Debug("Received %d bytes", len(responseBody))
	return responseBody, nil
}

// ============================================================================
// WS-SECURITY AUTHENTICATION
// ============================================================================

// addWSSecurityHeader adds WS-Security authentication header to SOAP request
func addWSSecurityHeader(soapBody, username, password string) string {
	// Generate nonce
	nonce := make([]byte, 16)
	rand.Read(nonce)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	// Generate timestamp
	created := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// Calculate password digest (SHA1 of nonce + timestamp + password)
	hash := sha1.New()
	hash.Write(nonce)
	hash.Write([]byte(created))
	hash.Write([]byte(password))
	passwordDigest := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	// Create security header
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

	// Insert header before Body tag
	bodyIndex := strings.Index(soapBody, "<s:Body")
	if bodyIndex == -1 {
		bodyIndex = strings.Index(soapBody, "<Body")
	}

	if bodyIndex != -1 {
		return soapBody[:bodyIndex] + securityHeader + soapBody[bodyIndex:]
	}

	return soapBody
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// determineStreamName determines a friendly name for the stream
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

// removeCredentials removes username:password from RTSP URL
func removeCredentials(rtspURL string) string {
	if !strings.HasPrefix(rtspURL, "rtsp://") {
		return rtspURL
	}

	// Find @ symbol that separates credentials from host
	lastAtIndex := strings.LastIndex(rtspURL, "@")
	if lastAtIndex == -1 {
		return rtspURL
	}

	return "rtsp://" + rtspURL[lastAtIndex+1:]
}

// generateUUID generates a simple UUID for WS-Discovery
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
