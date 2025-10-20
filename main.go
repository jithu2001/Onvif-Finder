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
	"log"
	"net"
	"net/http"
	"strings"
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

// Logger
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

var logger = NewLogger(false)

func main() {
	startGUI()
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

		rtspURL = strings.ReplaceAll(rtspURL, "&amp;", "&")
		rtspURL = removeCredentialsFromURL(rtspURL)

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
