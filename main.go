package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    SOAPBody `xml:"Body"`
}

type SOAPBody struct {
	Profiles   []MediaProfile `xml:"GetProfilesResponse>Profiles"`
	StreamURIs []StreamURI    `xml:"GetStreamUriResponse>MediaUri"`
}

type MediaProfile struct {
	Token       string      `xml:"token,attr"`
	VideoSource VideoSource `xml:"VideoSource"`
	URI         StreamURI   `xml:"Extensions>URI"`
}

type VideoSource struct {
	Token string `xml:"token,attr"`
}

type StreamURI struct {
	RTSPURI string `xml:"Uri"`
}

func main() {
	if len(os.Args) != 4 {
		log.Fatal("Usage: program <ip_address> <username> <password>")
	}

	ip, username, password := os.Args[1], os.Args[2], os.Args[3]
	rtspURL, err := discoverRTSPURL(ip, username, password)
	if err != nil {
		log.Fatalf("RTSP URL discovery failed: %v", err)
	}

	fmt.Printf("RTSP URL: %s\n", rtspURL)
}

func discoverRTSPURL(ip, username, password string) (string, error) {
	serviceURLs := []string{
		fmt.Sprintf("http://%s/onvif/device_service", ip),
		fmt.Sprintf("http://%s/onvif/media_service", ip),
		fmt.Sprintf("http://%s/media/service", ip),
	}

	authMethods := []string{"digest", "basic", "wsse"}

	for _, serviceURL := range serviceURLs {
		for _, authMethod := range authMethods {
			profiles, err := sendSOAPRequest(serviceURL, createSOAPRequest(username, password, "GetProfiles", authMethod))
			if err != nil {
				log.Printf("Discovery attempt failed: %v", err)
				continue
			}

			if len(profiles) > 0 {
				// Try first profile's URI
				streamURIRequest := createStreamURIRequest(username, password, profiles[0].Token, authMethod)
				rtspURL, err := sendStreamURIRequest(serviceURL, streamURIRequest)
				if err == nil {
					return rtspURL, nil
				}
			}
		}
	}

	return "", fmt.Errorf("RTSP URL discovery failed across all methods")
}

func sendSOAPRequest(url, soapRequest string) ([]MediaProfile, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, strings.NewReader(soapRequest))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://www.onvif.org/ver10/media/wsdl/GetProfiles")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var envelope SOAPEnvelope
	err = xml.Unmarshal(body, &envelope)
	if err != nil {
		return nil, fmt.Errorf("XML parsing error: %v. Raw response: %s", err, string(body))
	}

	return envelope.Body.Profiles, nil
}

func sendStreamURIRequest(url, soapRequest string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, strings.NewReader(soapRequest))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://www.onvif.org/ver10/media/wsdl/GetStreamUri")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	rtspMatch := string(body)
	rtspRegex := regexp.MustCompile(`rtsp://[^<]+`)
	matches := rtspRegex.FindStringSubmatch(rtspMatch)
	if len(matches) > 0 {
		return matches[0], nil
	}

	return "", fmt.Errorf("RTSP URL not found")
}

func createSOAPRequest(username, password, action, authMethod string) string {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	nonce := generateNonce()
	passwordDigest := generatePasswordDigest(nonce, timestamp, password)

	switch authMethod {
	case "digest":
		return createDigestSOAPRequest(username, passwordDigest, nonce, timestamp, action)
	case "basic":
		return createBasicSOAPRequest(username, password, action)
	default:
		return createWSSESOAPRequest(username, passwordDigest, nonce, timestamp, action)
	}
}

func createWSSESOAPRequest(username, passwordDigest, nonce, timestamp, action string) string {
	if action == "GetProfiles" {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
		<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
			xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
			xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
			xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
			<soap:Header>
				<wsse:Security>
					<wsse:UsernameToken>
						<wsse:Username>%s</wsse:Username>
						<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%s</wsse:Password>
						<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce>
						<wsu:Created>%s</wsu:Created>
					</wsse:UsernameToken>
				</wsse:Security>
			</soap:Header>
			<soap:Body>
				<trt:GetProfiles/>
			</soap:Body>
		</soap:Envelope>`, username, passwordDigest, nonce, timestamp)
	}
	return ""
}

func createDigestSOAPRequest(username, passwordDigest, nonce, timestamp, action string) string {
	if action == "GetProfiles" {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
		<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
			xmlns:wsa="http://www.w3.org/2005/08/addressing"
			xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
			<soap:Header>
				<wsa:Action>http://www.onvif.org/ver10/media/wsdl/GetProfiles</wsa:Action>
			</soap:Header>
			<soap:Body>
				<trt:GetProfiles/>
			</soap:Body>
		</soap:Envelope>`)
	}
	return ""
}

func createBasicSOAPRequest(username, password, action string) string {
	if action == "GetProfiles" {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
			xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
			<soap:Body>
				<trt:GetProfiles/>
			</soap:Body>
		</soap:Envelope>`)
	}
	return ""
}

func createStreamURIRequest(username, password, profileToken, authMethod string) string {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	nonce := generateNonce()
	passwordDigest := generatePasswordDigest(nonce, timestamp, password)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
	<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
		xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
		xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
		xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
		<soap:Header>
			<wsse:Security>
				<wsse:UsernameToken>
					<wsse:Username>%s</wsse:Username>
					<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%s</wsse:Password>
					<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce>
					<wsu:Created>%s</wsu:Created>
				</wsse:UsernameToken>
			</wsse:Security>
		</soap:Header>
		<soap:Body>
			<trt:GetStreamUri>
				<trt:StreamSetup>
					<trt:Stream>RTP-Unicast</trt:Stream>
					<trt:Transport>
						<trt:Protocol>RTSP</trt:Protocol>
					</trt:Transport>
				</trt:StreamSetup>
				<trt:ProfileToken>%s</trt:ProfileToken>
			</trt:GetStreamUri>
		</soap:Body>
	</soap:Envelope>`, username, passwordDigest, nonce, timestamp, profileToken)
}

func generateNonce() string {
	nonceBytes := make([]byte, 16)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return base64.StdEncoding.EncodeToString([]byte("default-nonce"))
	}
	return base64.StdEncoding.EncodeToString(nonceBytes)
}

func generatePasswordDigest(nonce, timestamp, password string) string {
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonce)
	timestampBytes := []byte(timestamp)
	passwordBytes := []byte(password)

	combinedBytes := append(append(nonceBytes, timestampBytes...), passwordBytes...)

	sha1Hash := sha1.Sum(combinedBytes)
	return base64.StdEncoding.EncodeToString(sha1Hash[:])
}
