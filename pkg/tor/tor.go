package tor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// TorProxyPort Tor Browser'ın kullandığı port (9150)
	// Sistem Tor daemon'u 9050 kullanır
	TorProxyPort = "9150"
	TorProxyAddr = "127.0.0.1:" + TorProxyPort
)

// NewTorClient Tor proxy'si ile HTTP istemcisi oluşturur
func NewTorClient() (*http.Client, error) {
	// SOCKS5 proxy dialer oluştur
	dialer, err := proxy.SOCKS5("tcp", TorProxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// Custom transport ile HTTP client oluştur
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
		DisableKeepAlives:     false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
	}

	return client, nil
}

// TestTorConnection Tor bağlantısını test eder
func TestTorConnection(client *http.Client) error {
	req, err := http.NewRequest("GET", "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tor connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tor check returned status %d", resp.StatusCode)
	}

	return nil
}
