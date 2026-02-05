package flaresolverr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Client FlareSolverr istemcisi
type Client struct {
	url        string
	timeout    int
	httpClient *http.Client
}

// Request FlareSolverr istek yapısı
type Request struct {
	Cmd        string `json:"cmd"`
	URL        string `json:"url"`
	MaxTimeout int    `json:"maxTimeout"`
}

// Response FlareSolverr yanıt yapısı
type Response struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	Solution struct {
		URL       string            `json:"url"`
		Status    int               `json:"status"`
		Headers   map[string]string `json:"headers"`
		Cookies   []Cookie          `json:"cookies"`
		UserAgent string            `json:"userAgent"`
		Response  string            `json:"response"` // HTML içerik
	} `json:"solution"`
}

// Cookie FlareSolverr cookie yapısı
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"`
	HttpOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

// NewClient yeni bir FlareSolverr client oluşturur
func NewClient() *Client {
	url := os.Getenv("FLARESOLVERR_URL")
	if url == "" {
		url = "http://localhost:8191"
	}

	timeout := 180000 // ms = 180 saniye (cloudflare challenge için yeterli)
	if timeoutStr := os.Getenv("FLARESOLVERR_TIMEOUT"); timeoutStr != "" {
		if val, err := strconv.Atoi(timeoutStr); err == nil {
			timeout = val
		}
	}

	return &Client{
		url:     url,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout+30000) * time.Millisecond, // +30 saniye buffer
		},
	}
}

// IsAvailable FlareSolverr servisinin çalışıp çalışmadığını kontrol eder
func (c *Client) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", c.url+"/health", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("FlareSolverr erişilemez")
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetPage Cloudflare korumalı sayfanın HTML içeriğini alır
func (c *Client) GetPage(ctx context.Context, targetURL string) (*Response, error) {
	startTime := time.Now()

	log.Info().
		Str("url", targetURL).
		Msg("🛡️ FlareSolverr ile sayfa alınıyor")

	// Request oluştur
	reqBody := Request{
		Cmd:        "request.get",
		URL:        targetURL,
		MaxTimeout: c.timeout,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("request marshal hatası: %w", err)
	}

	// HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/v1", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("request oluşturma hatası: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// İstek gönder
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("FlareSolverr isteği başarısız: %w", err)
	}
	defer resp.Body.Close()

	// Response oku
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response okuma hatası: %w", err)
	}

	// Parse et
	var flareResp Response
	if err := json.Unmarshal(body, &flareResp); err != nil {
		return nil, fmt.Errorf("response parse hatası: %w", err)
	}

	// Status kontrol
	if flareResp.Status != "ok" {
		return nil, fmt.Errorf("FlareSolverr hatası: %s", flareResp.Message)
	}

	elapsed := time.Since(startTime)
	log.Info().
		Str("url", targetURL).
		Int("html_uzunluk", len(flareResp.Solution.Response)).
		Dur("süre", elapsed).
		Msg("✅ FlareSolverr başarılı")

	return &flareResp, nil
}

// ExtractCookies cookie'leri string formatına çevirir
func (c *Client) ExtractCookies(cookies []Cookie) string {
	var result string
	for i, cookie := range cookies {
		if i > 0 {
			result += "; "
		}
		result += cookie.Name + "=" + cookie.Value
	}
	return result
}
