package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ElasticConfig Elasticsearch yapılandırması
type ElasticConfig struct {
	URL          string
	Username     string
	Password     string
	Index        string
	SkipVerify   bool
	MaxRetries   int
	RetryBackoff time.Duration
}

// loadEnvFile .env dosyasını manuel olarak yükler
func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Boş satır veya yorum atla
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// KEY=VALUE formatını parse et
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Environment variable'ı set et
		os.Setenv(key, value)
	}

	return scanner.Err()
}

// LoadElasticConfig .env dosyasından Elasticsearch config yükler
func LoadElasticConfig() (*ElasticConfig, error) {
	// Çalışma dizinini al
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("çalışma dizini alınamadı: %w", err)
	}

	// .env dosyasını farklı konumlarda ara
	envPaths := []string{
		filepath.Join(cwd, ".env"),
		filepath.Join(cwd, "..", ".env"),
		filepath.Join(cwd, "..", "..", ".env"),
	}

	var loaded bool
	for _, envPath := range envPaths {
		if err := loadEnvFile(envPath); err == nil {
			fmt.Printf("✅ .env dosyası yüklendi: %s\n", envPath)
			loaded = true
			break
		}
	}

	if !loaded {
		return nil, fmt.Errorf(".env dosyası bulunamadı (aranan yerler: %v)", envPaths)
	}

	// Required fields
	url := os.Getenv("ELASTIC_URL")
	if url == "" {
		return nil, fmt.Errorf("ELASTIC_URL is required in .env file")
	}

	username := os.Getenv("ELASTIC_USERNAME")
	if username == "" {
		return nil, fmt.Errorf("ELASTIC_USERNAME is required in .env file")
	}

	password := os.Getenv("ELASTIC_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("ELASTIC_PASSWORD is required in .env file")
	}

	index := os.Getenv("ELASTIC_INDEX")
	if index == "" {
		index = "dark-web-monitor"
	}

	skipVerify := false
	if skipVerifyStr := os.Getenv("ELASTIC_SKIP_VERIFY"); skipVerifyStr != "" {
		skipVerify, _ = strconv.ParseBool(skipVerifyStr)
	}

	maxRetries := 3
	if maxRetriesStr := os.Getenv("ELASTIC_MAX_RETRIES"); maxRetriesStr != "" {
		if val, err := strconv.Atoi(maxRetriesStr); err == nil {
			maxRetries = val
		}
	}

	retryBackoff := 5 * time.Second
	if retryBackoffStr := os.Getenv("ELASTIC_RETRY_BACKOFF"); retryBackoffStr != "" {
		if val, err := time.ParseDuration(retryBackoffStr); err == nil {
			retryBackoff = val
		}
	}

	return &ElasticConfig{
		URL:          url,
		Username:     username,
		Password:     password,
		Index:        index,
		SkipVerify:   skipVerify,
		MaxRetries:   maxRetries,
		RetryBackoff: retryBackoff,
	}, nil
}
