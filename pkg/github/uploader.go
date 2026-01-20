package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"dark-deep-new-tool/pkg/config"

	"github.com/rs/zerolog/log"
)

// UploadJob background upload için job
type UploadJob struct {
	FilePath   string // Local screenshot path
	DocumentID string // Elasticsearch document ID (update için)
}

// BatchUploadResult batch upload sonucu
type BatchUploadResult struct {
	Success      bool
	UploadedURLs map[string]string // filename -> raw URL mapping
	Failed       []string          // failed filenames
}

// Uploader GitHub upload işlemlerini yönetir
type Uploader struct {
	config *config.GitHubConfig
	client *http.Client
}

// NewUploader yeni bir GitHub uploader oluşturur
func NewUploader(cfg *config.GitHubConfig) *Uploader {
	return &Uploader{
		config: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second, // Batch için daha uzun timeout
		},
	}
}

// UploadImageBatch birden fazla image'i tek commit ile push eder
func (u *Uploader) UploadImageBatch(ctx context.Context, jobs []UploadJob) (*BatchUploadResult, error) {
	if len(jobs) == 0 {
		return &BatchUploadResult{Success: true, UploadedURLs: make(map[string]string)}, nil
	}

	log.Info().Int("dosya_sayısı", len(jobs)).Msg("📦 Batch upload başlatılıyor...")

	result := &BatchUploadResult{
		UploadedURLs: make(map[string]string),
		Failed:       []string{},
	}

	// Her dosyayı ayrı ayrı yükle (GitHub API tree kullanmak çok kompleks)
	// Ama aynı anda paralel yükleyerek hızlandırıyoruz
	type uploadResult struct {
		filename string
		rawURL   string
		err      error
	}

	resultChan := make(chan uploadResult, len(jobs))

	// Paralel upload (max 5 aynı anda)
	semaphore := make(chan struct{}, 5)

	for _, job := range jobs {
		go func(j UploadJob) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			filename := filepath.Base(j.FilePath)
			rawURL, err := u.uploadSingleFile(ctx, j.FilePath)

			resultChan <- uploadResult{
				filename: filename,
				rawURL:   rawURL,
				err:      err,
			}
		}(job)
	}

	// Sonuçları topla
	successCount := 0
	for i := 0; i < len(jobs); i++ {
		res := <-resultChan
		if res.err != nil {
			log.Error().
				Err(res.err).
				Str("file", res.filename).
				Msg("❌ Dosya yüklenemedi")
			result.Failed = append(result.Failed, res.filename)
		} else {
			result.UploadedURLs[res.filename] = res.rawURL
			successCount++

			// Local dosyayı sil (config'e göre)
			if u.config.DeleteLocal {
				// Job'ları tekrar bul ve sil
				for _, job := range jobs {
					if filepath.Base(job.FilePath) == res.filename {
						if err := os.Remove(job.FilePath); err != nil {
							log.Warn().Err(err).Str("file", res.filename).Msg("⚠️ Local file silinemedi")
						}
						break
					}
				}
			}
		}
	}

	result.Success = successCount > 0

	log.Info().
		Int("başarılı", successCount).
		Int("başarısız", len(result.Failed)).
		Int("toplam", len(jobs)).
		Msg("📦 Batch upload tamamlandı")

	return result, nil
}

// uploadSingleFile tek bir dosyayı GitHub'a push eder (internal)
func (u *Uploader) uploadSingleFile(ctx context.Context, filePath string) (string, error) {
	// Dosya kontrolü
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", filePath)
	}

	// Dosyayı oku
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Base64 encode
	encodedContent := base64.StdEncoding.EncodeToString(fileData)

	// Dosya adı (dümdüz, klasörsüz)
	filename := filepath.Base(filePath)

	// GitHub API URL
	apiURL := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/%s",
		u.config.Username,
		u.config.Repo,
		filename,
	)

	// Request body
	requestBody := map[string]interface{}{
		"message": fmt.Sprintf("Add screenshot: %s", filename),
		"content": encodedContent,
		"branch":  u.config.Branch,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// HTTP request oluştur
	req, err := http.NewRequestWithContext(ctx, "PUT", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Headers
	req.Header.Set("Authorization", "Bearer "+u.config.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	// Request gönder
	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Response kontrolü
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github api error (status %d): %s", resp.StatusCode, string(body))
	}

	// Raw URL oluştur
	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/%s/%s/%s/%s",
		u.config.Username,
		u.config.Repo,
		u.config.Branch,
		filename,
	)

	return rawURL, nil
}

// UploadImage tek bir image'i GitHub'a push eder (backward compatibility)
func (u *Uploader) UploadImage(ctx context.Context, filePath string) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= u.config.MaxRetries; attempt++ {
		rawURL, err := u.uploadSingleFile(ctx, filePath)
		if err == nil {
			log.Info().
				Str("file", filepath.Base(filePath)).
				Str("github_url", rawURL).
				Int("attempt", attempt).
				Msg("🐙 GitHub push başarılı")

			// Local dosyayı sil (config'e göre)
			if u.config.DeleteLocal {
				if err := os.Remove(filePath); err != nil {
					log.Warn().Err(err).Str("file", filePath).Msg("⚠️ Local file silinemedi")
				} else {
					log.Info().Str("file", filepath.Base(filePath)).Msg("🗑️ Local file silindi")
				}
			}

			return rawURL, nil
		}

		lastErr = err
		log.Warn().
			Err(err).
			Str("file", filepath.Base(filePath)).
			Int("attempt", attempt).
			Msg("⚠️ GitHub push başarısız, yeniden deneniyor")

		if attempt < u.config.MaxRetries {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(u.config.RetryBackoff * time.Duration(attempt)):
				// Retry
			}
		}
	}

	return "", fmt.Errorf("github push failed after %d attempts: %v", u.config.MaxRetries, lastErr)
}
