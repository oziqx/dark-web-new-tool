package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GitHubConfig GitHub yapılandırması
type GitHubConfig struct {
	Username     string
	Repo         string
	Token        string
	Branch       string
	MaxRetries   int
	RetryBackoff time.Duration
	DeleteLocal  bool
}

// LoadGitHubConfig .env dosyasından GitHub config yükler
func LoadGitHubConfig() (*GitHubConfig, error) {
	// .env zaten LoadElasticConfig() tarafından yüklendi

	// Required fields
	username := os.Getenv("GITHUB_USERNAME")
	if username == "" {
		return nil, fmt.Errorf("GITHUB_USERNAME is required in .env file")
	}

	repo := os.Getenv("GITHUB_REPO")
	if repo == "" {
		return nil, fmt.Errorf("GITHUB_REPO is required in .env file")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is required in .env file")
	}

	branch := os.Getenv("GITHUB_BRANCH")
	if branch == "" {
		branch = "main" // Default
	}

	// Optional fields
	maxRetries := 3 // Default
	if maxRetriesStr := os.Getenv("GITHUB_MAX_RETRIES"); maxRetriesStr != "" {
		if val, err := strconv.Atoi(maxRetriesStr); err == nil {
			maxRetries = val
		}
	}

	retryBackoff := 5 * time.Second // Default
	if retryBackoffStr := os.Getenv("GITHUB_RETRY_BACKOFF"); retryBackoffStr != "" {
		if val, err := time.ParseDuration(retryBackoffStr); err == nil {
			retryBackoff = val
		}
	}

	deleteLocal := true // Default (disk tasarrufu)
	if deleteLocalStr := os.Getenv("GITHUB_DELETE_LOCAL"); deleteLocalStr != "" {
		deleteLocal, _ = strconv.ParseBool(deleteLocalStr)
	}

	return &GitHubConfig{
		Username:     username,
		Repo:         repo,
		Token:        token,
		Branch:       branch,
		MaxRetries:   maxRetries,
		RetryBackoff: retryBackoff,
		DeleteLocal:  deleteLocal,
	}, nil
}
