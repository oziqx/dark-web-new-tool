package config

import (
	"fmt"
	"os"

	"dark-deep-new-tool/pkg/models"

	"github.com/spf13/viper"
)

// Config forum girişlerini tutar
type Config struct {
	Forums []models.ForumEntry `mapstructure:"forums"`
}

// LoadConfig YAML dosyasından konfigürasyonu yükler
func LoadConfig(path string) (Config, error) {
	var cfg Config

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	viper.SetConfigFile(path)

	if err := viper.ReadInConfig(); err != nil {
		return cfg, fmt.Errorf("failed to read config: %w", err)
	}

	if err := viper.UnmarshalKey("forums", &cfg.Forums); err != nil {
		return cfg, fmt.Errorf("failed to unmarshal forums: %w", err)
	}

	if err := validateConfig(cfg); err != nil {
		return cfg, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// validateConfig konfigürasyon validasyonu yapar
func validateConfig(cfg Config) error {
	if len(cfg.Forums) == 0 {
		return fmt.Errorf("no forums configured")
	}

	for i, forum := range cfg.Forums {
		if forum.Name == "" {
			return fmt.Errorf("forum[%d]: name is required", i)
		}
		if forum.URL == "" {
			return fmt.Errorf("forum[%d]: url is required", i)
		}
		if forum.CSSSelector == "" {
			return fmt.Errorf("forum[%d]: css_selector is required", i)
		}
	}

	return nil
}
