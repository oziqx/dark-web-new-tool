package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"dark-deep-new-tool/pkg/config"
	"dark-deep-new-tool/pkg/elastic"
	"dark-deep-new-tool/pkg/models"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Log ayarları
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
		With().
		Timestamp().
		Logger()

	log.Info().Msg("🚀 Manuel veri ekleme başlatılıyor")

	// 1. JSON dosyasını oku
	data, err := os.ReadFile("manuel-data.json")
	if err != nil {
		log.Fatal().Err(err).Msg("❌ manuel-data.json okunamadı. Dosyanın var olduğundan ve isminin doğru olduğundan emin ol.")
	}

	// 2. Parse et (Hem tek obje hem liste desteği)
	var records []models.Forum
	if err := json.Unmarshal(data, &records); err != nil {
		// Liste değilse tek obje olarak dene
		var singleRecord models.Forum
		if err2 := json.Unmarshal(data, &singleRecord); err2 != nil {
			log.Fatal().Err(err).Msg("❌ JSON parse hatası. Formatın []models.Forum veya models.Forum olduğundan emin ol.")
		}
		records = append(records, singleRecord)
	}

	if len(records) == 0 {
		log.Fatal().Msg("❌ JSON dosyası boş veya geçerli kayıt içermiyor")
	}

	log.Info().Int("kayıt_sayısı", len(records)).Msg("📋 Veriler bellekten okundu")

	// 3. Elasticsearch Config Yükle
	elasticCfg, err := config.LoadElasticConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("❌ Elasticsearch config (.env) yüklenemedi")
	}

	// 4. Elasticsearch Client Oluştur
	client, err := elastic.NewElasticClient(
		elasticCfg.URL,
		elasticCfg.Username,
		elasticCfg.Password,
		elasticCfg.Index,
		elasticCfg.SkipVerify,
		elasticCfg.MaxRetries,
		elasticCfg.RetryBackoff,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("❌ Elasticsearch client oluşturulamadı")
	}

	// Bağlantıyı test et
	if err := client.TestConnection(); err != nil {
		log.Fatal().Err(err).Msg("❌ Elasticsearch sunucusuna ulaşılamıyor. URL ve kimlik bilgilerini kontrol et.")
	}

	log.Info().Str("index", elasticCfg.Index).Msg("✅ Elasticsearch bağlantısı kuruldu")

	// 5. Kayıtları İşle ve Gönder
	ctx := context.Background()
	successCount := 0
	errorCount := 0

	for i, record := range records {
		// Kayıt validasyonu
		if record.Link == "" {
			log.Warn().Int("sıra", i+1).Msg("⚠️ Link alanı boş olan kayıt atlanıyor")
			errorCount++
			continue
		}

		// Otomatik Alan Tamamlama
		if record.Name == "" {
			record.Name = "manual-entry"
		}
		if record.Source == "" {
			record.Source = "manual"
		}

		// Link Hash
		if record.LinkHash == "" {
			record.LinkHash = models.ComputeLinkHash(record.Link)
		}

		// Thread ID (Linkten türet, eğer yoksa)
		if record.ThreadID == "" {
			parts := strings.Split(strings.TrimRight(record.Link, "/"), "/")
			record.ThreadID = parts[len(parts)-1]
		}

		// Zaman damgası
		now := time.Now().UTC()
		formattedNow := now.Format("2006-01-02T15:04:05.000Z")
		if record.Timestamp == "" {
			record.Timestamp = formattedNow
		}
		if record.DetectionDate == "" {
			record.DetectionDate = formattedNow
		}

		// Elasticsearch'e Gönder
		log.Info().
			Int("sıra", i+1).
			Str("title", safeTruncate(record.Title, 50)).
			Msg("📤 Kayıt gönderiliyor...")

		if err := client.IndexDocument(ctx, record); err != nil {
			log.Error().
				Err(err).
				Int("sıra", i+1).
				Str("link", record.Link).
				Msg("❌ Kayıt gönderilemedi")
			errorCount++
		} else {
			successCount++
			log.Info().
				Int("sıra", i+1).
				Str("hash", record.LinkHash[:12]+"...").
				Msg("✅ Başarıyla eklendi")
		}

		// Rate limiting (Çok fazla kayıt varsa sunucuyu yormamak için)
		if len(records) > 5 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	// 6. Özet Sonuç
	log.Info().Msg("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Info().
		Int("toplam", len(records)).
		Int("başarılı", successCount).
		Int("hata", errorCount).
		Msg("📊 İşlem tamamlandı")

	if errorCount > 0 {
		fmt.Println("\n⚠️ Bazı kayıtlar eklenemedi, detaylar yukarıda.")
	}
}

// safeTruncate Türkçe karakter desteği ile string kısaltır
func safeTruncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
