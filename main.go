package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"dark-deep-new-tool/pkg/config"
	"dark-deep-new-tool/pkg/elastic"
	"dark-deep-new-tool/pkg/models"
	"dark-deep-new-tool/pkg/scraper"
	"dark-deep-new-tool/pkg/tor"
)

const (
	maxInMemoryRecords = 100
	cleanupInterval    = 15 * time.Minute
	maxConcurrent      = 3
	batchSize          = 10
	batchWaitTime      = 80 * time.Second   // ← Batch arası bekleme yok
	scrapeInterval     = 60 * time.Second  // ← Döngü bitince 10 sn sonra tekrar
	shutdownTimeout    = 30 * time.Second
)

var (
	forumData       []models.Forum
	forumCounter    int64
	contentChecker  *models.ContentChecker
	elasticClient   *elastic.ElasticClient
	dataFile        = "output/data.json"
	lastContentFile = "output/last_contents.json"
	failureDir      = "output/failure"
	dataMutex       sync.RWMutex
	isShuttingDown  int32
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("Çalışma dizini alınamadı")
	}

	// Dizinleri oluştur
	for _, dir := range []string{failureDir, "output"} {
		fullPath := filepath.Join(cwd, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			log.Fatal().Err(err).Str("klasör", fullPath).Msg("Klasör oluşturulamadı")
		}
	}

	// Loglama ayarı
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logDir := filepath.Join(cwd, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatal().Err(err).Msg("Log klasörü oluşturulamadı")
	}
	logFilePath := filepath.Join(logDir, "app.log")
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal().Err(err).Msg("Log dosyası açılamadı")
	}
	defer logFile.Close()

	multi := zerolog.MultiLevelWriter(os.Stdout, logFile)
	log.Logger = zerolog.New(multi).With().Timestamp().Logger()

	log.Info().Msg("🚀 Program başlatıldı")

	// Content checker başlat
	contentChecker = models.NewContentChecker(filepath.Join(cwd, lastContentFile))
	log.Info().Msg("📋 İçerik karşılaştırma sistemi başlatıldı (SHA-256 Hash)")

	// Son içerikleri yükle
	if err := contentChecker.LoadFromFile(); err != nil {
		log.Warn().Err(err).Msg("Son içerikler yüklenemedi, sıfırdan başlanıyor")
	} else {
		log.Info().
			Int("yüklenen_url", contentChecker.Count()).
			Msg("📚 Son içerikler yüklendi")
	}

	// Konfigürasyon yükle
	configPath := filepath.Join(cwd, "config.yaml")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Config yüklenemedi")
	}
	log.Info().Int("forum_sayısı", len(cfg.Forums)).Msg("⚙️ Konfigürasyon yüklendi")

	// Tor istemcisi
	torClient, err := tor.NewTorClient()
	if err != nil {
		log.Fatal().Err(err).Msg("Tor client başlatılamadı")
	}
	log.Info().Msg("🧅 Tor client hazır")

	// Elasticsearch client
	elasticCfg, err := config.LoadElasticConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Elasticsearch config yüklenemedi")
	}

	elasticClient, err = elastic.NewElasticClient(
		elasticCfg.URL,
		elasticCfg.Username,
		elasticCfg.Password,
		elasticCfg.Index,
		elasticCfg.SkipVerify,
		elasticCfg.MaxRetries,
		elasticCfg.RetryBackoff,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Elasticsearch client başlatılamadı")
	}

	// Elasticsearch bağlantısını test et
	if err := elasticClient.TestConnection(); err != nil {
		log.Fatal().Err(err).Msg("Elasticsearch bağlantı testi başarısız")
	}
	log.Info().
		Str("url", elasticCfg.URL).
		Str("index", elasticCfg.Index).
		Msg("📊 Elasticsearch client hazır")

	// Scraper oluştur
	s := scraper.NewScraperWithBrowsers(torClient)
	log.Info().Msg("🌐 2 Chrome browser hazır")
	log.Info().Msg("💾 RAM optimize: ~400MB (2 browser)")

	// JSON'dan eski verileri yükle
	loadExistingData(cwd)

	// İlk memory durumu
	logMemoryStats("Başlangıç")

	// Ana context ve cancel fonksiyonu
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	// WaitGroup for goroutines
	var wg sync.WaitGroup

	// Signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Cleanup ticker
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()

	// Scrape ticker
	scrapeTicker := time.NewTicker(scrapeInterval)
	defer scrapeTicker.Stop()

	// İlk tarama hemen
	log.Info().Msg("🔍 İlk tarama döngüsü başlatılıyor...")
	if err := scrapeCycleWithBatch(mainCtx, s, cfg, cwd); err != nil {
		if err != context.Canceled {
			log.Error().Err(err).Msg("İlk tarama döngüsü başarısız")
		}
	}
	saveToJSON(cwd)
	saveContentChecker()
	performCleanup()
	log.Info().Msg("✅ İlk tarama döngüsü tamamlandı")

	// Ana döngü
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-mainCtx.Done():
				log.Info().Msg("🛑 Ana döngü sonlandırılıyor...")
				return

			case <-sigChan:
				log.Info().Msg("🛑 Kapatma sinyali alındı (CTRL+C)")
				atomic.StoreInt32(&isShuttingDown, 1)

				// Graceful shutdown with timeout
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer shutdownCancel()

				shutdownChan := make(chan struct{})

				go func() {
					log.Info().Msg("💾 Veriler kaydediliyor...")
					saveToJSON(cwd)
					saveContentChecker()
					performCleanup()

					log.Info().Msg("🧹 Browser'lar kapatılıyor...")
					s.Close()

					logMemoryStats("Kapanış")
					close(shutdownChan)
				}()

				select {
				case <-shutdownChan:
					log.Info().Msg("👋 Program güvenli şekilde kapatıldı")
				case <-shutdownCtx.Done():
					log.Warn().Msg("⚠️ Graceful shutdown timeout, zorla kapatılıyor")
				}

				mainCancel()
				return

			case <-cleanupTicker.C:
				if atomic.LoadInt32(&isShuttingDown) == 1 {
					return
				}
				log.Info().Msg("🧹 Periyodik cleanup başlatılıyor...")
				performCleanup()
				saveContentChecker()
				logMemoryStats("Cleanup Sonrası")

			case <-scrapeTicker.C:
				if atomic.LoadInt32(&isShuttingDown) == 1 {
					return
				}
				log.Info().Msg("⏰ Yeni tarama döngüsü başlatılıyor...")
				if err := scrapeCycleWithBatch(mainCtx, s, cfg, cwd); err != nil {
					if err != context.Canceled {
						log.Error().Err(err).Msg("Tarama döngüsü başarısız")
					}
				}
				saveToJSON(cwd)
				saveContentChecker()
				log.Info().Msg("✅ Tarama döngüsü tamamlandı")
			}
		}
	}()

	// Wait for graceful shutdown
	wg.Wait()

	// Final cleanup
	log.Info().Msg("🏁 Program tamamen sonlandırıldı")
	os.Exit(0)
}

// scrapeCycleWithBatch siteleri batch'ler halinde tarar
func scrapeCycleWithBatch(ctx context.Context, s *scraper.Scraper, cfg config.Config, cwd string) error {
	totalForums := len(cfg.Forums)

	for i := 0; i < totalForums; i += batchSize {
		// Shutdown kontrolü
		if atomic.LoadInt32(&isShuttingDown) == 1 {
			return context.Canceled
		}

		// Context kontrolü
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		end := i + batchSize
		if end > totalForums {
			end = totalForums
		}

		batch := cfg.Forums[i:end]
		batchNum := (i / batchSize) + 1
		totalBatches := (totalForums + batchSize - 1) / batchSize

		log.Info().
			Int("batch", batchNum).
			Int("toplam_batch", totalBatches).
			Int("site_sayısı", len(batch)).
			Msg("📦 Batch tarama başlatılıyor")

		if err := scrapeBatch(ctx, s, batch, cwd); err != nil {
			if err == context.Canceled {
				return err
			}
			log.Error().Err(err).Int("batch", batchNum).Msg("Batch tarama başarısız")
		}

		// Batch'ler arası bekleme (son batch hariç)
		if end < totalForums {
			log.Info().
				Dur("bekleme", batchWaitTime).
				Msg("⏸️ Sonraki batch için bekleniyor")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(batchWaitTime):
				// Continue
			}
		}
	}

	return nil
}

// scrapeBatch bir batch'teki siteleri tarar
func scrapeBatch(ctx context.Context, s *scraper.Scraper, batch []models.ForumEntry, cwd string) error {
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, entry := range batch {
		// Shutdown kontrolü
		if atomic.LoadInt32(&isShuttingDown) == 1 {
			break
		}

		wg.Add(1)
		go func(e models.ForumEntry) {
			defer wg.Done()

			// Context kontrolü
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			log.Info().Str("forum", e.Name).Msg("📡 Tarama başlatılıyor")

			// Scraper'dan veriyi al
			scraperData, err := s.Scrape(e, cwd)
			if err != nil {
				log.Error().Err(err).Str("forum", e.Name).Msg("❌ Tarama başarısız")
				return
			}

			// Boş content kontrolü
			if scraperData.Content == "" {
				log.Info().Str("forum", e.Name).Msg("⚠️ İçerik boş, atlanıyor")
				return
			}

			// İçerik karşılaştırma (SHA-256 Hash)
			if contentChecker.IsDuplicate(scraperData.Source, scraperData.Link, scraperData.Content) {
				log.Info().
					Str("forum", e.Name).
					Str("url", e.URL).
					Str("link", scraperData.Link).
					Str("önizleme", truncateString(scraperData.Content, 40)).
					Msg("🔄 İçerik değişmemiş, atlanıyor")
				return
			}

			// YENİ İÇERİK TESPİT EDİLDİ
			log.Info().
				Str("forum", e.Name).
				Str("url", e.URL).
				Str("link", scraperData.Link).
				Msg("🆕 YENİ içerik tespit edildi")

			// Elasticsearch uyumlu Forum struct'ı oluştur
			data := models.NewForum(
				scraperData.Source,
				scraperData.Content,
				scraperData.Author,
				scraperData.Link,
				e.Type,
			)

			// Content hash'i hesapla
			contentHash := contentChecker.Update(data.Source, data.Link, data.Content)
			data.ContentHash = contentHash

			// Elasticsearch'e ANINDA gönder
			if err := saveToElastic(ctx, data); err != nil {
				log.Warn().
					Err(err).
					Str("forum", e.Name).
					Msg("⚠️ Elasticsearch'e gönderilemedi ama devam ediliyor")
			}

			dataMutex.Lock()
			defer dataMutex.Unlock()

			// Yeni veri ekle
			atomic.AddInt64(&forumCounter, 1)
			data.ID = int(atomic.LoadInt64(&forumCounter))

			// Bellekte sadece son 100 kayıt tut
			if len(forumData) >= maxInMemoryRecords {
				forumData = forumData[1:]
			}
			forumData = append(forumData, data)

			log.Info().
				Str("forum", e.Name).
				Str("link", data.Link).
				Str("hash", contentHash[:16]+"...").
				Str("type", data.Type).
				Int("kayıt_no", data.ID).
				Int("bellekteki_kayıt", len(forumData)).
				Msg("✅ YENİ VERİ kaydedildi")
		}(entry)
	}

	// Goroutine'lerin bitmesini bekle
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Context cancel veya goroutines complete
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// loadExistingData JSON'dan eski verileri yükler
func loadExistingData(cwd string) {
	dataPath := filepath.Join(cwd, dataFile)

	if _, err := os.Stat(dataPath); err != nil {
		log.Info().Msg("📂 Eski veri bulunamadı, sıfırdan başlanıyor")
		return
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		log.Warn().Err(err).Msg("Eski veri okunamadı")
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	if err := json.Unmarshal(data, &forumData); err != nil {
		log.Warn().Err(err).Msg("Eski veri parse edilemedi")
		return
	}

	// Sadece son 100 kayıt tut
	if len(forumData) > maxInMemoryRecords {
		forumData = forumData[len(forumData)-maxInMemoryRecords:]
	}

	atomic.StoreInt64(&forumCounter, int64(len(forumData)))
	log.Info().
		Int("yüklenen_kayıt", len(forumData)).
		Int("url_count", contentChecker.Count()).
		Msg("📚 Eski veriler başarıyla yüklendi")
}

// saveToJSON tüm veriyi JSON'a kaydeder
func saveToJSON(cwd string) {
	dataMutex.RLock()
	defer dataMutex.RUnlock()

	if len(forumData) == 0 {
		log.Info().Msg("💾 Kaydedilecek veri yok")
		return
	}

	data, err := json.MarshalIndent(forumData, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("JSON encode hatası")
		return
	}

	dataPath := filepath.Join(cwd, dataFile)

	if err := os.MkdirAll(filepath.Dir(dataPath), 0755); err != nil {
		log.Error().Err(err).Msg("Data klasörü oluşturulamadı")
		return
	}

	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		log.Error().Err(err).Msg("JSON yazma hatası")
	} else {
		log.Info().
			Int("toplam_kayıt", len(forumData)).
			Str("dosya", dataPath).
			Msg("💾 Veriler başarıyla kaydedildi")
	}
}

// saveContentChecker son içerikleri kaydeder
func saveContentChecker() {
	if err := contentChecker.SaveToFile(); err != nil {
		log.Error().Err(err).Msg("Son içerikler kaydedilemedi")
	} else {
		log.Info().Int("url_count", contentChecker.Count()).Msg("💾 Son içerikler kaydedildi")
	}
}

// saveToElastic Elasticsearch'e tek kayıt gönderir
func saveToElastic(ctx context.Context, data models.Forum) error {
	if elasticClient == nil {
		log.Warn().Msg("⚠️ Elasticsearch client yok, atlıyor")
		return nil
	}

	// Elasticsearch'e ANINDA gönder
	if err := elasticClient.IndexDocument(ctx, data); err != nil {
		log.Error().
			Err(err).
			Str("source", data.Source).
			Str("link", data.Link).
			Msg("❌ Elasticsearch'e gönderilemedi")
		return err
	}

	log.Info().
		Str("source", data.Source).
		Str("type", data.Type).
		Str("hash", data.ContentHash[:16]+"...").
		Msg("📊 Elasticsearch'e başarıyla gönderildi")

	return nil
}

// performCleanup memory cleanup yapar
func performCleanup() {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	initialCount := len(forumData)

	// Bellekte max 100 kayıt tut
	if len(forumData) > maxInMemoryRecords {
		removedCount := len(forumData) - maxInMemoryRecords
		forumData = forumData[removedCount:]

		log.Info().
			Int("silinen_kayıt", removedCount).
			Int("kalan_kayıt", len(forumData)).
			Msg("✂️ Eski kayıtlar bellekten temizlendi")
	}

	log.Info().
		Int("önceki_kayıt", initialCount).
		Int("şimdiki_kayıt", len(forumData)).
		Msg("🧹 Cleanup tamamlandı")

	// Garbage collection
	runtime.GC()
	debug.FreeOSMemory()

	log.Info().Msg("♻️ Garbage collection çalıştırıldı")
}

// logMemoryStats memory istatistiklerini loglar
func logMemoryStats(phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	log.Info().
		Str("phase", phase).
		Uint64("alloc_mb", m.Alloc/1024/1024).
		Uint64("total_alloc_mb", m.TotalAlloc/1024/1024).
		Uint64("sys_mb", m.Sys/1024/1024).
		Uint32("num_gc", m.NumGC).
		Int("forum_data_count", len(forumData)).
		Int("url_count", contentChecker.Count()).
		Msg("📊 Memory Stats")
}

// truncateString string'i keser
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
