package customer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// consumerDoc "consumers" index'indeki döküman yapısı
type consumerDoc struct {
	Consumer     string `json:"consumer"`
	CustomerName string `json:"customer-name"`
}

// customerInfoDoc "customer-info-{x}" index'indeki döküman yapısı
type customerInfoDoc struct {
	Keywords     []string `json:"keywords"`
	MainConsumer string   `json:"main_consumer"`
	ElasticIndex string   `json:"elastic_index"`
	Consumer     string   `json:"consumer"`
	Type         string   `json:"type"`
}

// LoadAll tüm müşterileri ve keyword'leri Elasticsearch'ten yükler
func (cm *CustomerManager) LoadAll(ctx context.Context) error {
	startTime := time.Now()
	log.Info().Msg("📥 Müşteri verileri yükleniyor...")

	// 1. consumers index'inden müşteri listesini çek
	consumers, err := cm.loadConsumerList(ctx)
	if err != nil {
		return fmt.Errorf("müşteri listesi yüklenemedi: %w", err)
	}

	if len(consumers) == 0 {
		log.Warn().Msg("⚠️ Hiç müşteri bulunamadı")
		return nil
	}

	log.Info().Int("müşteri_sayısı", len(consumers)).Msg("📋 Müşteri listesi alındı")

	// 2. Her müşteri için keyword bilgilerini çek
	loadedCount := 0
	totalKeywords := 0

	for _, consumer := range consumers {
		info, err := cm.loadCustomerInfo(ctx, consumer)
		if err != nil {
			log.Warn().
				Err(err).
				Str("consumer", consumer).
				Msg("⚠️ Müşteri bilgisi yüklenemedi, atlanıyor")
			continue
		}

		if info == nil || len(info.Keywords) == 0 {
			log.Debug().
				Str("consumer", consumer).
				Msg("Keyword bulunamadı, atlanıyor")
			continue
		}

		// Müşteriyi kaydet
		cm.mu.Lock()
		cm.customers[consumer] = info

		// Keyword'leri lookup table'a ekle (normalized)
		for _, keyword := range info.Keywords {
			normalizedKeyword := normalizeText(keyword)
			cm.keywordMap[normalizedKeyword] = info
		}
		cm.mu.Unlock()

		loadedCount++
		totalKeywords += len(info.Keywords)

		log.Debug().
			Str("consumer", consumer).
			Int("keyword_sayısı", len(info.Keywords)).
			Str("index", info.ElasticIndex).
			Msg("✅ Müşteri yüklendi")
	}

	elapsed := time.Since(startTime)
	log.Info().
		Int("müşteri", loadedCount).
		Int("keyword", totalKeywords).
		Dur("süre", elapsed).
		Msg("✅ Müşteri verileri yüklendi")

	return nil
}

// loadConsumerList "consumers" index'inden tüm müşteri kodlarını çeker
func (cm *CustomerManager) loadConsumerList(ctx context.Context) ([]string, error) {
	query := map[string]interface{}{
		"size": 1000, // max müşteri sayısı
		"_source": []string{"consumer"},
	}

	result, err := cm.elasticClient.Search(ctx, "consumers", query)
	if err != nil {
		return nil, err
	}

	var consumers []string
	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hits alanı bulunamadı")
	}

	hitsArray, ok := hits["hits"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("hits array bulunamadı")
	}

	for _, hit := range hitsArray {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}

		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		if consumer, ok := source["consumer"].(string); ok && consumer != "" {
			consumers = append(consumers, consumer)
		}
	}

	return consumers, nil
}

// loadCustomerInfo "customer-info-{consumer}" index'inden müşteri detaylarını çeker
func (cm *CustomerManager) loadCustomerInfo(ctx context.Context, consumer string) (*CustomerInfo, error) {
	indexName := fmt.Sprintf("customer-info-%s", consumer)

	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
	}

	result, err := cm.elasticClient.Search(ctx, indexName, query)
	if err != nil {
		return nil, err
	}

	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hits alanı bulunamadı")
	}

	hitsArray, ok := hits["hits"].([]interface{})
	if !ok || len(hitsArray) == 0 {
		return nil, nil // döküman yok
	}

	hitMap, ok := hitsArray[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hit parse hatası")
	}

	source, ok := hitMap["_source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("source alanı bulunamadı")
	}

	// JSON'a çevirip struct'a parse et
	sourceBytes, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}

	var doc customerInfoDoc
	if err := json.Unmarshal(sourceBytes, &doc); err != nil {
		return nil, err
	}

	return &CustomerInfo{
		Consumer:     consumer,
		CustomerName: doc.MainConsumer,
		ElasticIndex: doc.ElasticIndex,
		Keywords:     doc.Keywords,
	}, nil
}

// Reload müşteri verilerini yeniden yükler (production için)
func (cm *CustomerManager) Reload(ctx context.Context) error {
	log.Info().Msg("🔄 Müşteri verileri yeniden yükleniyor...")

	// Eski verileri temizle
	cm.mu.Lock()
	cm.customers = make(map[string]*CustomerInfo)
	cm.keywordMap = make(map[string]*CustomerInfo)
	cm.mu.Unlock()

	return cm.LoadAll(ctx)
}