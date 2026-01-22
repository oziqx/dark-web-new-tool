package elastic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"dark-deep-new-tool/pkg/models"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

// ElasticClient Elasticsearch istemcisi
type ElasticClient struct {
	client     *elasticsearch.Client
	index      string
	maxRetries int
	backoff    time.Duration
}

// NewElasticClient yeni bir Elasticsearch client oluşturur
func NewElasticClient(url, username, password, index string, skipVerify bool, maxRetries int, backoff time.Duration) (*ElasticClient, error) {
	cfg := elasticsearch.Config{
		Addresses: []string{url},
		Username:  username,
		Password:  password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
		RetryOnStatus: []int{502, 503, 504, 429},
		MaxRetries:    maxRetries,
		RetryBackoff: func(i int) time.Duration {
			return time.Duration(i) * backoff
		},
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	return &ElasticClient{
		client:     client,
		index:      index,
		maxRetries: maxRetries,
		backoff:    backoff,
	}, nil
}

// TestConnection Elasticsearch bağlantısını test eder
func (ec *ElasticClient) TestConnection() error {
	res, err := ec.client.Info()
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch returned error: %s", res.String())
	}

	log.Info().Msg("✅ Elasticsearch bağlantısı başarılı")
	return nil
}

// BuildDocumentID deterministik document ID oluşturur
// Format: contentHash + "-" + shortHash(source)
// Content-only hash: Link extraction sorunlarını önler
func BuildDocumentID(contentHash, source string) string {
	// Source'un hash'ini al (ilk 12 karakter)
	hash := sha256.Sum256([]byte(source))
	shortHash := hex.EncodeToString(hash[:])[:12]

	// Final ID: contentHash-shortHash
	return contentHash + "-" + shortHash
}

// IndexDocument tek bir dökümanı Elasticsearch'e gönderir
func (ec *ElasticClient) IndexDocument(ctx context.Context, doc models.Forum) error {
	// Document ID oluştur (deterministik)
	docID := BuildDocumentID(doc.ContentHash, doc.Source)

	// Document'i JSON'a çevir
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	// Elasticsearch'e gönder (Document ID ile)
	res, err := ec.client.Index(
		ec.index,
		bytes.NewReader(data),
		ec.client.Index.WithContext(ctx),
		ec.client.Index.WithDocumentID(docID),
		ec.client.Index.WithRefresh("true"),
	)

	if err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch index error: %s", res.String())
	}

	log.Info().
		Str("index", ec.index).
		Str("doc_id", docID[:24]+"...").
		Str("source", doc.Source).
		Str("type", doc.Type).
		Msg("✅ Döküman Elasticsearch'e kaydedildi")

	return nil
}

// Close Elasticsearch client'ı kapatır
func (ec *ElasticClient) Close() error {
	log.Info().Msg("🔌 Elasticsearch client kapatıldı")
	return nil
}
