package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ForumSelectors opsiyonel explicit CSS selector'lar (hibrit sistem)
type ForumSelectors struct {
	Link     string `json:"link" mapstructure:"link"`
	Title    string `json:"title" mapstructure:"title"`
	Author   string `json:"author" mapstructure:"author"`
	PostedAt string `json:"posted_at" mapstructure:"posted_at"`
	Views    string `json:"views" mapstructure:"views"`
	Replies  string `json:"replies" mapstructure:"replies"`
}

// ForumEntry config.yaml'dan okunan forum bilgisi
type ForumEntry struct {
	Name        string          `json:"name" mapstructure:"name"`
	URL         string          `json:"url" mapstructure:"url"`
	CSSSelector string          `json:"css_selector" mapstructure:"css_selector"`
	IsOnion     bool            `json:"is_onion" mapstructure:"is_onion"`
	Type        string          `json:"type" mapstructure:"type"`
	Selectors   *ForumSelectors `json:"selectors,omitempty" mapstructure:"selectors"`
}

// Forum scrape edilen veri (Elasticsearch uyumlu)
// Forum scrape edilen veri (Elasticsearch uyumlu)
type Forum struct {
	ID            int    `json:"-"`
	Name          string `json:"name"`
	Source        string `json:"source"`
	Title         string `json:"title"`
	Author        string `json:"author"`
	Link          string `json:"link"`
	DetectionDate string `json:"detection-date"`
	Timestamp     string `json:"timestamp"`
	ThreadID      string `json:"thread-id"`
	LinkHash      string `json:"link-hash"`
}

// formatTimestampWithMs timestamp'i milisaniye ile formatlar
func formatTimestampWithMs(t time.Time) string {
	return fmt.Sprintf("%s.%03dZ",
		t.Format("2006-01-02T15:04:05"),
		t.Nanosecond()/1000000,
	)
}

// NewForum yeni bir Forum struct'ı oluşturur
func NewForum(name, source, threadID, title, author, link string) Forum {
	now := time.Now().UTC()
	timestamp := formatTimestampWithMs(now)

	return Forum{
		Name:          name,
		Source:        source,
		ThreadID:      threadID,
		Title:         title,
		Author:        author,
		Link:          link,
		DetectionDate: timestamp,
		Timestamp:     timestamp,
	}
}

// ComputeLinkHash link'in SHA-256 hash'ini hesaplar
func ComputeLinkHash(link string) string {
	hash := sha256.Sum256([]byte(link))
	return hex.EncodeToString(hash[:])
}

// LastLinkStore son çekilen linklerin hash'lerini ve timestamp'lerini saklar
type LastLinkStore struct {
	LinkHashes map[string]string `json:"link_hashes"`
	Timestamps map[string]int64  `json:"timestamps,omitempty"`
}

// LinkChecker link bazlı duplicate kontrolü (SHA-256 Hash)
type LinkChecker struct {
	linkHashes map[string]string // link_hash -> source (hangi forumdan geldi)
	lastSeen   map[string]int64  // link_hash -> unix timestamp (TTL için)
	mu         sync.RWMutex
	filePath   string
	maxEntries int
	ttlDays    int
}

const (
	// Memory ve TTL limitleri
	defaultMaxEntries = 10000 // Max 10,000 link
	defaultTTLDays    = 30    // 30 gün sonra temizle
)

// NewLinkChecker yeni bir link checker oluşturur
func NewLinkChecker(filePath string) *LinkChecker {
	return &LinkChecker{
		linkHashes: make(map[string]string),
		lastSeen:   make(map[string]int64),
		filePath:   filePath,
		maxEntries: defaultMaxEntries,
		ttlDays:    defaultTTLDays,
	}
}

// IsDuplicate link'in daha önce kaydedilip kaydedilmediğini kontrol eder
func (lc *LinkChecker) IsDuplicate(link string) bool {
	if link == "" {
		return false
	}

	lc.mu.RLock()
	defer lc.mu.RUnlock()

	linkHash := ComputeLinkHash(link)
	_, exists := lc.linkHashes[linkHash]
	return exists
}

// Update link'i kaydeder ve hash'i döner
func (lc *LinkChecker) Update(link, source string) string {
	if link == "" {
		return ""
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	linkHash := ComputeLinkHash(link)
	lc.linkHashes[linkHash] = source
	lc.lastSeen[linkHash] = time.Now().Unix()

	// Memory limit kontrolü
	if len(lc.linkHashes) > lc.maxEntries {
		lc.cleanupOldEntries()
	}

	return linkHash
}

// cleanupOldEntries eski kayıtları temizler (TTL + memory limit)
func (lc *LinkChecker) cleanupOldEntries() {
	now := time.Now().Unix()
	ttlSeconds := int64(lc.ttlDays * 24 * 60 * 60)

	var toDelete []string

	// TTL aşan kayıtları bul
	for linkHash, lastSeenTime := range lc.lastSeen {
		if now-lastSeenTime > ttlSeconds {
			toDelete = append(toDelete, linkHash)
		}
	}

	// Sil
	for _, linkHash := range toDelete {
		delete(lc.linkHashes, linkHash)
		delete(lc.lastSeen, linkHash)
	}

	// Hala limit aşıyorsa, en eskileri sil (LRU)
	if len(lc.linkHashes) > lc.maxEntries {
		type entry struct {
			linkHash  string
			timestamp int64
		}

		var entries []entry
		for lh, ts := range lc.lastSeen {
			entries = append(entries, entry{lh, ts})
		}

		// Timestamp'e göre sırala (eski → yeni)
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].timestamp > entries[j].timestamp {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}

		// En eski %10'u sil
		deleteCount := lc.maxEntries / 10
		for i := 0; i < deleteCount && i < len(entries); i++ {
			linkHash := entries[i].linkHash
			delete(lc.linkHashes, linkHash)
			delete(lc.lastSeen, linkHash)
		}
	}
}

// Count kayıtlı link sayısını döner
func (lc *LinkChecker) Count() int {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return len(lc.linkHashes)
}

// SaveToFile link hash'lerini ve timestamp'leri dosyaya kaydeder
func (lc *LinkChecker) SaveToFile() error {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	store := LastLinkStore{
		LinkHashes: lc.linkHashes,
		Timestamps: lc.lastSeen,
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize hatası: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(lc.filePath), 0755); err != nil {
		return fmt.Errorf("klasör oluşturulamadı: %w", err)
	}

	if err := os.WriteFile(lc.filePath, data, 0644); err != nil {
		return fmt.Errorf("dosya yazma hatası: %w", err)
	}

	return nil
}

// LoadFromFile link hash'lerini ve timestamp'leri dosyadan yükler
func (lc *LinkChecker) LoadFromFile() error {
	data, err := os.ReadFile(lc.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dosya okuma hatası: %w", err)
	}

	var store LastLinkStore
	if err := json.Unmarshal(data, &store); err != nil {
		return fmt.Errorf("parse hatası: %w", err)
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.linkHashes = store.LinkHashes
	if lc.linkHashes == nil {
		lc.linkHashes = make(map[string]string)
	}

	lc.lastSeen = store.Timestamps
	if lc.lastSeen == nil {
		lc.lastSeen = make(map[string]int64)
		// Timestamp yoksa şimdiyi kullan
		now := time.Now().Unix()
		for linkHash := range lc.linkHashes {
			lc.lastSeen[linkHash] = now
		}
	}

	// Yükleme sonrası eski kayıtları temizle
	lc.cleanupOldEntries()

	return nil
}

// GetStats memory ve TTL istatistiklerini döner
func (lc *LinkChecker) GetStats() map[string]interface{} {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	now := time.Now().Unix()
	ttlSeconds := int64(lc.ttlDays * 24 * 60 * 60)

	expiredCount := 0
	for _, ts := range lc.lastSeen {
		if now-ts > ttlSeconds {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_entries":    len(lc.linkHashes),
		"max_entries":      lc.maxEntries,
		"ttl_days":         lc.ttlDays,
		"expired_count":    expiredCount,
		"memory_usage_pct": float64(len(lc.linkHashes)) / float64(lc.maxEntries) * 100,
	}
}