package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// ForumEntry config.yaml'dan okunan forum bilgisi
type ForumEntry struct {
	Name        string `json:"name" mapstructure:"name"`
	URL         string `json:"url" mapstructure:"url"`
	CSSSelector string `json:"css_selector" mapstructure:"css_selector"`
	IsOnion     bool   `json:"is_onion" mapstructure:"is_onion"`
	Type        string `json:"type" mapstructure:"type"`
}

// Forum scrape edilen veri (Elasticsearch uyumlu)
type Forum struct {
	// Internal fields (Elasticsearch'e gönderilmez)
	ID int `json:"-"`

	// Elasticsearch fields
	Source        string `json:"source"`
	Content       string `json:"content"`
	ContentHash   string `json:"content-hash"`
	Author        string `json:"author,omitempty"`
	Link          string `json:"link,omitempty"`
	DetectionDate string `json:"detection-date"`
	Timestamp     string `json:"timestamp"`
	Type          string `json:"type"`
}

// formatTimestampWithMs timestamp'i milisaniye ile formatlar
func formatTimestampWithMs(t time.Time) string {
	return fmt.Sprintf("%s.%03dZ",
		t.Format("2006-01-02T15:04:05"),
		t.Nanosecond()/1000000,
	)
}

// NewForum yeni bir Forum struct'ı oluşturur
func NewForum(source, content, author, link, contentType string) Forum {
	now := time.Now().UTC()
	timestamp := formatTimestampWithMs(now)

	return Forum{
		Source:        source,
		Content:       content,
		Author:        author,
		Link:          link,
		DetectionDate: timestamp,
		Timestamp:     timestamp,
		Type:          contentType,
	}
}

// LastContentStore son çekilen içeriklerin hash'lerini ve timestamp'lerini saklar
type LastContentStore struct {
	Hashes    map[string]string `json:"hashes"`
	Timestamps map[string]int64  `json:"timestamps,omitempty"` // TTL için
}

// ContentChecker içerik karşılaştırma (Source + Normalized Content + SHA-256 Hash)
type ContentChecker struct {
	lastHashes   map[string]string // source -> content hash
	lastSeen     map[string]int64  // source -> unix timestamp (TTL için)
	mu           sync.RWMutex
	filePath     string
	dynamicRegex *regexp.Regexp
	maxEntries   int           // Memory limit
	ttlDays      int           // TTL gün sayısı
}

const (
	// Memory ve TTL limitleri
	defaultMaxEntries = 10000 // Max 10,000 URL
	defaultTTLDays    = 30    // 30 gün sonra temizle
)

// NewContentChecker yeni bir checker oluşturur
func NewContentChecker(filePath string) *ContentChecker {
	dynamicPattern := `(?i)(` +
		// ==================== FORUM TABLO METRİKLERİ (ÖNCE) ====================
		// Zaman ifadesi + yan yana sayılar (replies + views)
		`(?:yesterday|today|tomorrow|ago|am|pm)[,\s]+\d{1,6}\s+\d{1,6}[,\s]*|` +
		`\d{1,6}\s+\d{1,6}\s+(?:yesterday|today|tomorrow|ago|am|pm)[,\s]*|` +
		`\d{1,2}:\d{2}\s*(?:am|pm)?[,\s]+\d{1,6}\s+\d{1,6}[,\s]*|` +
		`\d{1,6}\s+\d{1,6}\s+\d{1,2}:\d{2}\s*(?:am|pm)?[,\s]*|` +
		
		// Zaman + tek sayı
		`(?:yesterday|today|tomorrow|ago|am|pm)[,\s]+\d{1,5}[,\s]+|` +
		`\d{1,5}\s+(?:yesterday|today|tomorrow|ago|am|pm)[,\s]*|` +
		
		// "by" veya "Last Post:" ile biten metrikler
		`\d{1,6}\s+\d{1,6}\s+(?:by|last\s+post:?)[,\s]*|` +
		`\d{1,6}\s+(?:by|last\s+post:?)[,\s]*|` +

		// ==================== COUNTDOWN / TIMER ====================
		`\d+\s*D\s*\d+\s*H\s*\d+\s*M\s*\d+\s*S[,\s]*|` +
		`\d+\s*d\s*\d+\s*h\s*\d+\s*m\s*\d+\s*s[,\s]*|` +
		`\d+\s*days?\s*\d+\s*hours?\s*\d+\s*min(?:ute)?s?\s*\d+\s*sec(?:ond)?s?[,\s]*|` +
		`\d+\s*days?\s*\d+\s*hours?\s*\d+\s*min(?:ute)?s?[,\s]*|` +
		`\d+\s*days?\s*\d+\s*hours?[,\s]*|` +
		`\d+\s*h\s*\d+\s*m\s*\d+\s*s[,\s]*|` +
		`\d+\s*h\s*\d+\s*m[,\s]*|` +
		`\d+:\d+:\d+:\d+[,\s]*|` +
		`\d+:\d+:\d+[,\s]*|` +
		`time\s*left[:\s]*[^,\n]+[,\s]*|` +
		`expires?\s*in[:\s]*[^,\n]+[,\s]*|` +
		`deadline[:\s]*[^,\n]+[,\s]*|` +
		`countdown[:\s]*[^,\n]+[,\s]*|` +

		// ==================== TARİH / SAAT ====================
		`\d{1,2}:\d{2}:\d{2}\s*(?:am|pm)?[,\s]*|` +
		`\d{1,2}:\d{2}\s*(?:am|pm)?[,\s]*|` +
		`\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}[,\s]*|` +
		`\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}[,\s]*|` +
		`\d{2}\.\d{2}\.\d{4}[,\s]*|` +
		`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}[,\s]*|` +
		`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}[,\s]*|` +
		`\d{1,2}/\d{1,2}/\d{2,4}[,\s]*|` +
		`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[,\s]*|` +
		`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\s]*|` +
		`\d{4}-\d{2}-\d{2}[,\s]*|` +
		`(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}[,\s]*\d{4}[,\s]*|` +
		`\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[,\s]*\d{4}[,\s]*|` +
		`(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}[,\s]*|` +

		// ==================== GÖRECELİ ZAMAN ====================
		`\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago[,\s]*|` +
		`\d+\s*(?:sec|min|hr|wk|mo|yr)s?\s+ago[,\s]*|` +
		`a\s+(?:second|minute|hour|day|week|month|year)\s+ago[,\s]*|` +
		`an?\s+(?:second|minute|hour|day|week|month|year)\s+ago[,\s]*|` +
		`a\s+moment\s+ago[,\s]*|just\s+now[,\s]*|moments?\s+ago[,\s]*|` +
		`a\s+few\s+(?:second|minute|hour)s?\s+ago[,\s]*|` +
		`seconds?\s+ago[,\s]*|minutes?\s+ago[,\s]*|hours?\s+ago[,\s]*|` +
		`(?:yesterday|today|tomorrow)[,\s]*at\s*\d{1,2}:\d{2}\s*(?:am|pm)?[,\s]*|` +
		`(?:yesterday|today|tomorrow)[,\s]*\d{1,2}:\d{2}\s*(?:am|pm)?[,\s]*|` +
		`(?:yesterday|today|tomorrow)[,\s]*|` +
		`last\s+(?:week|month|year|night|monday|tuesday|wednesday|thursday|friday|saturday|sunday)[,\s]*|` +
		`in\s+\d+\s+(?:second|minute|hour|day|week|month|year)s?[,\s]*|` +
		`recently[,\s]*|just\s+posted[,\s]*|just\s+now[,\s]*|` +
		`new[,\s]*|updated[,\s]*|edited[,\s]*|modified[,\s]*|` +

		// ==================== FORUM METRİKLERİ ====================
		`views?[:\s]*[\d,\.]+\s*[km]?[,\s]*|` +
		`[\d,\.]+\s*[km]?\s*views?[,\s]*|` +
		`[\d,\.]+\s*[km]?\s*view[,\s]*|` +
		`replies?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*replies?[,\s]*|` +
		`comments?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*comments?[,\s]*|` +
		`responses?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*responses?[,\s]*|` +
		`likes?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*likes?[,\s]*|` +
		`reactions?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*reactions?[,\s]*|` +
		`upvotes?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*upvotes?[,\s]*|` +
		`downvotes?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*downvotes?[,\s]*|` +
		`posts?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*posts?[,\s]*|` +
		`threads?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*threads?[,\s]*|` +
		`topics?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*topics?[,\s]*|` +
		`members?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*members?[,\s]*|` +
		`users?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*users?[,\s]*|` +
		`users?\s+online[:\s]*[\d,\.]+[,\s]*|` +
		`[\d,\.]+\s*users?\s*online[,\s]*|` +
		`online[:\s]*[\d,\.]+[,\s]*|` +
		`guests?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*guests?[,\s]*|` +
		`messages?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*messages?[,\s]*|` +
		`downloads?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*downloads?[,\s]*|` +
		`shares?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*shares?[,\s]*|` +
		`ratings?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*ratings?[,\s]*|` +
		`stars?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*stars?[,\s]*|` +
		`score[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*score[,\s]*|` +
		`points?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*points?[,\s]*|` +
		`karma[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*karma[,\s]*|` +
		`reputation[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*reputation[,\s]*|` +
		`rep[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*rep[,\s]*|` +
		`credits?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*credits?[,\s]*|` +

		// ==================== RANSOMWARE / LEAK ====================
		`disclosures?\s*\d+/\d+[,\s]*|\d+/\d+\s*disclosures?[,\s]*|` +
		`victims?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*victims?[,\s]*|` +
		`companies?\s*affected[:\s]*[\d,\.]+[,\s]*|` +
		`files?\s*encrypted[:\s]*[\d,\.]+[,\s]*|` +
		`encrypted\s*files?[:\s]*[\d,\.]+[,\s]*|` +
		`files?\s*leaked[:\s]*[\d,\.]+[,\s]*|` +
		`data\s*size[:\s]*~?\s*[\d,\.]+\s*(?:gb|tb|mb|kb|bytes?)?[,\s]*|` +
		`~?\s*[\d,\.]+\s*(?:gb|tb|mb|kb)\s*(?:data|total|size)?[,\s]*|` +
		`total\s*size[:\s]*~?\s*[\d,\.]+\s*(?:gb|tb|mb|kb)?[,\s]*|` +
		`size[:\s]*~?\s*[\d,\.]+\s*(?:gb|tb|mb|kb)?[,\s]*|` +
		`price[:\s]*\$?\s*[\d,\.]+[,\s]*|` +
		`ransom[:\s]*\$?\s*[\d,\.]+[,\s]*|` +
		`payment[:\s]*\$?\s*[\d,\.]+[,\s]*|` +
		`amount[:\s]*\$?\s*[\d,\.]+[,\s]*|` +
		`\$\s*[\d,\.]+\s*(?:usd|btc|xmr|eth)?[,\s]*|` +
		`[\d,\.]+\s*(?:usd|btc|xmr|eth|bitcoin|monero|ethereum)[,\s]*|` +
		`published[:\s]*\d+[,\s]*|leaked[:\s]*\d+[,\s]*|` +

		// ==================== SAYFA / NAVİGASYON ====================
		`page\s*\d+\s*(?:of\s*\d+)?[,\s]*|` +
		`\d+\s*of\s*\d+[,\s]*|` +
		`showing\s*\d+\s*-\s*\d+[,\s]*|` +
		`#\d+[,\s]*|` +
		`prev(?:ious)?[,\s]*|next[,\s]*|first[,\s]*|last[,\s]*|` +

		// ==================== KULLANICI DURUMU ====================
		`last\s*seen[:\s]*[^,\n]+[,\s]*|` +
		`last\s*active[:\s]*[^,\n]+[,\s]*|` +
		`last\s*visit[:\s]*[^,\n]+[,\s]*|` +
		`last\s*login[:\s]*[^,\n]+[,\s]*|` +
		`last\s*post[:\s]*[^,\n]+[,\s]*|` +
		`(?:currently\s*)?(?:online|offline|away|busy|idle|invisible)[,\s]*|` +
		`status[:\s]*(?:online|offline|away|busy|idle)[,\s]*|` +
		`active\s*now[,\s]*|` +
		`joined[:\s]*[^,\n]+[,\s]*|` +

		// ==================== DOSYA BOYUTU ====================
		`[\d,\.]+\s*(?:bytes?|kb|mb|gb|tb|pb)[,\s]*|` +
		`size[:\s]*[\d,\.]+\s*(?:bytes?|kb|mb|gb|tb)?[,\s]*|` +
		`length[:\s]*[\d,\.]+[,\s]*|` +
		`duration[:\s]*[\d:]+[,\s]*|` +
		`[\d:]+\s*duration[,\s]*|` +

		// ==================== DİĞER ====================
		`visitors?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*visitors?[,\s]*|` +
		`hits?[:\s]*[\d,\.]+[,\s]*|[\d,\.]+\s*hits?[,\s]*|` +
		`[\d,\.]+\s*%[,\s]*|` +
		`\b\d{4,}\b[,\s]*` +
		`)`


	return &ContentChecker{
		lastHashes:   make(map[string]string),
		lastSeen:     make(map[string]int64),
		filePath:     filePath,
		dynamicRegex: regexp.MustCompile(dynamicPattern),
		maxEntries:   defaultMaxEntries,
		ttlDays:      defaultTTLDays,
	}
}

// normalizeContent içerikteki dinamik ifadeleri temizler
func (cc *ContentChecker) normalizeContent(content string) string {
	return cc.dynamicRegex.ReplaceAllString(content, "[DYNAMIC]")
}

// computeHash normalized content'in SHA-256 hash'ini hesaplar
func (cc *ContentChecker) computeHash(content string) string {
	normalized := cc.normalizeContent(content)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// makeKey source bazlı key oluşturur
func (cc *ContentChecker) makeKey(source string) string {
	return source
}

// IsDuplicate içeriğin değişip değişmediğini kontrol eder
func (cc *ContentChecker) IsDuplicate(source, content string) bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	newHash := cc.computeHash(content)
	key := cc.makeKey(source)

	if lastHash, exists := cc.lastHashes[key]; exists {
		return newHash == lastHash
	}

	return false
}

// Update içeriği günceller ve hash'i saklar
func (cc *ContentChecker) Update(source, content string) string {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	hash := cc.computeHash(content)
	key := cc.makeKey(source)
	
	cc.lastHashes[key] = hash
	cc.lastSeen[key] = time.Now().Unix()

	// ✅ YENİ: Memory limit kontrolü
	if len(cc.lastHashes) > cc.maxEntries {
		cc.cleanupOldEntries()
	}

	return hash
}

// cleanupOldEntries eski kayıtları temizler (TTL + memory limit)
func (cc *ContentChecker) cleanupOldEntries() {
	now := time.Now().Unix()
	ttlSeconds := int64(cc.ttlDays * 24 * 60 * 60)
	
	var toDelete []string
	
	// TTL aşan kayıtları bul
	for key, lastSeenTime := range cc.lastSeen {
		if now-lastSeenTime > ttlSeconds {
			toDelete = append(toDelete, key)
		}
	}
	
	// Sil
	for _, key := range toDelete {
		delete(cc.lastHashes, key)
		delete(cc.lastSeen, key)
	}
	
	// Hala limit aşıyorsa, en eskileri sil (LRU)
	if len(cc.lastHashes) > cc.maxEntries {
		// En eski kayıtları bul
		type entry struct {
			key       string
			timestamp int64
		}
		
		var entries []entry
		for key, ts := range cc.lastSeen {
			entries = append(entries, entry{key, ts})
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
		deleteCount := cc.maxEntries / 10
		for i := 0; i < deleteCount && i < len(entries); i++ {
			key := entries[i].key
			delete(cc.lastHashes, key)
			delete(cc.lastSeen, key)
		}
	}
}

// Count kayıtlı URL sayısını döner
func (cc *ContentChecker) Count() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return len(cc.lastHashes)
}

// SaveToFile son hash'leri ve timestamp'leri dosyaya kaydeder
func (cc *ContentChecker) SaveToFile() error {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	store := LastContentStore{
		Hashes:     cc.lastHashes,
		Timestamps: cc.lastSeen,
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize hatası: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(cc.filePath), 0755); err != nil {
		return fmt.Errorf("klasör oluşturulamadı: %w", err)
	}

	if err := os.WriteFile(cc.filePath, data, 0644); err != nil {
		return fmt.Errorf("dosya yazma hatası: %w", err)
	}

	return nil
}

// LoadFromFile son hash'leri ve timestamp'leri dosyadan yükler
func (cc *ContentChecker) LoadFromFile() error {
	data, err := os.ReadFile(cc.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dosya okuma hatası: %w", err)
	}

	var store LastContentStore
	if err := json.Unmarshal(data, &store); err != nil {
		return fmt.Errorf("parse hatası: %w", err)
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Backward compatibility - eski format
	if store.Hashes == nil {
		var oldStore struct {
			Contents map[string]string `json:"contents"`
		}
		if err := json.Unmarshal(data, &oldStore); err == nil && oldStore.Contents != nil {
			cc.lastHashes = make(map[string]string)
			cc.lastSeen = make(map[string]int64)
			now := time.Now().Unix()
			
			for key, content := range oldStore.Contents {
				cc.lastHashes[key] = cc.computeHash(content)
				cc.lastSeen[key] = now
			}
			return nil
		}
	}

	cc.lastHashes = store.Hashes
	if cc.lastHashes == nil {
		cc.lastHashes = make(map[string]string)
	}

	cc.lastSeen = store.Timestamps
	if cc.lastSeen == nil {
		cc.lastSeen = make(map[string]int64)
		// Timestamp yoksa şimdiyi kullan
		now := time.Now().Unix()
		for key := range cc.lastHashes {
			cc.lastSeen[key] = now
		}
	}

	// Yükleme sonrası eski kayıtları temizle
	cc.cleanupOldEntries()

	return nil
}

// GetStats memory ve TTL istatistiklerini döner
func (cc *ContentChecker) GetStats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	now := time.Now().Unix()
	ttlSeconds := int64(cc.ttlDays * 24 * 60 * 60)
	
	expiredCount := 0
	for _, ts := range cc.lastSeen {
		if now-ts > ttlSeconds {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(cc.lastHashes),
		"max_entries":     cc.maxEntries,
		"ttl_days":        cc.ttlDays,
		"expired_count":   expiredCount,
		"memory_usage_pct": float64(len(cc.lastHashes)) / float64(cc.maxEntries) * 100,
	}
}