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
// Format: "2025-10-12T17:30:45.552Z"
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

// LastContentStore son çekilen içeriklerin hash'lerini saklar
type LastContentStore struct {
	Hashes map[string]string `json:"hashes"`
}

// ContentChecker içerik karşılaştırma (Link + Normalized Content + SHA-256 Hash)
type ContentChecker struct {
	lastHashes   map[string]string
	mu           sync.RWMutex
	filePath     string
	dynamicRegex *regexp.Regexp
}

// NewContentChecker yeni bir checker oluşturur
func NewContentChecker(filePath string) *ContentChecker {
	// Dinamik içerik pattern'leri (normalize edilecek)
	dynamicPattern := `(?i)(` +
		// ==================== COUNTDOWN / TIMER ====================
		`\d+\s*D\s*\d+\s*H\s*\d+\s*M\s*\d+\s*S|` + // 9 D 1 H 44 M 4 S
		`\d+\s*d\s*\d+\s*h\s*\d+\s*m\s*\d+\s*s|` + // 9d 1h 44m 4s
		`\d+\s*days?\s*\d+\s*hours?\s*\d+\s*min(ute)?s?\s*\d+\s*sec(ond)?s?|` + // 9 days 1 hour 44 min
		`\d+\s*days?\s*\d+\s*hours?\s*\d+\s*min(ute)?s?|` + // 9 days 1 hour 44 min
		`\d+\s*days?\s*\d+\s*hours?|` + // 9 days 1 hour
		`\d+\s*h\s*\d+\s*m\s*\d+\s*s|` + // 1h 44m 30s
		`\d+\s*h\s*\d+\s*m|` + // 1h 44m
		`\d+:\d+:\d+:\d+|` + // 9:01:44:04 (D:H:M:S)
		`\d+:\d+:\d+|` + // 01:44:04 (H:M:S)
		`time\s*left[:\s]*[^,\n]+|` + // Time left: 9 days
		`expires?\s*in[:\s]*[^,\n]+|` + // Expires in 9 days
		`deadline[:\s]*[^,\n]+|` + // Deadline: 9 days
		`countdown[:\s]*[^,\n]+|` + // Countdown: ...

		// ==================== TARİH / SAAT ====================
		`\d{1,2}:\d{2}:\d{2}\s*(am|pm)?|` + // 14:30:45 veya 2:30:45 PM
		`\d{1,2}:\d{2}\s*(am|pm)?|` + // 14:30 veya 2:30 PM
		`\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}|` + // 06.12.2025 20:14:26
		`\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}|` + // 06.12.2025 20:14
		`\d{2}\.\d{2}\.\d{4}|` + // 06.12.2025
		`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}|` + // 12/06/2025 20:14:26
		`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}|` + // 12/06/2025 20:14
		`\d{1,2}/\d{1,2}/\d{2,4}|` + // 12/6/25 veya 12/06/2025
		`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|` + // 2025-12-06T20:14:26 (ISO)
		`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|` + // 2025-12-06 20:14:26
		`\d{4}-\d{2}-\d{2}|` + // 2025-12-06

		// ==================== GÖRECELİ ZAMAN ====================
		`\d+\s+(second|minute|hour|day|week|month|year)s?\s+ago|` + // 5 minutes ago
		`\d+\s*(sec|min|hr|wk|mo|yr)s?\s+ago|` + // 5 min ago
		`a\s+(second|minute|hour|day|week|month|year)\s+ago|` + // a minute ago
		`a\s+moment\s+ago|just\s+now|moments?\s+ago|` + // just now
		`yesterday|today|tomorrow|` + // yesterday
		`last\s+(week|month|year)|` + // last week
		`\d+\s*(seconds?|minutes?|hours?|days?|weeks?|months?|years?)\s*ago|` +
		`(an?|one|\d+)\s+hours?\s+ago|` + // an hour ago
		`recently|just\s+posted|new|updated|` + // recently

		// ==================== FORUM METRİKLERİ ====================
		`views?\s*[:\-]?\s*[\d,\.]+\s*[km]?|` + // Views: 1,234 veya Views: 1.2k
		`[\d,\.]+\s*[km]?\s*views?|` + // 1,234 views
		`replies?\s*[:\-]?\s*[\d,\.]+|` + // Replies: 50
		`[\d,\.]+\s*replies?|` + // 50 replies
		`likes?\s*[:\-]?\s*[\d,\.]+|` + // Likes: 100
		`[\d,\.]+\s*likes?|` + // 100 likes
		`comments?\s*[:\-]?\s*[\d,\.]+|` + // Comments: 25
		`[\d,\.]+\s*comments?|` + // 25 comments
		`reactions?\s*[:\-]?\s*[\d,\.]+|` + // Reactions: 10
		`[\d,\.]+\s*reactions?|` + // 10 reactions
		`posts?\s*[:\-]?\s*[\d,\.]+|` + // Posts: 500
		`[\d,\.]+\s*posts?|` + // 500 posts
		`members?\s*[:\-]?\s*[\d,\.]+|` + // Members: 1000
		`[\d,\.]+\s*members?|` + // 1000 members
		`threads?\s*[:\-]?\s*[\d,\.]+|` + // Threads: 200
		`[\d,\.]+\s*threads?|` + // 200 threads
		`messages?\s*[:\-]?\s*[\d,\.]+|` + // Messages: 50
		`[\d,\.]+\s*messages?|` + // 50 messages
		`users?\s*online[:\s]*[\d,\.]+|` + // Users online: 50
		`[\d,\.]+\s*users?\s*online|` + // 50 users online
		`online[:\s]*[\d,\.]+|` + // Online: 50
		`visitors?[:\s]*[\d,\.]+|` + // Visitors: 100
		`[\d,\.]+\s*visitors?|` + // 100 visitors
		`downloads?\s*[:\-]?\s*[\d,\.]+|` + // Downloads: 500
		`[\d,\.]+\s*downloads?|` + // 500 downloads
		`shares?\s*[:\-]?\s*[\d,\.]+|` + // Shares: 25
		`[\d,\.]+\s*shares?|` + // 25 shares
		`ratings?\s*[:\-]?\s*[\d,\.]+|` + // Rating: 4.5
		`[\d,\.]+\s*ratings?|` + // 4.5 rating
		`votes?\s*[:\-]?\s*[\d,\.]+|` + // Votes: 100
		`[\d,\.]+\s*votes?|` + // 100 votes
		`reputation\s*[:\-]?\s*[\d,\.]+|` + // Reputation: 500
		`rep\s*[:\-]?\s*[\d,\.]+|` + // Rep: 500
		`karma\s*[:\-]?\s*[\d,\.]+|` + // Karma: 100
		`points?\s*[:\-]?\s*[\d,\.]+|` + // Points: 250
		`[\d,\.]+\s*points?|` + // 250 points
		`credits?\s*[:\-]?\s*[\d,\.]+|` + // Credits: 100
		`[\d,\.]+\s*credits?|` + // 100 credits

		// ==================== RANSOMWARE / LEAK SPESİFİK ====================
		`disclosures?\s*\d+/\d+|` + // Disclosures 0/2
		`\d+/\d+\s*disclosures?|` + // 0/2 disclosures
		`victims?\s*[:\-]?\s*[\d,\.]+|` + // Victims: 50
		`[\d,\.]+\s*victims?|` + // 50 victims
		`files?\s*encrypted[:\s]*[\d,\.]+|` + // Files encrypted: 1000
		`encrypted\s*files?[:\s]*[\d,\.]+|` + // Encrypted files: 1000
		`data\s*size[:\s]*[\d,\.]+\s*(gb|tb|mb|kb|bytes?)?|` + // Data size: 500 GB
		`[\d,\.]+\s*(gb|tb|mb|kb)\s*data|` + // 500 GB data
		`~?\s*[\d,\.]+\s*(gb|tb|mb|kb)\s*(data|total)?|` + // ~500 GB total
		`total\s*size[:\s]*[\d,\.]+\s*(gb|tb|mb|kb)?|` + // Total size: 500 GB
		`price[:\s]*\$?[\d,\.]+|` + // Price: $50000
		`ransom[:\s]*\$?[\d,\.]+|` + // Ransom: $50000
		`payment[:\s]*\$?[\d,\.]+|` + // Payment: $50000
		`amount[:\s]*\$?[\d,\.]+|` + // Amount: $50000
		`\$[\d,\.]+\s*(usd|btc)?|` + // $50,000 USD
		`[\d,\.]+\s*(usd|btc|xmr|eth)|` + // 50000 USD
		`published[:\s]*\d+|` + // Published: 5
		`leaked[:\s]*\d+|` + // Leaked: 5

		// ==================== SAYFA / INDEX ====================
		`page\s*\d+\s*(of\s*\d+)?|` + // Page 1 of 10
		`\d+\s*of\s*\d+|` + // 1 of 10
		`showing\s*\d+\s*-\s*\d+|` + // Showing 1 - 10
		`#\d+|` + // #123

		// ==================== KULLANICI DURUMU ====================
		`last\s*seen[:\s]*[^,\n]+|` + // Last seen: 5 min ago
		`last\s*active[:\s]*[^,\n]+|` + // Last active: today
		`last\s*visit[:\s]*[^,\n]+|` + // Last visit: yesterday
		`last\s*login[:\s]*[^,\n]+|` + // Last login: 2 days ago
		`(currently\s*)?(online|offline|away|busy|idle)|` + // Online/Offline
		`status[:\s]*(online|offline|away|busy|idle)|` + // Status: Online
		`active\s*now|` + // Active now

		// ==================== DOSYA / VERİ BOYUTU ====================
		`[\d,\.]+\s*(bytes?|kb|mb|gb|tb|pb)|` + // 500 MB
		`size[:\s]*[\d,\.]+\s*(bytes?|kb|mb|gb|tb)?|` + // Size: 500 MB
		`length[:\s]*[\d,\.]+|` + // Length: 500
		`duration[:\s]*[\d:]+|` + // Duration: 5:30
		`[\d:]+\s*duration` + // 5:30 duration
		`)`

	return &ContentChecker{
		lastHashes:   make(map[string]string),
		filePath:     filePath,
		dynamicRegex: regexp.MustCompile(dynamicPattern),
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

// makeKey composite key oluşturur (source + link)
func (cc *ContentChecker) makeKey(source, link string) string {
	if link == "" {
		return source
	}
	return source + "|" + link
}

// IsDuplicate içeriğin değişip değişmediğini kontrol eder
func (cc *ContentChecker) IsDuplicate(source, link, content string) bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	newHash := cc.computeHash(content)

	// 1. Önce tam key ile kontrol et (source + link)
	if link != "" {
		key := cc.makeKey(source, link)
		if lastHash, exists := cc.lastHashes[key]; exists {
			if newHash == lastHash {
				return true
			}
		}
	}

	// 2. Sadece source ile kontrol et (link boş olabilir)
	if lastHash, exists := cc.lastHashes[source]; exists {
		if newHash == lastHash {
			return true
		}
	}

	// 3. Content hash ile tüm değerleri tara (ekstra güvenlik)
	for _, existingHash := range cc.lastHashes {
		if existingHash == newHash {
			return true
		}
	}

	return false
}

// Update içeriği günceller ve hash'i saklar
func (cc *ContentChecker) Update(source, link, content string) string {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	hash := cc.computeHash(content)

	// Her iki key'e de kaydet (link varsa)
	if link != "" {
		key := cc.makeKey(source, link)
		cc.lastHashes[key] = hash
	}

	// Source-only key'e de kaydet (fallback için)
	cc.lastHashes[source] = hash

	return hash
}

// Count kayıtlı URL+Link sayısını döner
func (cc *ContentChecker) Count() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return len(cc.lastHashes)
}

// SaveToFile son hash'leri dosyaya kaydeder
func (cc *ContentChecker) SaveToFile() error {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	store := LastContentStore{
		Hashes: cc.lastHashes,
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

// LoadFromFile son hash'leri dosyadan yükler
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

	// Eski format kontrolü (backward compatibility)
	if store.Hashes == nil {
		var oldStore struct {
			Contents map[string]string `json:"contents"`
		}
		if err := json.Unmarshal(data, &oldStore); err == nil && oldStore.Contents != nil {
			cc.lastHashes = make(map[string]string)
			for key, content := range oldStore.Contents {
				cc.lastHashes[key] = cc.computeHash(content)
			}
			return nil
		}
	}

	cc.lastHashes = store.Hashes
	if cc.lastHashes == nil {
		cc.lastHashes = make(map[string]string)
	}

	return nil
}
