package customer

import (
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// MatchResult eşleşme sonucunu tutar
type MatchResult struct {
	Matched      bool            // eşleşme var mı
	Customers    []*CustomerInfo // eşleşen müşteriler
	IndexTargets []string        // yazılacak index'ler
}

// Match verilen title'da müşteri keyword'ü arar
// Eşleşme varsa müşteri index'lerini, yoksa ana index'i döndürür
func (cm *CustomerManager) Match(title string) *MatchResult {
	result := &MatchResult{
		Matched:      false,
		Customers:    make([]*CustomerInfo, 0),
		IndexTargets: make([]string, 0),
	}

	if title == "" {
		result.IndexTargets = append(result.IndexTargets, "dark-web-monitor")
		return result
	}

	// Title'ı normalize et
	normalizedTitle := normalizeText(title)

	// Eşleşen müşterileri bul (duplicate önlemek için map kullan)
	matchedCustomers := make(map[string]*CustomerInfo)

	cm.mu.RLock()
	for keyword, customerInfo := range cm.keywordMap {
		// Keyword title içinde geçiyor mu?
		if strings.Contains(normalizedTitle, keyword) {
			// Aynı müşteriyi tekrar ekleme
			if _, exists := matchedCustomers[customerInfo.Consumer]; !exists {
				matchedCustomers[customerInfo.Consumer] = customerInfo
			}
		}
	}
	cm.mu.RUnlock()

	// Sonuçları oluştur
	if len(matchedCustomers) > 0 {
		result.Matched = true
		for _, info := range matchedCustomers {
			result.Customers = append(result.Customers, info)
			result.IndexTargets = append(result.IndexTargets, info.ElasticIndex)
		}
	} else {
		// Eşleşme yok - ana index'e yaz
		result.IndexTargets = append(result.IndexTargets, "dark-web-monitor")
	}

	return result
}

// normalizeText metni arama için normalize eder
// - Küçük harfe çevir
// - Türkçe karakterleri ASCII'ye çevir (ğ->g, ü->u, ş->s, ı->i, ö->o, ç->c)
// - Fazla boşlukları temizle
func normalizeText(text string) string {
	// Küçük harfe çevir
	text = strings.ToLower(text)

	// Türkçe karakterleri manuel dönüştür (daha güvenilir)
	turkishMap := map[rune]rune{
		'ğ': 'g',
		'Ğ': 'g',
		'ü': 'u',
		'Ü': 'u',
		'ş': 's',
		'Ş': 's',
		'ı': 'i',
		'I': 'i',
		'İ': 'i',
		'ö': 'o',
		'Ö': 'o',
		'ç': 'c',
		'Ç': 'c',
	}

	var builder strings.Builder
	for _, r := range text {
		if replacement, ok := turkishMap[r]; ok {
			builder.WriteRune(replacement)
		} else {
			builder.WriteRune(r)
		}
	}
	text = builder.String()

	// Unicode normalization (aksanları kaldır)
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	normalized, _, _ := transform.String(t, text)

	// Fazla boşlukları temizle
	normalized = strings.Join(strings.Fields(normalized), " ")

	return normalized
}

// MatchWithDetails eşleşme detaylarını loglamak için kullanılır
func (cm *CustomerManager) MatchWithDetails(title string) (*MatchResult, []string) {
	result := cm.Match(title)

	var matchedKeywords []string
	if result.Matched {
		normalizedTitle := normalizeText(title)

		cm.mu.RLock()
		for keyword := range cm.keywordMap {
			if strings.Contains(normalizedTitle, keyword) {
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
		cm.mu.RUnlock()
	}

	return result, matchedKeywords
}