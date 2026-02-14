package customer

import (
	"sync"

	"dark-deep-new-tool/pkg/elastic"
)

// CustomerInfo tek bir müşterinin bilgilerini tutar
type CustomerInfo struct {
	Consumer     string   // müşteri kodu (cyberarts)
	CustomerName string   // müşteri adı
	ElasticIndex string   // dark-web-monitor-cyberarts
	Keywords     []string // ["marsathletic", "iwallet", ...]
}

// CustomerManager müşteri keyword eşleştirmesini yönetir
type CustomerManager struct {
	elasticClient *elastic.ElasticClient
	customers     map[string]*CustomerInfo // consumer -> info
	keywordMap    map[string]*CustomerInfo // normalized keyword -> info (lookup table)
	mu            sync.RWMutex
}

// NewCustomerManager yeni bir CustomerManager oluşturur
func NewCustomerManager(client *elastic.ElasticClient) *CustomerManager {
	return &CustomerManager{
		elasticClient: client,
		customers:     make(map[string]*CustomerInfo),
		keywordMap:    make(map[string]*CustomerInfo),
	}
}

// GetCustomerCount yüklü müşteri sayısını döndürür
func (cm *CustomerManager) GetCustomerCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.customers)
}

// GetKeywordCount yüklü keyword sayısını döndürür
func (cm *CustomerManager) GetKeywordCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.keywordMap)
}

// GetCustomer belirli bir müşteriyi döndürür
func (cm *CustomerManager) GetCustomer(consumer string) *CustomerInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.customers[consumer]
}