package scraper

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"dark-deep-new-tool/pkg/flaresolverr"
	"dark-deep-new-tool/pkg/models"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	zlog "github.com/rs/zerolog/log"
)

const (
	// Timeout ayarları
	normalTimeout = 10 * time.Second
	onionTimeout  = 180 * time.Second
	maxRetries    = 3

	// Paralel bekleme ayarları
	elementPollInterval = 300 * time.Millisecond
	maxElementWait      = 30 * time.Second
	maxElementWaitOnion = 60 * time.Second
	logInterval         = 10 * time.Second

	// Minimum içerik uzunluğu
	minContentLength = 50
)

// Cloudflare tespit pattern'leri
var cloudflarePatterns = []string{
	"checking your browser",
	"just a moment",
	"cloudflare",
	"ray id:",
	"cf-browser-verification",
	"challenge-platform",
	"turnstile",
	"güvenliğini gözden geçirmesi",
	"insan olduğunuzu doğrulayın",
}

// Whitespace temizleme regex'i
var multipleSpaceRegex = regexp.MustCompile(`[\s\t\n\r]+`)
var multipleNewlineRegex = regexp.MustCompile(`\n{2,}`)

// Scraper web scraping işlemlerini yönetir
type Scraper struct {
	TorClient      *http.Client
	normalBrowser  context.Context
	onionBrowser   context.Context
	normalCancel   context.CancelFunc
	onionCancel    context.CancelFunc
	flareClient    *flaresolverr.Client
	flareAvailable bool
	
	// ✅ YENİ: Browser auto-restart için
	scrapeCount  int64
	restartMutex sync.Mutex
	restartLimit int
}

// ✅ YENİ: buildChromeOptions ortak Chrome ayarlarını döndürür (kod tekrarını önler)
func buildChromeOptions() []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("exclude-switches", "enable-automation"),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("disable-background-networking", false),
		chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-webgl", false),
		chromedp.Flag("disable-reading-from-canvas", false),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"),
		chromedp.WindowSize(1920, 1080),
	}
}

// NewScraperWithBrowsers tek chrome, çoklu sekme ile scraper oluşturur
func NewScraperWithBrowsers(torClient *http.Client) *Scraper {
	// ✅ GÜNCELLENDİ: Helper fonksiyon kullanılıyor
	normalAllocOpts := buildChromeOptions()
	normalAllocCtx, _ := chromedp.NewExecAllocator(context.Background(), normalAllocOpts...)
	normalBrowser, normalCancel := chromedp.NewContext(normalAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	// ✅ GÜNCELLENDİ: Helper fonksiyon kullanılıyor
	onionAllocOpts := append(buildChromeOptions(), chromedp.ProxyServer("socks5://127.0.0.1:9150"))
	onionAllocCtx, _ := chromedp.NewExecAllocator(context.Background(), onionAllocOpts...)
	onionBrowser, onionCancel := chromedp.NewContext(onionAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	flareClient := flaresolverr.NewClient()
	flareAvailable := flareClient.IsAvailable()

	if flareAvailable {
		zlog.Info().Msg("🛡️ FlareSolverr aktif - Cloudflare bypass hazır")
	} else {
		zlog.Warn().Msg("⚠️ FlareSolverr erişilemez - Cloudflare korumalı siteler atlanacak")
	}

	zlog.Info().Msg("🌐 2 Chrome browser başlatıldı (Stealth Mode)")
	zlog.Info().Msg("⚡ Optimizasyon: Paralel yükleme + Cloudflare detection aktif")

	return &Scraper{
		TorClient:      torClient,
		normalBrowser:  normalBrowser,
		onionBrowser:   onionBrowser,
		normalCancel:   normalCancel,
		onionCancel:    onionCancel,
		flareClient:    flareClient,
		flareAvailable: flareAvailable,
		scrapeCount:    0,   // ✅ YENİ
		restartLimit:   100, // ✅ YENİ: Her 100 scrape'te restart
	}
}

// Close tüm browser'ları kapatır
func (s *Scraper) Close() {
	zlog.Info().Msg("🧹 Browser'lar kapatılıyor...")

	if s.normalCancel != nil {
		s.normalCancel()
		zlog.Info().Msg("✅ Normal browser kapatıldı")
	}

	if s.onionCancel != nil {
		s.onionCancel()
		zlog.Info().Msg("✅ Onion browser kapatıldı")
	}
}

// Scrape forumdan veri çeker
func (s *Scraper) Scrape(entry models.ForumEntry, cwd string) (models.Forum, error) {
	// ✅ YENİ: Browser restart kontrolü
	if s.incrementScrapeCount() {
		if err := s.restartBrowsers(); err != nil {
			zlog.Error().Err(err).Msg("❌ Browser restart başarısız")
		}
	}

	forum := models.Forum{
		Source: entry.URL,
	}

	timeout := normalTimeout
	if entry.IsOnion {
		timeout = onionTimeout
		zlog.Info().Str("forum", entry.Name).Msg("🧅 Tor modu aktif")
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		startTime := time.Now()

		zlog.Info().
			Str("forum", entry.Name).
			Int("deneme", attempt).
			Msg("🔄 Tarama başlatılıyor")

		tabCtx, tabCancel := s.createTab(entry.IsOnion, timeout)
		content, author, link, err := s.performScrape(tabCtx, entry, cwd)
		tabCancel()

		elapsed := time.Since(startTime)

		if err == nil && content != "" {
			forum.Content = content
			forum.Author = author
			forum.Link = link

			zlog.Info().
				Str("forum", entry.Name).
				Int("uzunluk", len(content)).
				Dur("süre", elapsed).
				Msg("✅ Veri başarıyla çekildi")

			return forum, nil
		}

		lastErr = err
		zlog.Warn().
			Err(err).
			Str("forum", entry.Name).
			Int("deneme", attempt).
			Dur("süre", elapsed).
			Msg("⚠️ Deneme başarısız")

		if attempt < maxRetries {
			wait := time.Duration(5*attempt) * time.Second
			zlog.Info().Dur("bekleme", wait).Msg("⏳ Yeniden deneme öncesi bekleme")
			time.Sleep(wait)
		}
	}

	zlog.Error().Err(lastErr).Str("forum", entry.Name).Msg("❌ Tarama başarısız")
	return forum, fmt.Errorf("tüm denemeler başarısız: %v", lastErr)
}

// createTab yeni bir tab oluşturur
func (s *Scraper) createTab(isOnion bool, timeout time.Duration) (context.Context, context.CancelFunc) {
	var baseBrowser context.Context

	if isOnion {
		baseBrowser = s.onionBrowser
	} else {
		baseBrowser = s.normalBrowser
	}

	tabCtx, tabCancel := chromedp.NewContext(baseBrowser)
	ctx, timeoutCancel := context.WithTimeout(tabCtx, timeout)

	combinedCancel := func() {
		timeoutCancel()
		tabCancel()
	}

	return ctx, combinedCancel
}

// injectStealthScripts bot detection'ı atlatmak için script inject eder
func (s *Scraper) injectStealthScripts(ctx context.Context) {
	stealth := `
		Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
		Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
		Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en', 'tr']});
		window.chrome = {runtime: {}, loadTimes: function() {}, csi: function() {}, app: {}};
		const originalQuery = window.navigator.permissions.query;
		window.navigator.permissions.query = (parameters) => (
			parameters.name === 'notifications' ?
				Promise.resolve({ state: Notification.permission }) :
				originalQuery(parameters)
		);
	`
	chromedp.Run(ctx, chromedp.Evaluate(stealth, nil))
}

// isCloudflareChallenge HTML içeriğinde Cloudflare challenge olup olmadığını kontrol eder
func (s *Scraper) isCloudflareChallenge(html string) bool {
	htmlLower := strings.ToLower(html)
	for _, pattern := range cloudflarePatterns {
		if strings.Contains(htmlLower, pattern) {
			return true
		}
	}
	return false
}
// ✅ ESKİ HALİNE GERİ DÖN (Fallback logic'siz)
func (s *Scraper) performScrape(ctx context.Context, entry models.ForumEntry, cwd string) (string, string, string, error) {
	s.injectStealthScripts(ctx)

	found, html, err := s.loadPageAndWaitElement(ctx, entry)

	if err != nil || !found {
		if html != "" && s.isCloudflareChallenge(html) {
			zlog.Info().
				Str("forum", entry.Name).
				Msg("🛡️ Cloudflare tespit edildi, FlareSolverr deneniyor...")

			return s.scrapeWithFlareSolverr(ctx, entry, cwd)
		}

		s.saveFailure(ctx, entry.Name, cwd)
		return "", "", "", fmt.Errorf("element bulunamadı: %s - %v", entry.CSSSelector, err)
	}

	content, err := s.extractContent(ctx, entry.CSSSelector)
	if err != nil || content == "" {
		var currentHTML string
		chromedp.Run(ctx, chromedp.OuterHTML("html", &currentHTML))
		if s.isCloudflareChallenge(currentHTML) {
			zlog.Info().
				Str("forum", entry.Name).
				Msg("🛡️ Cloudflare tespit edildi (içerik çekme aşamasında)")

			return s.scrapeWithFlareSolverr(ctx, entry, cwd)
		}

		s.saveFailure(ctx, entry.Name, cwd)
		return "", "", "", fmt.Errorf("içerik çekilemedi: %w", err)
	}

	content = cleanContent(content)
	author := s.extractMetadata(ctx, fmt.Sprintf("%s .username", entry.CSSSelector))
	link := s.extractLink(ctx, entry.CSSSelector)

	return content, author, link, nil
}




func (s *Scraper) scrapeWithFlareSolverr(ctx context.Context, entry models.ForumEntry, cwd string) (string, string, string, error) {
	if !s.flareAvailable {
		return "", "", "", fmt.Errorf("FlareSolverr kullanılamıyor, Cloudflare korumalı site atlanıyor")
	}

	resp, err := s.flareClient.GetPage(ctx, entry.URL)
	if err != nil {
		return "", "", "", fmt.Errorf("FlareSolverr hatası: %w", err)
	}

	html := resp.Solution.Response
	if html == "" {
		return "", "", "", fmt.Errorf("FlareSolverr boş HTML döndü")
	}

	content, author, link := s.parseHTMLContent(html, entry.CSSSelector)

	if content == "" {
		s.saveHTMLForDebug(html, entry.Name, cwd)
		return "", "", "", fmt.Errorf("FlareSolverr HTML'inden içerik çıkarılamadı")
	}

	zlog.Info().
		Str("forum", entry.Name).
		Int("uzunluk", len(content)).
		Msg("✅ FlareSolverr ile veri çekildi")

	return content, author, link, nil
}

// cleanContent içerikteki gereksiz whitespace'leri temizler
func cleanContent(content string) string {
	content = multipleSpaceRegex.ReplaceAllString(content, " ")
	content = multipleNewlineRegex.ReplaceAllString(content, "\n")
	content = strings.TrimSpace(content)

	lines := strings.Split(content, "\n")
	var cleanedLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleanedLines = append(cleanedLines, trimmed)
		}
	}

	return strings.Join(cleanedLines, "\n")
}

// isValidContent içeriğin geçerli olup olmadığını kontrol eder
func isValidContent(content string) bool {
	if len(content) < minContentLength {
		return false
	}

	onlyNumbersSpaces := regexp.MustCompile(`^[\d\s\n]+$`)
	if onlyNumbersSpaces.MatchString(content) {
		return false
	}

	navPatterns := []string{
		"next", "previous", "page", "first", "last",
		"ileri", "geri", "sayfa", "önceki", "sonraki",
	}
	contentLower := strings.ToLower(content)
	navCount := 0
	words := strings.Fields(contentLower)
	for _, word := range words {
		for _, pattern := range navPatterns {
			if word == pattern {
				navCount++
			}
		}
	}
	if len(words) > 0 && float64(navCount)/float64(len(words)) > 0.5 {
		return false
	}

	return true
}

// parseHTMLContent HTML string'inden içerik çıkarır (goquery ile)
func (s *Scraper) parseHTMLContent(html, selector string) (content, author, link string) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		zlog.Warn().Err(err).Msg("HTML parse hatası")
		return "", "", ""
	}

	threadSelectors := []string{
		"div.structItem--thread",
		"div.structItem-title",
		"li.discussionListItem",
		".discussionList .discussionListItem",
		"tr.inline_row",
		"tr.forumdisplay_regular",
		"div.thread_list_item",
		".tborder tr",
		"li.threadbit",
		"div.threadbit",
		".threads .thread",
		"li.ipsDataItem",
		"div.cTopicList",
		"article.thread",
		"div.thread-item",
		"div.topic-item",
		".thread-row",
		".topic-row",
	}

	var selection *goquery.Selection
	var usedSelector string

	simpleSelector := simplifySelector(selector)
	selection = doc.Find(simpleSelector).First()

	if selection.Length() > 0 {
		usedSelector = simpleSelector
	} else {
		for _, altSelector := range threadSelectors {
			selection = doc.Find(altSelector).First()
			if selection.Length() > 0 {
				usedSelector = altSelector
				zlog.Info().
					Str("selector", altSelector).
					Msg("✅ Alternatif selector ile element bulundu")
				break
			}
		}
	}

	if selection == nil || selection.Length() == 0 {
		zlog.Warn().Msg("Hiçbir selector ile element bulunamadı")
		return "", "", ""
	}

	titleSelectors := []string{
		".structItem-title a",
		".subject_new a",
		".subject_old a",
		".threadtitle a",
		".title a",
		"a.topictitle",
		"h3 a",
		"h4 a",
		".thread-title a",
		"a[href*='thread']",
		"a[href*='topic']",
		"a[href*='Thread']",
	}

	var title string
	for _, titleSel := range titleSelectors {
		titleEl := selection.Find(titleSel).First()
		if titleEl.Length() > 0 {
			title = strings.TrimSpace(titleEl.Text())
			if title != "" && len(title) > 10 {
				break
			}
		}
	}

	if title == "" {
		title = selection.Text()
	}

	content = cleanContent(title)

	if !isValidContent(content) {
		zlog.Warn().
			Str("content_preview", truncateString(content, 50)).
			Msg("İçerik geçersiz (pagination veya nav olabilir)")

		selection = doc.Find(usedSelector).Eq(1)
		if selection.Length() > 0 {
			for _, titleSel := range titleSelectors {
				titleEl := selection.Find(titleSel).First()
				if titleEl.Length() > 0 {
					title = strings.TrimSpace(titleEl.Text())
					if title != "" && len(title) > 10 {
						break
					}
				}
			}
			if title == "" {
				title = selection.Text()
			}
			content = cleanContent(title)
		}
	}

	linkSelectors := []string{
		"a[href*='thread']",
		"a[href*='topic']",
		"a[href*='Thread']",
		".structItem-title a",
		".subject_new a",
		".threadtitle a",
		"a",
	}

	for _, linkSel := range linkSelectors {
		linkEl := selection.Find(linkSel).First()
		if linkEl.Length() > 0 {
			link, _ = linkEl.Attr("href")
			if link != "" && !strings.HasPrefix(link, "#") && !strings.Contains(link, "page=") {
				break
			}
		}
	}

	authorSelectors := []string{
		".username",
		".author",
		".posterdate a",
		".message-name a",
		".structItem-minor a",
		"a[href*='member']",
		"a[href*='user']",
		".poster a",
	}

	for _, authorSel := range authorSelectors {
		authorEl := selection.Find(authorSel).First()
		if authorEl.Length() > 0 {
			author = strings.TrimSpace(authorEl.Text())
			if author != "" && len(author) > 1 {
				break
			}
		}
	}

	zlog.Debug().
		Str("selector", usedSelector).
		Int("content_len", len(content)).
		Str("link", link).
		Str("author", author).
		Msg("HTML parse sonucu")

	return content, author, link
}

// simplifySelector karmaşık CSS selector'ı basitleştirir
func simplifySelector(selector string) string {
	result := selector

	for strings.Contains(result, ":nth-child") {
		start := strings.Index(result, ":nth-child")
		end := strings.Index(result[start:], ")")
		if end != -1 {
			result = result[:start] + result[start+end+1:]
		} else {
			break
		}
	}

	result = strings.ReplaceAll(result, " > ", " ")
	result = strings.ReplaceAll(result, ">", " ")

	for strings.Contains(result, "  ") {
		result = strings.ReplaceAll(result, "  ", " ")
	}

	return strings.TrimSpace(result)
}

// truncateString string'i belirtilen uzunlukta keser
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// loadPageAndWaitElement sayfa yüklerken aynı anda element arar (PARALEL)
func (s *Scraper) loadPageAndWaitElement(ctx context.Context, entry models.ForumEntry) (bool, string, error) {
	startTime := time.Now()

	maxWait := maxElementWait
	if entry.IsOnion {
		maxWait = maxElementWaitOnion
	}

	zlog.Info().
		Str("url", entry.URL).
		Dur("max_süre", maxWait).
		Msg("🚀 Paralel yükleme başlatıldı")

	navigateDone := make(chan error, 1)
	go func() {
		err := chromedp.Run(ctx, chromedp.Navigate(entry.URL))
		navigateDone <- err
	}()

	deadline := time.Now().Add(maxWait)
	query := fmt.Sprintf(`document.querySelectorAll('%s').length`, entry.CSSSelector)

	var lastLogTime time.Time
	attemptCount := 0
	elementFound := false
	var pageHTML string

	time.Sleep(2 * time.Second)
	s.injectStealthScripts(ctx)

	for time.Now().Before(deadline) {
		attemptCount++

		var count int
		err := chromedp.Run(ctx, chromedp.Evaluate(query, &count))

		if err == nil && count > 0 {
			elementFound = true
			zlog.Info().
				Int("element_sayısı", count).
				Int("deneme", attemptCount).
				Dur("süre", time.Since(startTime)).
				Msg("✅ Element bulundu")
			break
		}

		if attemptCount%10 == 0 {
			chromedp.Run(ctx, chromedp.OuterHTML("html", &pageHTML))
			if s.isCloudflareChallenge(pageHTML) {
				zlog.Debug().Msg("🛡️ Cloudflare challenge tespit edildi")
				return false, pageHTML, fmt.Errorf("cloudflare challenge")
			}
		}

		if time.Since(lastLogTime) >= logInterval {
			elapsed := time.Since(startTime)
			remaining := maxWait - elapsed
			zlog.Debug().
				Dur("geçen", elapsed).
				Dur("kalan", remaining).
				Int("deneme", attemptCount).
				Msg("⏳ Element aranıyor...")
			lastLogTime = time.Now()
		}

		time.Sleep(elementPollInterval)
	}

	select {
	case navErr := <-navigateDone:
		if navErr != nil && !strings.Contains(navErr.Error(), "timeout") {
			zlog.Debug().Err(navErr).Msg("Navigate tamamlandı")
		}
	default:
	}

	totalTime := time.Since(startTime)

	if !elementFound {
		chromedp.Run(ctx, chromedp.OuterHTML("html", &pageHTML))

		zlog.Warn().
			Str("selector", entry.CSSSelector).
			Int("toplam_deneme", attemptCount).
			Dur("toplam_süre", totalTime).
			Msg("❌ Element bulunamadı (timeout)")
		return false, pageHTML, fmt.Errorf("element %v sürede bulunamadı", maxWait)
	}

	zlog.Info().
		Dur("toplam_süre", totalTime).
		Msg("🏁 Yükleme tamamlandı")

	return true, "", nil
}

// extractContent içeriği çeker
func (s *Scraper) extractContent(ctx context.Context, selector string) (string, error) {
	var content string

	if err := chromedp.Run(ctx,
		chromedp.Text(selector, &content, chromedp.ByQuery, chromedp.NodeVisible),
	); err == nil && content != "" {
		return strings.TrimSpace(content), nil
	}

	query := fmt.Sprintf(`document.querySelector('%s')?.innerText || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &content)); err == nil && content != "" {
		return strings.TrimSpace(content), nil
	}

	query = fmt.Sprintf(`document.querySelector('%s')?.textContent || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &content)); err == nil && content != "" {
		return strings.TrimSpace(content), nil
	}

	return "", fmt.Errorf("içerik çekilemedi")
}

// extractMetadata metadata çeker
func (s *Scraper) extractMetadata(ctx context.Context, selector string) string {
	var data string
	chromedp.Run(ctx, chromedp.Text(selector, &data, chromedp.ByQuery))
	return strings.TrimSpace(data)
}

// extractLink link çeker (çoklu yöntem ile)
func (s *Scraper) extractLink(ctx context.Context, selector string) string {
	var link string

	query := fmt.Sprintf(`document.querySelector('%s a')?.getAttribute('href') || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &link)); err == nil && link != "" {
		return link
	}

	query = fmt.Sprintf(`document.querySelector('%s')?.getAttribute('href') || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &link)); err == nil && link != "" {
		return link
	}

	query = fmt.Sprintf(`document.querySelector('%s')?.getAttribute('data-href') || document.querySelector('%s a')?.getAttribute('data-href') || ''`, selector, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &link)); err == nil && link != "" {
		return link
	}

	chromedp.Run(ctx, chromedp.AttributeValue(fmt.Sprintf("%s a", selector), "href", &link, nil, chromedp.ByQuery))

	return link
}

// saveFailure hata diagnostics kaydeder
func (s *Scraper) saveFailure(ctx context.Context, forumName string, cwd string) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	failureDir := filepath.Join(cwd, "output", "failure")

	if err := os.MkdirAll(failureDir, 0755); err != nil {
		return
	}

	var buf []byte
	if err := chromedp.Run(ctx, chromedp.FullScreenshot(&buf, 90)); err == nil && len(buf) > 0 {
		path := filepath.Join(failureDir, fmt.Sprintf("%s_%s.png", forumName, timestamp))
		os.WriteFile(path, buf, 0644)
		zlog.Debug().Str("dosya", filepath.Base(path)).Msg("🔧 Failure screenshot kaydedildi")
	}

	var html string
	if err := chromedp.Run(ctx, chromedp.OuterHTML("html", &html)); err == nil && html != "" {
		path := filepath.Join(failureDir, fmt.Sprintf("%s_%s.html", forumName, timestamp))
		os.WriteFile(path, []byte(html), 0644)
		zlog.Debug().Str("dosya", filepath.Base(path)).Msg("🔧 Failure HTML kaydedildi")
	}
}

// saveHTMLForDebug FlareSolverr HTML'ini debug için kaydeder
func (s *Scraper) saveHTMLForDebug(html, forumName, cwd string) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	debugDir := filepath.Join(cwd, "output", "debug")

	if err := os.MkdirAll(debugDir, 0755); err != nil {
		return
	}

	path := filepath.Join(debugDir, fmt.Sprintf("%s_flare_%s.html", forumName, timestamp))
	os.WriteFile(path, []byte(html), 0644)
	zlog.Debug().Str("dosya", filepath.Base(path)).Msg("🔧 FlareSolverr HTML kaydedildi")
}

// ✅ YENİ: incrementScrapeCount scrape sayısını artırır ve restart gerekip gerekmediğini döner
func (s *Scraper) incrementScrapeCount() bool {
	s.restartMutex.Lock()
	defer s.restartMutex.Unlock()

	s.scrapeCount++

	if s.scrapeCount >= int64(s.restartLimit) {
		s.scrapeCount = 0
		return true
	}

	return false
}

// ✅ YENİ: restartBrowsers browser'ları kapat-aç (memory temizliği)
func (s *Scraper) restartBrowsers() error {
	zlog.Info().
		Int("limit", s.restartLimit).
		Msg("🔄 Browser restart başlatılıyor (memory cleanup)")

	if s.normalCancel != nil {
		s.normalCancel()
	}
	if s.onionCancel != nil {
		s.onionCancel()
	}

	time.Sleep(2 * time.Second)

	normalAllocOpts := buildChromeOptions()
	normalAllocCtx, _ := chromedp.NewExecAllocator(context.Background(), normalAllocOpts...)
	s.normalBrowser, s.normalCancel = chromedp.NewContext(normalAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	onionAllocOpts := append(buildChromeOptions(), chromedp.ProxyServer("socks5://127.0.0.1:9150"))
	onionAllocCtx, _ := chromedp.NewExecAllocator(context.Background(), onionAllocOpts...)
	s.onionBrowser, s.onionCancel = chromedp.NewContext(onionAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	zlog.Info().Msg("✅ Browser restart tamamlandı")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	zlog.Info().
		Uint64("alloc_mb", m.Alloc/1024/1024).
		Uint64("sys_mb", m.Sys/1024/1024).
		Msg("📊 Restart sonrası memory")

	return nil
}