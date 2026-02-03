package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
	minContentLength = 10
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

// ScrapedData scraper'dan dönen ham veri
type ScrapedData struct {
	Name     string
	Source   string
	ThreadID string
	Title    string
	Author   string
	Link     string
}

// Scraper web scraping işlemlerini yönetir
type Scraper struct {
	TorClient         *http.Client
	normalBrowser     context.Context
	onionBrowser      context.Context
	normalCancel      context.CancelFunc
	onionCancel       context.CancelFunc
	normalAllocCancel context.CancelFunc
	onionAllocCancel  context.CancelFunc
	flareClient       *flaresolverr.Client
	flareAvailable    bool

	// Browser auto-restart için
	scrapeCount  int64
	restartMutex sync.Mutex
	restartLimit int
}

// buildChromeOptions ortak Chrome ayarlarını döndürür
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
	normalAllocOpts := buildChromeOptions()
	normalAllocCtx, normalAllocCancel := chromedp.NewExecAllocator(context.Background(), normalAllocOpts...)
	normalBrowser, normalCancel := chromedp.NewContext(normalAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	onionAllocOpts := append(buildChromeOptions(), chromedp.ProxyServer("socks5://127.0.0.1:9150"))
	onionAllocCtx, onionAllocCancel := chromedp.NewExecAllocator(context.Background(), onionAllocOpts...)
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
		TorClient:         torClient,
		normalBrowser:     normalBrowser,
		onionBrowser:      onionBrowser,
		normalCancel:      normalCancel,
		onionCancel:       onionCancel,
		normalAllocCancel: normalAllocCancel,
		onionAllocCancel:  onionAllocCancel,
		flareClient:       flareClient,
		flareAvailable:    flareAvailable,
		scrapeCount:       0,
		restartLimit:      100,
	}
}

// Close tüm browser'ları kapatır
func (s *Scraper) Close() {
	zlog.Info().Msg("🧹 Browser'lar kapatılıyor...")

	// Önce tab context'leri kapat
	if s.normalCancel != nil {
		s.normalCancel()
		zlog.Info().Msg("✅ Normal browser context kapatıldı")
	}

	if s.onionCancel != nil {
		s.onionCancel()
		zlog.Info().Msg("✅ Onion browser context kapatıldı")
	}

	// Sonra allocator'ları kapat (Chrome process'leri tamamen öldürür)
	if s.normalAllocCancel != nil {
		s.normalAllocCancel()
		zlog.Info().Msg("✅ Normal Chrome process sonlandırıldı")
	}

	if s.onionAllocCancel != nil {
		s.onionAllocCancel()
		zlog.Info().Msg("✅ Onion Chrome process sonlandırıldı")
	}
}

// Scrape forumdan veri çeker
func (s *Scraper) Scrape(entry models.ForumEntry, cwd string) (ScrapedData, error) {
	// Browser restart kontrolü
	if s.incrementScrapeCount() {
		if err := s.restartBrowsers(); err != nil {
			zlog.Error().Err(err).Msg("❌ Browser restart başarısız")
		}
	}

	data := ScrapedData{
		Name:   entry.Name,
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
		scraped, err := s.performScrape(tabCtx, entry, cwd)
		tabCancel()

		elapsed := time.Since(startTime)

		if err == nil && scraped.Link != "" {
			// Absolute URL'e çevir
			scraped.Link = buildAbsoluteURL(entry.URL, scraped.Link)
			scraped.Name = entry.Name
			scraped.Source = entry.URL

			zlog.Info().
				Str("forum", entry.Name).
				Str("title", truncateString(scraped.Title, 50)).
				Str("link", scraped.Link).
				Dur("süre", elapsed).
				Msg("✅ Veri başarıyla çekildi")

			return scraped, nil
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
	return data, fmt.Errorf("tüm denemeler başarısız: %v", lastErr)
}

// buildAbsoluteURL relative URL'i absolute URL'e çevirir
func buildAbsoluteURL(baseURL, relativeURL string) string {
	// Zaten absolute ise dokunma
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}

	// Base URL'i parse et
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}

	// Relative URL'i parse et
	rel, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}

	// Birleştir
	absolute := base.ResolveReference(rel)
	return absolute.String()
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

// performScrape asıl scraping işlemini gerçekleştirir
func (s *Scraper) performScrape(ctx context.Context, entry models.ForumEntry, cwd string) (ScrapedData, error) {
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
		return ScrapedData{}, fmt.Errorf("element bulunamadı: %s - %v", entry.CSSSelector, err)
	}

	// Veriyi çek (hibrit sistem: explicit selectors varsa kullan, yoksa otomatik)
	data, err := s.extractData(ctx, entry)
	if err != nil || data.Link == "" {
		var currentHTML string
		chromedp.Run(ctx, chromedp.OuterHTML("html", &currentHTML))
		if s.isCloudflareChallenge(currentHTML) {
			zlog.Info().
				Str("forum", entry.Name).
				Msg("🛡️ Cloudflare tespit edildi (içerik çekme aşamasında)")

			return s.scrapeWithFlareSolverr(ctx, entry, cwd)
		}

		s.saveFailure(ctx, entry.Name, cwd)
		return ScrapedData{}, fmt.Errorf("link çekilemedi: %w", err)
	}

	data.Author = cleanAuthor(data.Author)
	

	return data, nil
}

// extractData hibrit sistem ile veri çeker
func (s *Scraper) extractData(ctx context.Context, entry models.ForumEntry) (ScrapedData, error) {
	// Explicit selectors varsa onları kullan
	if entry.Selectors != nil {
		return s.extractWithExplicitSelectors(ctx, entry)
	}

	// Otomatik detection
	return s.extractWithAutoDetection(ctx, entry)
}

// extractWithExplicitSelectors explicit selector'larla veri çeker
func (s *Scraper) extractWithExplicitSelectors(ctx context.Context, entry models.ForumEntry) (ScrapedData, error) {
	data := ScrapedData{}
	sel := entry.Selectors
	baseSelector := entry.CSSSelector

	// Link (zorunlu)
	if sel.Link != "" {
		fullSelector := fmt.Sprintf("%s %s", baseSelector, sel.Link)
		data.Link = s.extractAttribute(ctx, fullSelector, "href")
	}

	// Title
	if sel.Title != "" {
		fullSelector := fmt.Sprintf("%s %s", baseSelector, sel.Title)
		data.Title = s.extractText(ctx, fullSelector)
	}

	// Author
	if sel.Author != "" {
		fullSelector := fmt.Sprintf("%s %s", baseSelector, sel.Author)
		data.Author = s.extractText(ctx, fullSelector)
	}


	// ThreadID (link'ten çıkar)
	data.ThreadID = extractThreadIDFromLink(data.Link)

	// Title cleanup
	data.Title = cleanContent(data.Title)
	data.Author = cleanContent(data.Author)

	return data, nil
}

// extractWithAutoDetection otomatik detection ile veri çeker
func (s *Scraper) extractWithAutoDetection(ctx context.Context, entry models.ForumEntry) (ScrapedData, error) {
	data := ScrapedData{}
	selector := entry.CSSSelector

	// Link çek (öncelikli)
	data.Link = s.extractLink(ctx, selector)

	// Title çek
	data.Title = s.extractTitle(ctx, selector)

	// Author çek
	data.Author = s.extractAuthor(ctx, selector)

	// ThreadID
	data.ThreadID = extractThreadIDFromLink(data.Link)

	return data, nil
}

// extractText CSS selector'dan text çeker
func (s *Scraper) extractText(ctx context.Context, selector string) string {
	var text string

	// Önce innerText dene
	query := fmt.Sprintf(`document.querySelector('%s')?.innerText || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &text)); err == nil && text != "" {
		return strings.TrimSpace(text)
	}

	// textContent dene
	query = fmt.Sprintf(`document.querySelector('%s')?.textContent || ''`, selector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &text)); err == nil && text != "" {
		return strings.TrimSpace(text)
	}

	return ""
}

// extractAttribute CSS selector'dan attribute çeker
func (s *Scraper) extractAttribute(ctx context.Context, selector, attr string) string {
	var value string
	query := fmt.Sprintf(`document.querySelector('%s')?.getAttribute('%s') || ''`, selector, attr)
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &value)); err == nil {
		return strings.TrimSpace(value)
	}
	return ""
}

// extractNumber CSS selector'dan sayı çeker
func (s *Scraper) extractNumber(ctx context.Context, selector string) int {
	text := s.extractText(ctx, selector)
	if text == "" {
		return 0
	}

	// Sadece sayıları al
	re := regexp.MustCompile(`[\d,]+`)
	match := re.FindString(text)
	if match == "" {
		return 0
	}

	// Virgülleri kaldır ve parse et
	match = strings.ReplaceAll(match, ",", "")
	num, _ := strconv.Atoi(match)
	return num
}

// extractLink link çeker (otomatik detection)
func (s *Scraper) extractLink(ctx context.Context, selector string) string {
	linkSelectors := []string{
		"a[href*='thread']",
		"a[href*='Thread']",
		"a[href*='topic']",
		"a[href*='Topic']",
		".structItem-title a",
		".subject_new a",
		".subject_old a",
		".threadtitle a",
		".title a",
		"a.topictitle",
		"h3 a",
		"h4 a",
		"a",
	}

	for _, linkSel := range linkSelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, linkSel)
		link := s.extractAttribute(ctx, fullSelector, "href")
		if link != "" && !strings.HasPrefix(link, "#") && !strings.Contains(link, "page=") {
			return link
		}
	}

	// Direkt selector'da href ara
	link := s.extractAttribute(ctx, selector, "href")
	if link != "" {
		return link
	}

	return ""
}

// extractTitle title çeker (otomatik detection)
func (s *Scraper) extractTitle(ctx context.Context, selector string) string {
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
		"a[href*='Thread']",
	}

	for _, titleSel := range titleSelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, titleSel)
		title := s.extractText(ctx, fullSelector)
		if title != "" && len(title) > minContentLength {
			return cleanContent(title)
		}
	}

	// Fallback: tüm text'i al
	text := s.extractText(ctx, selector)
	return cleanContent(text)
}

// extractAuthor author çeker (otomatik detection)
func (s *Scraper) extractAuthor(ctx context.Context, selector string) string {
	authorSelectors := []string{
		".username",
		".author",
		".posterdate a",
		".message-name a",
		".structItem-minor a",
		"a[href*='member']",
		"a[href*='user']",
		"a[href*='profile']",
		".poster a",
		".by a",
	}

	for _, authorSel := range authorSelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, authorSel)
		author := s.extractText(ctx, fullSelector)
		if author != "" && len(author) > 1 && len(author) < 50 {
			return cleanContent(author)
		}
	}

	return ""
}

// extractPostedAt posted time çeker (otomatik detection)
func (s *Scraper) extractPostedAt(ctx context.Context, selector string) string {
	timeSelectors := []string{
		".structItem-latestDate",
		".structItem-startDate",
		".lastpost",
		".posted_at",
		".datetime",
		".date",
		"time",
		".time",
		".timestamp",
		".post-date",
		".thread-date",
	}

	for _, timeSel := range timeSelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, timeSel)
		posted := s.extractText(ctx, fullSelector)
		if posted != "" && len(posted) > 3 {
			return cleanContent(posted)
		}
	}

	return ""
}

// extractViews view count çeker (otomatik detection)
func (s *Scraper) extractViews(ctx context.Context, selector string) int {
	viewSelectors := []string{
		".structItem-cell--meta dd:nth-child(2)",
		".views",
		".view-count",
		".threadviews",
		"[title*='view']",
		"[title*='View']",
	}

	for _, viewSel := range viewSelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, viewSel)
		views := s.extractNumber(ctx, fullSelector)
		if views > 0 {
			return views
		}
	}

	return 0
}

// extractReplies reply count çeker (otomatik detection)
func (s *Scraper) extractReplies(ctx context.Context, selector string) int {
	replySelectors := []string{
		".structItem-cell--meta dd:first-child",
		".replies",
		".reply-count",
		".threadreplies",
		"[title*='repl']",
		"[title*='Repl']",
	}

	for _, replySel := range replySelectors {
		fullSelector := fmt.Sprintf("%s %s", selector, replySel)
		replies := s.extractNumber(ctx, fullSelector)
		if replies > 0 {
			return replies
		}
	}

	return 0
}

// extractThreadIDFromLink link'ten thread ID çıkarır
func extractThreadIDFromLink(link string) string {
	if link == "" {
		return ""
	}

	// Pattern'ler: tid_123, thread-123, threads/123, Thread-xxx
	patterns := []string{
		`tid[_-](\d+)`,
		`thread[_-](\d+)`,
		`threads?/(\d+)`,
		`topic[_-](\d+)`,
		`topics?/(\d+)`,
		`post[_-](\d+)`,
		`posts?/(\d+)`,
		`/(\d+)/?$`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(link)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// ID bulunamadıysa link'in son kısmını kullan
	parts := strings.Split(strings.TrimRight(link, "/"), "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		// Query string'i temizle
		if idx := strings.Index(last, "?"); idx > 0 {
			last = last[:idx]
		}
		if last != "" && len(last) < 100 {
			return last
		}
	}

	return ""
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

// scrapeWithFlareSolverr FlareSolverr ile scrape yapar
func (s *Scraper) scrapeWithFlareSolverr(ctx context.Context, entry models.ForumEntry, cwd string) (ScrapedData, error) {
	if !s.flareAvailable {
		return ScrapedData{}, fmt.Errorf("FlareSolverr kullanılamıyor, Cloudflare korumalı site atlanıyor")
	}

	resp, err := s.flareClient.GetPage(ctx, entry.URL)
	if err != nil {
		return ScrapedData{}, fmt.Errorf("FlareSolverr hatası: %w", err)
	}

	html := resp.Solution.Response
	if html == "" {
		return ScrapedData{}, fmt.Errorf("FlareSolverr boş HTML döndü")
	}

	data := s.parseHTMLContent(html, entry)

	if data.Link == "" {
		s.saveHTMLForDebug(html, entry.Name, cwd)
		return ScrapedData{}, fmt.Errorf("FlareSolverr HTML'inden link çıkarılamadı")
	}

	// Absolute URL'e çevir
	data.Link = buildAbsoluteURL(entry.URL, data.Link)

	zlog.Info().
		Str("forum", entry.Name).
		Str("title", truncateString(data.Title, 50)).
		Msg("✅ FlareSolverr ile veri çekildi")

	return data, nil
}

// parseHTMLContent HTML string'inden veri çıkarır (goquery ile)
func (s *Scraper) parseHTMLContent(html string, entry models.ForumEntry) ScrapedData {
	data := ScrapedData{}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		zlog.Warn().Err(err).Msg("HTML parse hatası")
		return data
	}

	selector := entry.CSSSelector

	// Basitleştirilmiş selector dene
	simpleSelector := simplifySelector(selector)
	selection := doc.Find(simpleSelector).First()

	// Alternatif selector'lar
	if selection.Length() == 0 {
		altSelectors := []string{
			"div.structItem--thread",
			"tr.inline_row",
			"li.discussionListItem",
			".thread_list_item",
			"div.threadbit",
			"li.threadbit",
		}

		for _, altSel := range altSelectors {
			selection = doc.Find(altSel).First()
			if selection.Length() > 0 {
				break
			}
		}
	}

	if selection.Length() == 0 {
		return data
	}

	// Link çek
	linkSelectors := []string{
		"a[href*='thread']",
		"a[href*='Thread']",
		".structItem-title a",
		".subject_new a",
		".threadtitle a",
		"a",
	}

	for _, linkSel := range linkSelectors {
		linkEl := selection.Find(linkSel).First()
		if linkEl.Length() > 0 {
			link, exists := linkEl.Attr("href")
			if exists && link != "" && !strings.HasPrefix(link, "#") {
				data.Link = link
				data.Title = cleanContent(linkEl.Text())
				break
			}
		}
	}

	// Author çek
	authorSelectors := []string{
		".username",
		".author",
		".posterdate a",
		"a[href*='member']",
		"a[href*='user']",
	}

	for _, authorSel := range authorSelectors {
		authorEl := selection.Find(authorSel).First()
		if authorEl.Length() > 0 {
			data.Author = cleanContent(authorEl.Text())
			if data.Author != "" && len(data.Author) > 1 {
				break
			}
		}
	}

	// ThreadID
	data.ThreadID = extractThreadIDFromLink(data.Link)

	return data
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

// loadPageAndWaitElement sayfa yüklerken aynı anda element arar
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

// incrementScrapeCount scrape sayısını artırır ve restart gerekip gerekmediğini döner
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

// restartBrowsers browser'ları kapat-aç (memory temizliği)
func (s *Scraper) restartBrowsers() error {
	zlog.Info().
		Int("limit", s.restartLimit).
		Msg("🔄 Browser restart başlatılıyor (memory cleanup)")

	// Önce tab context'leri kapat
	if s.normalCancel != nil {
		s.normalCancel()
	}
	if s.onionCancel != nil {
		s.onionCancel()
	}

	// Sonra allocator'ları kapat
	if s.normalAllocCancel != nil {
		s.normalAllocCancel()
	}
	if s.onionAllocCancel != nil {
		s.onionAllocCancel()
	}

	// Chrome process'lerin tamamen kapanması için bekle
	time.Sleep(2 * time.Second)

	// Yeni browser'ları başlat
	normalAllocOpts := buildChromeOptions()
	normalAllocCtx, normalAllocCancel := chromedp.NewExecAllocator(context.Background(), normalAllocOpts...)
	s.normalBrowser, s.normalCancel = chromedp.NewContext(normalAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	s.normalAllocCancel = normalAllocCancel

	onionAllocOpts := append(buildChromeOptions(), chromedp.ProxyServer("socks5://127.0.0.1:9150"))
	onionAllocCtx, onionAllocCancel := chromedp.NewExecAllocator(context.Background(), onionAllocOpts...)
	s.onionBrowser, s.onionCancel = chromedp.NewContext(onionAllocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	s.onionAllocCancel = onionAllocCancel

	zlog.Info().Msg("✅ Browser restart tamamlandı")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	zlog.Info().
		Uint64("alloc_mb", m.Alloc/1024/1024).
		Uint64("sys_mb", m.Sys/1024/1024).
		Msg("📊 Restart sonrası memory")

	return nil
}

// cleanAuthor "Started by XXX" veya "by XXX," → "XXX"
func cleanAuthor(author string) string {
	author = strings.TrimPrefix(author, "Started by ")
	author = strings.TrimPrefix(author, "by ")
	author = strings.TrimSuffix(author, ",")
	return strings.TrimSpace(author)
}

// cleanPostedAt kullanıcı adını temizler "Username2 minutes ago" → "2 minutes ago"
func cleanPostedAt(posted string) string {
	if idx := strings.Index(posted, "Last Post:"); idx > 0 {
		posted = strings.TrimSpace(posted[:idx])
	}

	timePatterns := []string{
		"seconds ago", "second ago",
		"minutes ago", "minute ago",
		"hours ago", "hour ago",
		"days ago", "day ago",
		"weeks ago", "week ago",
		"Today at", "Yesterday at",
	}

	for _, pattern := range timePatterns {
		if idx := strings.Index(posted, pattern); idx > 0 {
			start := idx - 1
			for start > 0 && (posted[start-1] >= '0' && posted[start-1] <= '9' || posted[start-1] == ' ') {
				start--
			}
			return strings.TrimSpace(posted[start:])
		}
	}

	return posted
}