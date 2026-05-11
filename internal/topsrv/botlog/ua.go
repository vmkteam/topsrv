package botlog

import "strings"

// botPattern is a single UA-substring → (family, subtype) rule. Each entry is
// matched in declaration order; the first hit wins. More specific patterns
// must precede the family-wide fallback (e.g. Googlebot-Image before Googlebot).
//
// Subtypes drive SEO drill-down in the bot-logs UI — googlebot-smartphone vs
// googlebot-desktop is a load-bearing distinction for mobile-first indexing
// analysis. Generic "Googlebot" catches everything Google ships with
// "Googlebot/2.1" and is refined to smartphone/desktop in refineSubtype using
// the surrounding Mobile/Android markers (Google does not use a distinct UA
// token for those).
type botPattern struct {
	Family string
	Pat    string // substring match, case-sensitive (UA values from logs are unchanged)
	Name   string
}

// knownBots is a snapshot of UA patterns kept in sync with the topsrv.io
// bot-verifier. Update this list whenever a new family is added upstream.
// Order is contract — declare specific patterns before family-wide fallbacks.
var knownBots = []botPattern{
	// ── Search engines: global ─────────────────────────────────────────
	{"google", "Googlebot-Image", "googlebot-image"},
	{"google", "Googlebot-News", "googlebot-news"},
	{"google", "Googlebot-Video", "googlebot-video"},
	{"google", "AdsBot-Google-Mobile", "adsbot-google-mobile"},
	{"google", "AdsBot-Google", "adsbot-google"},
	{"google", "Mediapartners-Google", "mediapartners-google"},
	{"google", "FeedFetcher-Google", "feedfetcher-google"},
	{"google", "Googlebot", "googlebot"}, // refined to smartphone/desktop in refineSubtype

	{"bing", "BingPreview", "bingpreview"},
	{"bing", "adidxbot", "adidxbot"},
	{"bing", "bingbot", "bingbot"},
	{"bing", "msnbot", "msnbot"},

	{"duckduckgo", "DuckDuckBot", "duckduckbot"},

	{"apple", "Applebot", "applebot"},

	// ── Search engines: RU / CIS ───────────────────────────────────────
	{"yandex", "YandexAccessibilityBot", "yandex-accessibility"},
	{"yandex", "YandexRenderResourcesBot", "yandex-render"},
	{"yandex", "YandexMetrika", "yandex-metrika"},
	{"yandex", "YandexImages", "yandeximages"},
	{"yandex", "YandexMobileBot", "yandexmobile"},
	{"yandex", "YandexVideo", "yandexvideo"},
	{"yandex", "YandexMedia", "yandexmedia"},
	{"yandex", "YandexTurbo", "yandex-turbo"},
	{"yandex", "YandexNews", "yandex-news"},
	{"yandex", "YandexMarket", "yandex-market"},
	{"yandex", "YandexCalendar", "yandex-calendar"},
	{"yandex", "YandexDirect", "yandex-direct"},
	{"yandex", "YandexFavicons", "yandex-favicons"},
	{"yandex", "YandexBot", "yandexbot"},

	{"mailru", "Mail.RU_Bot/Img", "mailru-images"},
	{"mailru", "Mail.RU_Bot/Fast", "mailru-fast"},
	{"mailru", "Mail.RU_Bot", "mailru"},

	{"rambler", "StackRambler", "stackrambler"},

	{"sputnik", "SputnikImageBot", "sputnik-images"},
	{"sputnik", "SputnikBot", "sputnik"},

	// ── Search engines: Asian ──────────────────────────────────────────
	{"baidu", "Baiduspider-image", "baidu-images"},
	{"baidu", "Baiduspider-mobile", "baidu-mobile"},
	{"baidu", "Baiduspider-news", "baidu-news"},
	{"baidu", "Baiduspider-video", "baidu-video"},
	{"baidu", "Baiduspider", "baiduspider"},

	{"sogou", "Sogou web spider", "sogou-web"},
	{"sogou", "Sogou news spider", "sogou-news"},
	{"sogou", "Sogou inst spider", "sogou-inst"},

	{"qihoo", "360Spider", "360spider"},
	{"qihoo", "HaosouSpider", "haosou"},

	{"petal", "PetalBot", "petalbot"},
	{"petal", "AspiegelBot", "aspiegel"},

	{"naver", "Yeti", "yeti"},

	{"daum", "Daum", "daum"},

	// ── AI / LLM crawlers (2024-2026) ──────────────────────────────────
	{"openai", "GPTBot", "gptbot"},
	{"openai", "OAI-SearchBot", "oai-searchbot"},
	{"openai", "ChatGPT-User", "chatgpt-user"},

	{"anthropic", "Claude-SearchBot", "claude-searchbot"},
	{"anthropic", "Claude-User", "claude-user"},
	{"anthropic", "ClaudeBot", "claudebot"},
	{"anthropic", "Claude-Web", "claude-web"},
	{"anthropic", "anthropic-ai", "anthropic-ai"},

	{"perplexity", "PerplexityBot", "perplexitybot"},
	{"perplexity", "Perplexity-User", "perplexity-user"},

	{"mistral", "MistralAI-User", "mistral-user"},

	{"cohere", "cohere-training-data-crawler", "cohere-training"},
	{"cohere", "cohere-ai", "cohere"},

	{"amazon", "Amazonbot", "amazonbot"},

	{"diffbot", "Diffbot", "diffbot"},

	{"ai2", "AI2Bot", "ai2bot"},

	{"you", "YouBot", "youbot"},

	{"timpi", "Timpibot", "timpibot"},

	{"meta", "meta-externalagent", "meta-externalagent"},
	{"meta", "meta-externalfetcher", "meta-externalfetcher"},
	{"meta", "facebookexternalhit", "facebookexternalhit"},
	{"meta", "FacebookBot", "facebookbot"},

	// TikTokSpider shares *.bytedance.com PTR with Bytespider — keep them
	// under one family so FCrDNS verification on the receiver side stays
	// consistent and legit TikTok crawls aren't mis-flagged as spoofed.
	{"bytespider", "TikTokSpider", "tiktokspider"},
	{"bytespider", "Bytespider", "bytespider"},

	{"common-crawl", "CCBot", "ccbot"},

	// ── SEO crawlers ──────────────────────────────────────────────────
	{"ahrefs", "AhrefsSiteAudit", "ahrefs-siteaudit"},
	{"ahrefs", "AhrefsBot", "ahrefsbot"},

	{"semrush", "SemrushBot-OCOB", "semrush-ocob"},
	{"semrush", "SemrushBot-SI", "semrush-si"},
	{"semrush", "SemrushBot-SWA", "semrush-swa"},
	{"semrush", "SemrushBot-BA", "semrush-ba"},
	{"semrush", "SemrushBot", "semrushbot"},

	{"majestic", "MJ12bot", "mj12bot"},

	{"moz", "rogerbot", "rogerbot"},
	{"moz", "DotBot", "dotbot"},

	{"webmeup", "BLEXBot", "blexbot"},

	{"dataforseo", "DataForSeoBot", "dataforseobot"},

	// ── Social / messenger link-preview fetchers ──────────────────────
	{"twitter", "Twitterbot", "twitterbot"},

	{"linkedin", "LinkedInBot", "linkedinbot"},

	{"pinterest", "Pinterestbot", "pinterestbot"},
	{"pinterest", "Pinterest", "pinterest"},

	{"slack", "Slackbot-LinkExpanding", "slack-linkexpanding"},
	{"slack", "Slackbot", "slackbot"},

	{"discord", "Discordbot", "discordbot"},

	{"telegram", "TelegramBot", "telegrambot"},

	{"whatsapp", "WhatsApp", "whatsapp"},

	{"vk", "vkShare", "vkshare"},

	{"skype", "SkypeUriPreview", "skype-preview"},

	// ── Web archive ───────────────────────────────────────────────────
	{"archive", "archive.org_bot", "archive-org"},
	{"archive", "ia_archiver", "ia-archiver"},
}

// MatchUA returns the bot family and subtype for ua. Returns ("", "") when no
// fingerprint matches. extraPatterns are checked first in declaration order and
// reported with family "custom" — empty entries are skipped.
func MatchUA(ua string, extraPatterns []string) (family, name string) {
	if ua == "" {
		return "", ""
	}
	for _, pat := range extraPatterns {
		if pat == "" {
			continue
		}
		if strings.Contains(ua, pat) {
			return "custom", pat
		}
	}
	for _, b := range knownBots {
		if strings.Contains(ua, b.Pat) {
			return b.Family, refineSubtype(b.Family, b.Name, ua)
		}
	}
	return "", ""
}

// refineSubtype splits generic Googlebot UAs into smartphone/desktop. Google
// uses the same "Googlebot/2.1" token in both — the difference is the OS prefix.
// More specific subtypes (image, news, AdsBot, ...) are caught upstream and
// passed through unchanged.
func refineSubtype(family, name, ua string) string {
	if family == "google" && name == "googlebot" {
		if strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") {
			return "googlebot-smartphone"
		}
		return "googlebot-desktop"
	}
	return name
}
