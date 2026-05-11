package botlog

import "strings"

// Bot is a known bot family with ordered UA fingerprints. More specific patterns
// come first; the family-wide fallback (if any) is last.
type Bot struct {
	Family    string
	NamesByUA []UAName
}

// UAName maps a UA substring to a botName subtype. Subtypes drive SEO drill-down
// in the bot-logs UI — googlebot-smartphone vs googlebot-desktop is a
// load-bearing distinction for mobile-first indexing analysis.
type UAName struct {
	Pat  string // substring match, case-sensitive (UA values from logs are unchanged)
	Name string
}

// knownBots is a snapshot of UA patterns kept in sync with the topsrv.io
// bot-verifier. Update this list whenever a new family is added upstream.
//
// Generic "Googlebot" catches everything Google ships with "Googlebot/2.1" and
// gets refined to googlebot-smartphone vs googlebot-desktop in refineSubtype —
// Google distinguishes those two by the surrounding Mobile/Android markers,
// not by a separate UA token.
var knownBots = []Bot{
	// ── Search engines: global ─────────────────────────────────────────
	{Family: "google", NamesByUA: []UAName{
		{"Googlebot-Image", "googlebot-image"},
		{"Googlebot-News", "googlebot-news"},
		{"Googlebot-Video", "googlebot-video"},
		{"AdsBot-Google-Mobile", "adsbot-google-mobile"},
		{"AdsBot-Google", "adsbot-google"},
		{"Mediapartners-Google", "mediapartners-google"},
		{"FeedFetcher-Google", "feedfetcher-google"},
		{"Googlebot", "googlebot"}, // refined to smartphone/desktop in refineSubtype
	}},
	{Family: "bing", NamesByUA: []UAName{
		{"BingPreview", "bingpreview"},
		{"adidxbot", "adidxbot"},
		{"bingbot", "bingbot"},
		{"msnbot", "msnbot"},
	}},
	{Family: "duckduckgo", NamesByUA: []UAName{
		{"DuckDuckBot", "duckduckbot"},
	}},
	{Family: "apple", NamesByUA: []UAName{
		{"Applebot", "applebot"},
	}},

	// ── Search engines: RU / CIS ───────────────────────────────────────
	{Family: "yandex", NamesByUA: []UAName{
		{"YandexAccessibilityBot", "yandex-accessibility"},
		{"YandexRenderResourcesBot", "yandex-render"},
		{"YandexMetrika", "yandex-metrika"},
		{"YandexImages", "yandeximages"},
		{"YandexMobileBot", "yandexmobile"},
		{"YandexVideo", "yandexvideo"},
		{"YandexMedia", "yandexmedia"},
		{"YandexTurbo", "yandex-turbo"},
		{"YandexNews", "yandex-news"},
		{"YandexMarket", "yandex-market"},
		{"YandexCalendar", "yandex-calendar"},
		{"YandexDirect", "yandex-direct"},
		{"YandexFavicons", "yandex-favicons"},
		{"YandexBot", "yandexbot"},
	}},
	{Family: "mailru", NamesByUA: []UAName{
		{"Mail.RU_Bot/Img", "mailru-images"},
		{"Mail.RU_Bot/Fast", "mailru-fast"},
		{"Mail.RU_Bot", "mailru"},
	}},
	{Family: "rambler", NamesByUA: []UAName{
		{"StackRambler", "stackrambler"},
	}},
	{Family: "sputnik", NamesByUA: []UAName{
		{"SputnikImageBot", "sputnik-images"},
		{"SputnikBot", "sputnik"},
	}},

	// ── Search engines: Asian ──────────────────────────────────────────
	{Family: "baidu", NamesByUA: []UAName{
		{"Baiduspider-image", "baidu-images"},
		{"Baiduspider-mobile", "baidu-mobile"},
		{"Baiduspider-news", "baidu-news"},
		{"Baiduspider-video", "baidu-video"},
		{"Baiduspider", "baiduspider"},
	}},
	{Family: "sogou", NamesByUA: []UAName{
		{"Sogou web spider", "sogou-web"},
		{"Sogou news spider", "sogou-news"},
		{"Sogou inst spider", "sogou-inst"},
	}},
	{Family: "qihoo", NamesByUA: []UAName{
		{"360Spider", "360spider"},
		{"HaosouSpider", "haosou"},
	}},
	{Family: "petal", NamesByUA: []UAName{
		{"PetalBot", "petalbot"},
		{"AspiegelBot", "aspiegel"},
	}},
	{Family: "naver", NamesByUA: []UAName{
		{"Yeti", "yeti"},
	}},
	{Family: "daum", NamesByUA: []UAName{
		{"Daum", "daum"},
	}},

	// ── AI / LLM crawlers (2024-2026) ──────────────────────────────────
	{Family: "openai", NamesByUA: []UAName{
		{"GPTBot", "gptbot"},
		{"OAI-SearchBot", "oai-searchbot"},
		{"ChatGPT-User", "chatgpt-user"},
	}},
	{Family: "anthropic", NamesByUA: []UAName{
		{"Claude-SearchBot", "claude-searchbot"},
		{"Claude-User", "claude-user"},
		{"ClaudeBot", "claudebot"},
		{"Claude-Web", "claude-web"},
		{"anthropic-ai", "anthropic-ai"},
	}},
	{Family: "perplexity", NamesByUA: []UAName{
		{"PerplexityBot", "perplexitybot"},
		{"Perplexity-User", "perplexity-user"},
	}},
	{Family: "mistral", NamesByUA: []UAName{
		{"MistralAI-User", "mistral-user"},
	}},
	{Family: "cohere", NamesByUA: []UAName{
		{"cohere-training-data-crawler", "cohere-training"},
		{"cohere-ai", "cohere"},
	}},
	{Family: "amazon", NamesByUA: []UAName{
		{"Amazonbot", "amazonbot"},
	}},
	{Family: "diffbot", NamesByUA: []UAName{
		{"Diffbot", "diffbot"},
	}},
	{Family: "ai2", NamesByUA: []UAName{
		{"AI2Bot", "ai2bot"},
	}},
	{Family: "you", NamesByUA: []UAName{
		{"YouBot", "youbot"},
	}},
	{Family: "timpi", NamesByUA: []UAName{
		{"Timpibot", "timpibot"},
	}},
	{Family: "meta", NamesByUA: []UAName{
		{"meta-externalagent", "meta-externalagent"},
		{"meta-externalfetcher", "meta-externalfetcher"},
		{"facebookexternalhit", "facebookexternalhit"},
		{"FacebookBot", "facebookbot"},
	}},
	{Family: "bytespider", NamesByUA: []UAName{
		{"Bytespider", "bytespider"},
	}},
	{Family: "tiktok", NamesByUA: []UAName{
		{"TikTokSpider", "tiktokspider"},
	}},
	{Family: "common-crawl", NamesByUA: []UAName{
		{"CCBot", "ccbot"},
	}},

	// ── SEO crawlers ──────────────────────────────────────────────────
	{Family: "ahrefs", NamesByUA: []UAName{
		{"AhrefsSiteAudit", "ahrefs-siteaudit"},
		{"AhrefsBot", "ahrefsbot"},
	}},
	{Family: "semrush", NamesByUA: []UAName{
		{"SemrushBot-OCOB", "semrush-ocob"},
		{"SemrushBot-SI", "semrush-si"},
		{"SemrushBot-SWA", "semrush-swa"},
		{"SemrushBot-BA", "semrush-ba"},
		{"SemrushBot", "semrushbot"},
	}},
	{Family: "majestic", NamesByUA: []UAName{
		{"MJ12bot", "mj12bot"},
	}},
	{Family: "moz", NamesByUA: []UAName{
		{"rogerbot", "rogerbot"},
		{"DotBot", "dotbot"},
	}},
	{Family: "webmeup", NamesByUA: []UAName{
		{"BLEXBot", "blexbot"},
	}},
	{Family: "dataforseo", NamesByUA: []UAName{
		{"DataForSeoBot", "dataforseobot"},
	}},

	// ── Social / messenger link-preview fetchers ──────────────────────
	{Family: "twitter", NamesByUA: []UAName{
		{"Twitterbot", "twitterbot"},
	}},
	{Family: "linkedin", NamesByUA: []UAName{
		{"LinkedInBot", "linkedinbot"},
	}},
	{Family: "pinterest", NamesByUA: []UAName{
		{"Pinterestbot", "pinterestbot"},
		{"Pinterest", "pinterest"},
	}},
	{Family: "slack", NamesByUA: []UAName{
		{"Slackbot-LinkExpanding", "slack-linkexpanding"},
		{"Slackbot", "slackbot"},
	}},
	{Family: "discord", NamesByUA: []UAName{
		{"Discordbot", "discordbot"},
	}},
	{Family: "telegram", NamesByUA: []UAName{
		{"TelegramBot", "telegrambot"},
	}},
	{Family: "whatsapp", NamesByUA: []UAName{
		{"WhatsApp", "whatsapp"},
	}},
	{Family: "vk", NamesByUA: []UAName{
		{"vkShare", "vkshare"},
	}},
	{Family: "skype", NamesByUA: []UAName{
		{"SkypeUriPreview", "skype-preview"},
	}},

	// ── Web archive ───────────────────────────────────────────────────
	{Family: "archive", NamesByUA: []UAName{
		{"archive.org_bot", "archive-org"},
		{"ia_archiver", "ia-archiver"},
	}},
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
		for _, p := range b.NamesByUA {
			if strings.Contains(ua, p.Pat) {
				return b.Family, refineSubtype(b.Family, p.Name, ua)
			}
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
