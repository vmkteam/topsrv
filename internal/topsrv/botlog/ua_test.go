package botlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchUA(t *testing.T) {
	cases := []struct {
		ua     string
		family string
		name   string
	}{
		// Real Googlebot UAs from production logs.
		{
			ua:     "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			family: "google",
			name:   "googlebot-smartphone",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			family: "google",
			name:   "googlebot-desktop",
		},
		{
			ua:     "Googlebot-Image/1.0",
			family: "google",
			name:   "googlebot-image",
		},
		{
			ua:     "AdsBot-Google (+http://www.google.com/adsbot.html)",
			family: "google",
			name:   "adsbot-google",
		},
		{
			ua:     "AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html)",
			family: "google",
			name:   "adsbot-google-mobile",
		},
		{
			ua:     "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			family: "yandex",
			name:   "yandexbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)",
			family: "yandex",
			name:   "yandeximages",
		},
		{
			ua:     "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			family: "bing",
			name:   "bingbot",
		},
		{
			ua:     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
			family: "openai",
			name:   "gptbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
			family: "openai",
			name:   "oai-searchbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
			family: "anthropic",
			name:   "claudebot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
			family: "perplexity",
			name:   "perplexitybot",
		},
		{
			ua:     "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
			family: "meta",
			name:   "meta-externalagent",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
			family: "bytespider",
			name:   "bytespider",
		},
		{
			ua:     "CCBot/2.0 (https://commoncrawl.org/faq/)",
			family: "common-crawl",
			name:   "ccbot",
		},
		// RU / CIS.
		{
			ua:     "Mozilla/5.0 (compatible; Mail.RU_Bot/2.0; +http://go.mail.ru/help/robots)",
			family: "mailru",
			name:   "mailru",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Mail.RU_Bot/Img/2.0; +http://go.mail.ru/help/robots)",
			family: "mailru",
			name:   "mailru-images",
		},
		{
			ua:     "StackRambler/2.0 (MSIE incompatible)",
			family: "rambler",
			name:   "stackrambler",
		},
		{
			ua:     "Mozilla/5.0 (compatible; SputnikBot/2.3; +http://corp.sputnik.ru/webmaster)",
			family: "sputnik",
			name:   "sputnik",
		},
		{
			ua:     "Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; http://yandex.com/bots)",
			family: "yandex",
			name:   "yandex-accessibility",
		},
		{
			ua:     "Mozilla/5.0 (compatible; YandexMetrika/2.0; +http://yandex.com/bots)",
			family: "yandex",
			name:   "yandex-metrika",
		},
		// AI 2026.
		{
			ua:     "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
			family: "amazon",
			name:   "amazonbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; cohere-training-data-crawler; +https://cohere.com)",
			family: "cohere",
			name:   "cohere-training",
		},
		{
			ua:     "Mozilla/5.0 (compatible; MistralAI-User/1.0; +https://mistral.ai)",
			family: "mistral",
			name:   "mistral-user",
		},
		{
			ua:     "Diffbot/1.0 (+http://diffbot.com)",
			family: "diffbot",
			name:   "diffbot",
		},
		{
			ua:     "AI2Bot (+https://allenai.org/crawler)",
			family: "ai2",
			name:   "ai2bot",
		},
		{
			ua:     "Mozilla/5.0 TikTokSpider (+https://www.tiktok.com/robots)",
			family: "bytespider",
			name:   "tiktokspider",
		},
		// Asian.
		{
			ua:     "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
			family: "baidu",
			name:   "baiduspider",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Baiduspider-image/2.0)",
			family: "baidu",
			name:   "baidu-images",
		},
		{
			ua:     "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
			family: "sogou",
			name:   "sogou-web",
		},
		{
			ua:     "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
			family: "petal",
			name:   "petalbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Yeti/1.1; +http://naver.me/spd)",
			family: "naver",
			name:   "yeti",
		},
		// SEO crawlers.
		{
			ua:     "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			family: "ahrefs",
			name:   "ahrefsbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
			family: "semrush",
			name:   "semrushbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; SemrushBot-SI/0.97; +http://www.semrush.com/bot.html)",
			family: "semrush",
			name:   "semrush-si",
		},
		{
			ua:     "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
			family: "majestic",
			name:   "mj12bot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
			family: "moz",
			name:   "dotbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; BLEXBot/1.0; +http://webmeup-crawler.com/)",
			family: "webmeup",
			name:   "blexbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)",
			family: "dataforseo",
			name:   "dataforseobot",
		},
		// Social / link-preview fetchers.
		{
			ua:     "Twitterbot/1.0",
			family: "twitter",
			name:   "twitterbot",
		},
		{
			ua:     "LinkedInBot/1.0 (compatible; Mozilla/5.0; +http://www.linkedin.com)",
			family: "linkedin",
			name:   "linkedinbot",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)",
			family: "pinterest",
			name:   "pinterestbot",
		},
		{
			ua:     "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
			family: "slack",
			name:   "slack-linkexpanding",
		},
		{
			ua:     "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
			family: "discord",
			name:   "discordbot",
		},
		{
			ua:     "TelegramBot (like TwitterBot)",
			family: "telegram",
			name:   "telegrambot",
		},
		{
			ua:     "WhatsApp/2.21.4.18 A",
			family: "whatsapp",
			name:   "whatsapp",
		},
		{
			ua:     "Mozilla/5.0 (compatible; vkShare; +http://vk.com/dev/Share)",
			family: "vk",
			name:   "vkshare",
		},
		// Archive.
		{
			ua:     "Mozilla/5.0 (compatible; archive.org_bot +http://www.archive.org/details/archive.org_bot)",
			family: "archive",
			name:   "archive-org",
		},
		{
			ua:     "ia_archiver-web.archive.org",
			family: "archive",
			name:   "ia-archiver",
		},
		// Non-bots.
		{ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"},
		{ua: "curl/8.4.0"},
		{ua: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_"+tc.family, func(t *testing.T) {
			gotFamily, gotName := MatchUA(tc.ua, nil)
			assert.Equal(t, tc.family, gotFamily, "ua=%q", tc.ua)
			assert.Equal(t, tc.name, gotName, "ua=%q", tc.ua)
		})
	}
}

func TestMatchUA_ExtraPatternsWinOverKnownBots(t *testing.T) {
	ua := "Mozilla/5.0 MyCustomCrawler/1.0 (compatible; Googlebot/2.1)"
	family, name := MatchUA(ua, []string{"MyCustomCrawler/"})
	assert.Equal(t, "custom", family)
	assert.Equal(t, "MyCustomCrawler/", name)
}

func TestMatchUA_ExtraPatternsEmptyEntriesIgnored(t *testing.T) {
	ua := "GPTBot/1.0"
	family, name := MatchUA(ua, []string{"", "Nope/"})
	assert.Equal(t, "openai", family)
	assert.Equal(t, "gptbot", name)
}

// Non-bot is the worst case: every pattern scanned. ~90% of real traffic.
const (
	benchUANonBot    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	benchUAGooglebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func BenchmarkMatchUA_NonBot(b *testing.B) {
	for range b.N {
		MatchUA(benchUANonBot, nil)
	}
}

func BenchmarkMatchUA_Googlebot(b *testing.B) {
	for range b.N {
		MatchUA(benchUAGooglebot, nil)
	}
}
