package shipper

import "time"

// Event is one bot-log entry shipped to the topsrv.io ingest endpoint. JSON
// tags mirror the documented /v1/bot-logs Input contract — keep them in sync.
// Numeric fields ship 0 when absent (the receiver treats 0 as sentinel
// "not present"); string fields use omitempty so empty values stay off the
// wire and save bytes.
type Event struct {
	TS                     time.Time `json:"ts"`
	Host                   string    `json:"host,omitempty"`
	ServerName             string    `json:"serverName,omitempty"`
	AgentHostname          string    `json:"agentHostname"`
	RemoteAddr             string    `json:"remoteAddr,omitempty"`
	Method                 string    `json:"method,omitempty"`
	URI                    string    `json:"uri"`
	Referer                string    `json:"referer,omitempty"`
	Status                 uint16    `json:"status"`
	BodyBytesSent          uint32    `json:"bodyBytesSent"`
	RequestTimeUs          uint32    `json:"requestTimeUs"`
	UpstreamResponseTimeUs uint32    `json:"upstreamResponseTimeUs"`
	UpstreamCacheStatus    string    `json:"upstreamCacheStatus,omitempty"`
	UserAgent              string    `json:"userAgent,omitempty"`
	BotFamily              string    `json:"botFamily,omitempty"`
	BotName                string    `json:"botName,omitempty"`

	// Web-log stream only; the bot stream leaves these zero.
	//
	// UAMatched with UAListVersion is what keeps stream membership out of the
	// receiver's guesswork: the boundary between the two streams moves with the
	// agent's UA list, so "not a bot" and "the list did not know it yet" must be
	// distinguishable in the row itself.
	UAMatched       bool   `json:"uaMatched,omitempty"`
	UAListVersion   string `json:"uaListVersion,omitempty"`
	ReachedUpstream bool   `json:"reachedUpstream,omitempty"`
	ProxyHost       string `json:"proxyHost,omitempty"`

	// Client fields read off the log line; see nginx.ParsedLine.
	Platform   string `json:"platform,omitempty"`
	AppVersion string `json:"appVersion,omitempty"`
	VisitorID  string `json:"visitorId,omitempty"`
}
