package sshdconf

import "strings"

// class is how sshd stores a keyword's values.
type class int

const (
	scalar     class = iota // the first value wins
	accumulate              // every line adds its values
	firstLine               // the whole first line is the value, later lines are ignored
	ignored                 // deprecated or unsupported: sshd logs and skips it
	include
	match
)

// keyword is one sshd_config keyword of upstream OpenSSH (servconf.c).
type keyword struct {
	name   string // canonical spelling, the key of Config.Global
	class  class
	enum   bool // the value is a case-insensitive enum (yes, no, ...): lowercased
	global bool // not allowed in a Match block
}

// keywords by lower-case name; aliases point to the keyword they set.
var keywords = buildKeywords()

// aliases share the slot of another keyword: since OpenSSH 8.7
// ChallengeResponseAuthentication is KbdInteractiveAuthentication.
var aliases = map[string]string{
	"challengeresponseauthentication": "kbdinteractiveauthentication",
	"skeyauthentication":              "kbdinteractiveauthentication",
	"dsaauthentication":               "pubkeyauthentication",
	"hostdsakey":                      "hostkey",
	"hostbasedacceptedkeytypes":       "hostbasedacceptedalgorithms",
	"pubkeyacceptedkeytypes":          "pubkeyacceptedalgorithms",
	"keepalive":                       "tcpkeepalive",
}

func buildKeywords() map[string]keyword {
	table := map[string]keyword{}
	add := func(c class, enum, global bool, names ...string) {
		for _, n := range names {
			table[strings.ToLower(n)] = keyword{name: n, class: c, enum: enum, global: global}
		}
	}
	const yes, no = true, false
	// enum scalars allowed in Match
	add(scalar, yes, no, "PermitRootLogin", "PasswordAuthentication", "KbdInteractiveAuthentication",
		"PermitEmptyPasswords", "PubkeyAuthentication", "HostbasedAuthentication",
		"HostbasedUsesNameFromPacketOnly", "IgnoreRhosts", "GSSAPIAuthentication", "KerberosAuthentication",
		"X11Forwarding", "X11UseLocalhost", "AllowTcpForwarding", "AllowAgentForwarding",
		"AllowStreamLocalForwarding", "PermitTunnel", "PermitTTY", "PermitUserRC", "GatewayPorts",
		"LogLevel", "DisableForwarding", "ExposeAuthInfo", "StreamLocalBindUnlink", "RefuseConnection")
	// enum scalars, global only
	add(scalar, yes, yes, "UsePAM", "AddressFamily", "StrictModes", "PrintMotd", "PrintLastLog",
		"IgnoreUserKnownHosts", "Compression", "TCPKeepAlive", "UseDNS", "KerberosOrLocalPasswd",
		"KerberosTicketCleanup", "KerberosGetAFSToken", "GSSAPICleanupCredentials",
		"GSSAPIStrictAcceptorCheck", "SyslogFacility", "FingerprintHash")
	// other scalars allowed in Match
	add(scalar, no, no, "MaxAuthTries", "MaxSessions", "Banner", "ClientAliveInterval",
		"ClientAliveCountMax", "AuthorizedKeysCommandUser", "AuthorizedPrincipalsCommandUser",
		"AuthorizedPrincipalsFile", "TrustedUserCAKeys", "RevokedKeys", "ChrootDirectory",
		"X11DisplayOffset", "StreamLocalBindMask", "PubkeyAcceptedAlgorithms",
		"HostbasedAcceptedAlgorithms", "CASignatureAlgorithms", "PubkeyAuthOptions", "RDomain",
		"RequiredRSASize", "UnusedConnectionTimeout")
	// other scalars, global only
	add(scalar, no, yes, "PermitUserEnvironment", "LoginGraceTime", "MaxStartups", "PerSourceMaxStartups",
		"PerSourceNetBlockSize", "PerSourcePenaltyExemptList", "Ciphers", "MACs", "KexAlgorithms",
		"HostKeyAlgorithms", "PidFile", "ModuliFile", "XAuthLocation", "HostKeyAgent",
		"SecurityKeyProvider", "SshdSessionPath", "SshdAuthPath")
	add(accumulate, no, no, "AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups", "AcceptEnv", "Subsystem")
	add(accumulate, no, yes, "Port", "ListenAddress", "HostKey", "HostCertificate")
	add(firstLine, no, no, "AuthorizedKeysFile", "AuthenticationMethods", "PermitOpen", "PermitListen",
		"SetEnv", "ChannelTimeout", "LogVerbose", "AuthorizedKeysCommand", "AuthorizedPrincipalsCommand",
		"ForceCommand", "RekeyLimit", "IPQoS")
	add(firstLine, no, yes, "VersionAddendum", "PerSourcePenalties")
	add(ignored, no, no, "ServerKeyBits", "KeyRegenerationInterval", "RhostsAuthentication",
		"RhostsRSAAuthentication", "RSAAuthentication", "KerberosTgtPassing", "AFSTokenPassing",
		"CheckMail", "UseLogin", "VerifyReverseMapping", "ReverseMappingCheck", "AuthorizedKeysFile2",
		"UsePrivilegeSeparation", "Protocol", "PAMAuthenticationViaKbdInt")
	add(include, no, no, "Include")
	add(match, no, no, "Match")
	for alias, target := range aliases {
		table[alias] = table[target]
	}
	return table
}

// lookup returns the keyword for a name as written, case-insensitively.
func lookup(name string) (keyword, bool) {
	k, ok := keywords[strings.ToLower(name)]
	return k, ok
}
