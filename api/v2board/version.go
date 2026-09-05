package panel

import "strings"

var clientVersion = "unknown"

func SetClientVersion(value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		clientVersion = value
	}
}

func ClientVersion() string {
	return clientVersion
}
