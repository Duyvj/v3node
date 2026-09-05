package format

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func UserTag(tag string, uuid string) string {
	digest := sha256.Sum256([]byte(uuid))
	// Xray includes MemoryUser.Email in access logs and some validation errors.
	// Store only a one-way identity there; the actual UUID/password remains in
	// the protocol account where it is required for authentication.
	return fmt.Sprintf("%s|h:%s", tag, hex.EncodeToString(digest[:]))
}

// UserCredentialDigest returns the same credential digest for both legacy
// raw user tags and the hashed runtime tags above. Redis device-limit keys can
// therefore remain compatible during a rolling Agent upgrade.
func UserCredentialDigest(value string) [sha256.Size]byte {
	identity := value
	if separator := strings.LastIndexByte(value, '|'); separator >= 0 && separator+1 < len(value) {
		identity = value[separator+1:]
	}
	if strings.HasPrefix(identity, "h:") {
		decoded, err := hex.DecodeString(strings.TrimPrefix(identity, "h:"))
		if err == nil && len(decoded) == sha256.Size {
			var digest [sha256.Size]byte
			copy(digest[:], decoded)
			return digest
		}
	}
	return sha256.Sum256([]byte(identity))
}

// RedactUserTag returns a stable diagnostic label without exposing the UUID,
// which is a bearer credential in several subscription protocols. The stable
// digest still lets operators correlate repeated errors in a log.
func RedactUserTag(value string) string {
	value = strings.TrimSpace(value)
	separator := strings.LastIndexByte(value, '|')
	tag := "user"
	credential := value
	if separator > 0 {
		tag = value[:separator]
		credential = value[separator+1:]
	}
	digest := UserCredentialDigest(credential)
	return fmt.Sprintf("%s|user-%s", tag, hex.EncodeToString(digest[:])[:12])
}
