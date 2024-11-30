package hmac

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"time"
	"unsafe"
)

const (
	HMACSignaturePrefix = "dumbproxy grant token v1"
)

var hmacSignaturePrefix = []byte(HMACSignaturePrefix)

func VerifyHMACLoginAndPassword(mac hash.Hash, login, password []byte) bool {
	n, err := base64.RawURLEncoding.Decode(password, password)
	if err != nil {
		return false
	}
	password = password[:n]

	var expire int64
	if len(password) < int(unsafe.Sizeof(expire)) {
		return false
	}
	expire = int64(binary.BigEndian.Uint64(password[:unsafe.Sizeof(expire)]))
	password = password[unsafe.Sizeof(expire):]

	if time.Unix(expire, 0).Before(time.Now()) {
		return false
	}

	expectedMAC := CalculateHMACSignature(mac, login, expire)
	return hmac.Equal(password, expectedMAC)
}

func CalculateHMACSignature(mac hash.Hash, username []byte, expire int64) []byte {
	mac.Reset()
	mac.Write(hmacSignaturePrefix)
	mac.Write(username)
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
