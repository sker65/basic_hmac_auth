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
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(password)))
	n, err := base64.RawURLEncoding.Decode(buf, password)
	if err != nil {
		return false
	}
	buf = buf[:n]

	var expire int64
	if len(buf) < int(unsafe.Sizeof(expire)) {
		return false
	}
	expire = int64(binary.BigEndian.Uint64(buf[:unsafe.Sizeof(expire)]))
	buf = buf[unsafe.Sizeof(expire):]

	if time.Unix(expire, 0).Before(time.Now()) {
		return false
	}

	if len(buf) < mac.Size() {
		return false
	}

	expectedMAC := CalculateHMACSignature(mac, login, expire)
	return hmac.Equal(buf[:mac.Size()], expectedMAC)
}

func CalculateHMACSignature(mac hash.Hash, username []byte, expire int64) []byte {
	mac.Reset()
	mac.Write(hmacSignaturePrefix)
	mac.Write(username)
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
