package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"time"
)

const (
	HMACSignaturePrefix = "dumbproxy grant token v1"
	HMACExpireSize      = 8
)

var hmacSignaturePrefix = []byte(HMACSignaturePrefix)

func NewHasher(secret []byte) hash.Hash {
	return hmac.New(sha256.New, secret)
}

func VerifyHMACLoginAndPassword(mac hash.Hash, login, password []byte) bool {
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(password)))
	n, err := base64.RawURLEncoding.Decode(buf, password)
	if err != nil {
		return false
	}
	buf = buf[:n]

	var expire int64
	if len(buf) < HMACExpireSize {
		return false
	}
	expire = int64(binary.BigEndian.Uint64(buf[:HMACExpireSize]))
	buf = buf[HMACExpireSize:]

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
	var buf [HMACExpireSize]byte
	binary.BigEndian.PutUint64(buf[:], uint64(expire))

	mac.Reset()
	mac.Write(hmacSignaturePrefix)
	mac.Write(username)
	mac.Write(buf[:])

	return mac.Sum(nil)
}
